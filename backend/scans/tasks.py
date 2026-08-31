import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile

from contextlib import contextmanager
from pathlib import (
    Path,
    PurePosixPath,
    PureWindowsPath,
)

from celery import shared_task

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from projects.models import SourceVersion

from .constants import (
    ANALYSIS_CHUNK_TASK_NAME,
    CHUNK_HEARTBEAT_INTERVAL_SECONDS,
    IGNORED_LANGUAGE_DIRECTORIES,
    LANGUAGE_ALIASES,
    LANGUAGE_DISPLAY_NAMES,
    LANGUAGE_EXTENSIONS,
    OUTBOX_DISPATCH_BATCH_SIZE,
    SUPPORTED_LANGUAGE_ORDER,
)

from .models import (
    AnalysisChunk,
    AnalysisChunkAttempt,
    AnalysisChunkFile,
    AnalysisRun,
    KisaSecurityWeakness,
    Vulnerability,
)

from .services.chunk_executor import (
    claim_chunk,
    heartbeat_attempt,
)

from .services.chunk_state_manager import (
    complete_chunk_attempt,
    fail_chunk_attempt,
)

from .services.chunk_planner import (
    plan_analysis_chunks,
)

from .services.chunk_recovery import (
    run_recovery_cycle,
)

from .services.outbox_dispatcher import (
    dispatch_pending_outboxes,
)

from .services.source_snapshot import (
    get_analysis_workspace_source_root,
    materialize_analysis_workspace,
)


# ========================================
# 실행 제한
# ========================================

GIT_CLONE_TIMEOUT = 120

SEMGREP_TIMEOUT = 300

MAX_LOG_LENGTH = 20000

MAX_EVIDENCE_LENGTH = 5000

MAX_EVIDENCE_LINES = 20


# ========================================
# ZIP Upload 보안 제한
#
# HTTP Serializer에서도 업로드 크기를
# 1차 검증하지만 Celery Worker에서도
# 동일한 제한을 다시 확인한다.
# ========================================

MAX_UPLOAD_ZIP_SIZE = (
    50
    * 1024
    * 1024
)

MAX_ZIP_TOTAL_UNCOMPRESSED_SIZE = (
    200
    * 1024
    * 1024
)

MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE = (
    10
    * 1024
    * 1024
)

MAX_ZIP_MEMBER_COUNT = 5000

MAX_ZIP_COMPRESSION_RATIO = 100

MAX_ZIP_MEMBER_NAME_LENGTH = 512

ZIP_EXTRACT_CHUNK_SIZE = (
    1024
    * 1024
)

ALLOWED_ZIP_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
}

NESTED_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".jar",
    ".war",
    ".ear",
    ".apk",
}


# ========================================
# Semgrep Rule Root
# ========================================

SEMGREP_RULE_ROOT = (
    Path(settings.BASE_DIR)
    / "semgrep_rules"
    / "kisa"
)


# ========================================
# 로그 길이 제한
# ========================================

def truncate_log(
    value,
    max_length=MAX_LOG_LENGTH
):

    if not value:
        return ""

    if len(value) <= max_length:
        return value

    return (
        value[:max_length]
        + "\n\n[로그가 너무 길어 일부만 저장되었습니다.]"
    )


# ========================================
# Upload ZIP 경로 확인
# ========================================

def get_upload_zip_path(
    source_version
):

    if not source_version.source_file:

        raise RuntimeError(
            "업로드된 분석 ZIP 파일이 없습니다."
        )


    try:

        raw_source_path = Path(
            source_version.source_file.path
        )

    except (
        ValueError,
        NotImplementedError,
    ):

        raise RuntimeError(
            "업로드 ZIP 파일의 로컬 경로를 확인할 수 없습니다."
        )


    # ------------------------------------
    # Storage 파일 자체가 Symbolic Link면
    # 분석하지 않는다.
    # ------------------------------------

    if raw_source_path.is_symlink():

        raise RuntimeError(
            "Symbolic Link 형태의 업로드 파일은 허용되지 않습니다."
        )


    try:

        source_path = (
            raw_source_path.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ):

        raise RuntimeError(
            "업로드된 분석 ZIP 파일이 존재하지 않습니다."
        )


    if not source_path.is_file():

        raise RuntimeError(
            "업로드 분석 대상이 올바른 파일이 아닙니다."
        )


    # ------------------------------------
    # MEDIA_ROOT 바깥의 파일을
    # SourceVersion이 참조하는 상황 차단
    # ------------------------------------

    media_root_value = getattr(
        settings,
        "MEDIA_ROOT",
        "",
    )


    if media_root_value:

        media_root = Path(
            media_root_value
        ).resolve()


        try:

            source_path.relative_to(
                media_root
            )

        except ValueError:

            raise RuntimeError(
                "허용되지 않은 업로드 파일 경로입니다."
            )


    # ------------------------------------
    # 확장자 방어
    #
    # Serializer 검증을 우회한 데이터도
    # Worker에서 다시 차단한다.
    # ------------------------------------

    if (
        source_path.suffix.lower()
        !=
        ".zip"
    ):

        raise RuntimeError(
            "파일 업로드 분석은 ZIP 파일만 지원합니다."
        )


    # ------------------------------------
    # 압축 파일 자체 크기
    # ------------------------------------

    try:

        compressed_size = (
            source_path.stat().st_size
        )

    except OSError as error:

        raise RuntimeError(
            "업로드 ZIP 파일 크기를 확인할 수 없습니다. "
            f"{error}"
        )


    if compressed_size <= 0:

        raise RuntimeError(
            "빈 ZIP 파일은 분석할 수 없습니다."
        )


    if (
        compressed_size
        >
        MAX_UPLOAD_ZIP_SIZE
    ):

        raise RuntimeError(
            "업로드 ZIP 파일 크기가 "
            "허용 한도 50MB를 초과했습니다."
        )


    # ------------------------------------
    # 파일명만 .zip으로 바꾼 경우 차단
    # ------------------------------------

    try:

        is_zip = zipfile.is_zipfile(
            source_path
        )

    except OSError as error:

        raise RuntimeError(
            "업로드 ZIP 파일을 확인할 수 없습니다. "
            f"{error}"
        )


    if not is_zip:

        raise RuntimeError(
            "실제 ZIP 형식이 아닌 파일은 분석할 수 없습니다."
        )


    return source_path


# ========================================
# ZIP Member 경로 정규화
#
# 차단 대상:
# - 절대 경로
# - ../
# - Windows Drive 경로
# - Backslash 기반 우회
# - 제어 문자
# - ADS 형태의 :
# ========================================

def normalize_zip_member_path(
    member_name
):

    if not isinstance(
        member_name,
        str,
    ):

        raise RuntimeError(
            "ZIP 내부 파일명이 올바르지 않습니다."
        )


    if not member_name:

        raise RuntimeError(
            "ZIP 내부에 빈 파일명이 존재합니다."
        )


    if (
        len(
            member_name
        )
        >
        MAX_ZIP_MEMBER_NAME_LENGTH
    ):

        raise RuntimeError(
            "ZIP 내부 파일 경로가 너무 깁니다."
        )


    if any(
        ord(character) < 32
        for character
        in member_name
    ):

        raise RuntimeError(
            "ZIP 내부 파일명에 허용되지 않는 "
            "제어 문자가 포함되어 있습니다."
        )


    # ZIP 표준은 /를 사용하지만
    # 악성 ZIP의 Windows Backslash 우회도
    # 같은 경로로 취급한다.

    normalized_name = (
        member_name.replace(
            "\\",
            "/",
        )
    )


    windows_path = PureWindowsPath(
        member_name
    )


    if (
        windows_path.drive
        or
        windows_path.root
    ):

        raise RuntimeError(
            "ZIP 내부에 절대 경로 또는 "
            "Windows Drive 경로가 포함되어 있습니다."
        )


    posix_path = PurePosixPath(
        normalized_name
    )


    if posix_path.is_absolute():

        raise RuntimeError(
            "ZIP 내부에 절대 경로가 포함되어 있습니다."
        )


    path_parts = []


    for part in posix_path.parts:

        if part in (
            "",
            ".",
        ):

            continue


        if part == "..":

            raise RuntimeError(
                "ZIP 내부에 상위 경로 이동(..)이 "
                "포함되어 있습니다."
            )


        # Windows Alternate Data Stream 및
        # Drive 표현 우회 차단

        if ":" in part:

            raise RuntimeError(
                "ZIP 내부 파일명에 ':' 문자는 "
                "허용되지 않습니다."
            )


        path_parts.append(
            part
        )


    if not path_parts:

        return None


    return PurePosixPath(
        *path_parts
    )


# ========================================
# ZIP Member 유형 검사
#
# Symbolic Link / Device / FIFO / Socket 등
# 일반 파일과 디렉터리가 아닌 항목은 거부한다.
# ========================================

def validate_zip_member_type(
    zip_info
):

    unix_mode = (
        zip_info.external_attr
        >> 16
    )


    file_type = stat.S_IFMT(
        unix_mode
    )


    if stat.S_ISLNK(
        unix_mode
    ):

        raise RuntimeError(
            "ZIP 내부 Symbolic Link는 허용되지 않습니다. "
            f"file={zip_info.filename}"
        )


    if zip_info.is_dir():

        return


    if file_type not in (
        0,
        stat.S_IFREG,
    ):

        raise RuntimeError(
            "ZIP 내부에 일반 파일이 아닌 "
            "특수 파일이 포함되어 있습니다. "
            f"file={zip_info.filename}"
        )


# ========================================
# ZIP 구조 검증
#
# 압축을 풀기 전에 Central Directory의
# 모든 Member를 먼저 검사한다.
#
# 검사:
# - Member 수
# - 경로 Traversal
# - Symbolic Link / 특수 파일
# - 암호화 ZIP
# - 지원하지 않는 압축 방식
# - 개별 압축 해제 크기
# - 전체 압축 해제 크기
# - 과도한 압축률
# - 중첩 Archive
#
# 반환값:
# 실제 분석에 필요한 Java / JavaScript /
# Python 소스 파일 Member 목록
# ========================================

def validate_zip_members(
    zip_file
):

    try:

        zip_infos = (
            zip_file.infolist()
        )

    except zipfile.BadZipFile:

        raise RuntimeError(
            "ZIP 중앙 디렉터리를 읽을 수 없습니다."
        )


    if not zip_infos:

        raise RuntimeError(
            "ZIP 파일 내부가 비어 있습니다."
        )


    if (
        len(
            zip_infos
        )
        >
        MAX_ZIP_MEMBER_COUNT
    ):

        raise RuntimeError(
            "ZIP 내부 항목 수가 허용 한도 "
            f"{MAX_ZIP_MEMBER_COUNT}개를 초과했습니다."
        )


    total_uncompressed_size = 0

    regular_file_count = 0

    seen_paths = set()

    source_members = []


    for zip_info in zip_infos:

        relative_path = (
            normalize_zip_member_path(
                zip_info.filename
            )
        )


        # "." 같은 의미 없는 Directory Entry

        if relative_path is None:

            continue


        normalized_path = str(
            relative_path
        )


        if normalized_path in seen_paths:

            raise RuntimeError(
                "ZIP 내부에 동일한 경로가 중복되어 있습니다. "
                f"file={normalized_path}"
            )


        seen_paths.add(
            normalized_path
        )


        validate_zip_member_type(
            zip_info
        )


        # Directory는 용량/압축률 대상에서 제외

        if zip_info.is_dir():

            continue


        regular_file_count += 1


        if (
            regular_file_count
            >
            MAX_ZIP_MEMBER_COUNT
        ):

            raise RuntimeError(
                "ZIP 내부 파일 수가 허용 한도 "
                f"{MAX_ZIP_MEMBER_COUNT}개를 초과했습니다."
            )


        # --------------------------------
        # 암호화 Member 차단
        # --------------------------------

        if (
            zip_info.flag_bits
            & 0x1
        ):

            raise RuntimeError(
                "암호화된 ZIP 내부 파일은 허용되지 않습니다. "
                f"file={normalized_path}"
            )


        # --------------------------------
        # 압축 방식 제한
        #
        # 일반적인 Stored / Deflate만 허용
        # --------------------------------

        if (
            zip_info.compress_type
            not in
            ALLOWED_ZIP_COMPRESSION_METHODS
        ):

            raise RuntimeError(
                "지원하지 않는 ZIP 압축 방식이 포함되어 있습니다. "
                f"file={normalized_path}"
            )


        # --------------------------------
        # 비정상 크기 차단
        # --------------------------------

        if (
            zip_info.file_size < 0
            or
            zip_info.compress_size < 0
        ):

            raise RuntimeError(
                "ZIP 내부 파일 크기 정보가 올바르지 않습니다. "
                f"file={normalized_path}"
            )


        if (
            zip_info.file_size
            >
            MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE
        ):

            raise RuntimeError(
                "ZIP 내부 단일 파일의 압축 해제 크기가 "
                "허용 한도 10MB를 초과했습니다. "
                f"file={normalized_path}"
            )


        total_uncompressed_size += (
            zip_info.file_size
        )


        if (
            total_uncompressed_size
            >
            MAX_ZIP_TOTAL_UNCOMPRESSED_SIZE
        ):

            raise RuntimeError(
                "ZIP 전체 압축 해제 크기가 "
                "허용 한도 200MB를 초과했습니다."
            )


        # --------------------------------
        # Zip Bomb 압축률 검사
        # --------------------------------

        if zip_info.file_size > 0:

            if zip_info.compress_size <= 0:

                raise RuntimeError(
                    "비정상적인 ZIP 압축 크기가 감지되었습니다. "
                    f"file={normalized_path}"
                )


            compression_ratio = (
                zip_info.file_size
                /
                zip_info.compress_size
            )


            if (
                compression_ratio
                >
                MAX_ZIP_COMPRESSION_RATIO
            ):

                raise RuntimeError(
                    "ZIP 내부 파일의 압축률이 "
                    "허용 범위를 초과했습니다. "
                    f"file={normalized_path}"
                )


        # --------------------------------
        # 중첩 Archive 차단
        # --------------------------------

        suffix = (
            relative_path
            .suffix
            .lower()
        )


        if (
            suffix
            in
            NESTED_ARCHIVE_EXTENSIONS
        ):

            raise RuntimeError(
                "중첩 압축 또는 Archive 파일은 "
                "업로드 소스에 포함할 수 없습니다. "
                f"file={normalized_path}"
            )


        # --------------------------------
        # 현재 지원하는 소스 확장자만
        # 실제 분석 디렉터리에 추출한다.
        #
        # README, 이미지, 빌드 산출물 등은
        # 안전성 검사는 수행하지만 추출하지 않는다.
        # --------------------------------

        ignored_directory_found = any(
            part.lower()
            in
            IGNORED_LANGUAGE_DIRECTORIES

            for part
            in relative_path.parts[:-1]
        )


        if ignored_directory_found:

            continue


        if (
            suffix
            in
            LANGUAGE_EXTENSIONS
        ):

            source_members.append(
                (
                    zip_info,
                    relative_path,
                )
            )


    if not source_members:

        raise RuntimeError(
            "ZIP 내부에서 지원하는 소스 파일을 찾을 수 없습니다. "
            "현재 지원 확장자는 "
            ".java, .js, .jsx, .mjs, .cjs, .py 입니다."
        )


    return source_members


# ========================================
# ZIP 안전 압축 해제
#
# zipfile.extractall()은 사용하지 않는다.
#
# 검증된 소스 Member만
# Fresh TemporaryDirectory 아래에
# Stream 방식으로 직접 기록한다.
#
# Central Directory의 file_size만 믿지 않고
# 실제 Stream 복사 중에도
# 개별 / 전체 크기를 다시 제한한다.
# ========================================

def safely_extract_zip(
    zip_path,
    extraction_root
):

    extraction_root = Path(
        extraction_root
    ).resolve()


    extraction_root.mkdir(
        parents=True,
        exist_ok=True,
    )


    runtime_total_size = 0


    try:

        with zipfile.ZipFile(
            zip_path,
            mode="r",
        ) as zip_file:

            source_members = (
                validate_zip_members(
                    zip_file
                )
            )


            for (
                zip_info,
                relative_path,
            ) in source_members:

                destination_path = (
                    extraction_root
                    / Path(
                        *relative_path.parts
                    )
                ).resolve()


                # ----------------------------
                # 최종 목적지가 반드시
                # Fresh extraction_root 내부인지
                # 다시 확인
                # ----------------------------

                try:

                    destination_path.relative_to(
                        extraction_root
                    )

                except ValueError:

                    raise RuntimeError(
                        "ZIP 압축 해제 경로가 "
                        "허용된 작업 디렉터리를 벗어났습니다."
                    )


                try:

                    destination_path.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                except OSError as error:

                    raise RuntimeError(
                        "ZIP 압축 해제 디렉터리를 "
                        "생성할 수 없습니다. "
                        f"{error}"
                    )


                member_written_size = 0


                try:

                    with (
                        zip_file.open(
                            zip_info,
                            mode="r",
                        )
                        as source_stream,
                        destination_path.open(
                            mode="xb",
                        )
                        as destination_stream
                    ):

                        while True:

                            chunk = (
                                source_stream.read(
                                    ZIP_EXTRACT_CHUNK_SIZE
                                )
                            )


                            if not chunk:

                                break


                            member_written_size += (
                                len(
                                    chunk
                                )
                            )

                            runtime_total_size += (
                                len(
                                    chunk
                                )
                            )


                            if (
                                member_written_size
                                >
                                MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE
                            ):

                                raise RuntimeError(
                                    "ZIP 압축 해제 중 단일 파일 크기가 "
                                    "허용 한도 10MB를 초과했습니다. "
                                    f"file={relative_path}"
                                )


                            if (
                                runtime_total_size
                                >
                                MAX_ZIP_TOTAL_UNCOMPRESSED_SIZE
                            ):

                                raise RuntimeError(
                                    "ZIP 압축 해제 중 전체 크기가 "
                                    "허용 한도 200MB를 초과했습니다."
                                )


                            destination_stream.write(
                                chunk
                            )


                except (
                    zipfile.BadZipFile,
                    RuntimeError,
                ):

                    raise

                except (
                    OSError,
                    EOFError,
                    NotImplementedError,
                ) as error:

                    raise RuntimeError(
                        "ZIP 내부 파일을 안전하게 "
                        "압축 해제할 수 없습니다. "
                        f"file={relative_path}, "
                        f"error={error}"
                    )


                # Central Directory의 크기와
                # 실제 읽은 크기가 다른 비정상 ZIP 차단

                if (
                    member_written_size
                    !=
                    zip_info.file_size
                ):

                    raise RuntimeError(
                        "ZIP 내부 파일의 실제 크기와 "
                        "기록된 크기가 일치하지 않습니다. "
                        f"file={relative_path}"
                    )


    except zipfile.BadZipFile:

        raise RuntimeError(
            "손상되었거나 올바르지 않은 ZIP 파일입니다."
        )


# ========================================
# Upload ZIP 분석 대상 준비
#
# 업로드 ZIP은 원본 위치에서 직접 분석하지 않는다.
#
# Fresh TemporaryDirectory에
# 검증된 소스 코드만 안전하게 추출한 뒤
# 그 디렉터리를 analysis_root로 사용한다.
#
# context 종료 시 임시 파일은 자동 삭제된다.
# ========================================

@contextmanager
def prepare_upload_target(
    source_version
):

    zip_path = (
        get_upload_zip_path(
            source_version
        )
    )


    with tempfile.TemporaryDirectory(
        prefix="sast_upload_"
    ) as temp_directory:

        analysis_root = (
            Path(temp_directory)
            / "source"
        )


        safely_extract_zip(
            zip_path,
            analysis_root,
        )


        yield analysis_root


# ========================================
# Internal Path 분석 대상
# ========================================

def get_internal_target(
    source_version
):

    internal_root = (
        Path(settings.BASE_DIR)
        / "internal_sources"
    ).resolve()


    raw_path = (
        source_version.internal_path
        or ""
    ).strip()


    if not raw_path:

        raise RuntimeError(
            "내부 분석 경로가 등록되어 있지 않습니다."
        )


    requested_path = Path(
        raw_path
    )


    if requested_path.is_absolute():

        target_path = (
            requested_path.resolve()
        )

    else:

        target_path = (
            internal_root
            / requested_path
        ).resolve()


    try:

        target_path.relative_to(
            internal_root
        )

    except ValueError:

        raise RuntimeError(
            "허용되지 않은 내부 분석 경로입니다."
        )


    if not target_path.exists():

        raise RuntimeError(
            "내부 분석 경로가 존재하지 않습니다."
        )


    if (
        not target_path.is_file()
        and
        not target_path.is_dir()
    ):

        raise RuntimeError(
            "내부 분석 대상이 올바른 파일 또는 디렉터리가 아닙니다."
        )


    return target_path


# ========================================
# Repository 분석 대상
# ========================================

@contextmanager
def prepare_repository_target(
    source_version
):

    repository_url = (
        source_version.repository_url
        or ""
    ).strip()


    if not repository_url:

        raise RuntimeError(
            "Repository URL이 등록되어 있지 않습니다."
        )


    with tempfile.TemporaryDirectory(
        prefix="sast_repository_"
    ) as temp_directory:

        clone_path = (
            Path(temp_directory)
            / "repository"
        )


        git_environment = (
            os.environ.copy()
        )

        git_environment[
            "GIT_TERMINAL_PROMPT"
        ] = "0"


        try:

            clone_result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--",
                    repository_url,
                    str(clone_path),
                ],

                capture_output=True,
                text=True,

                timeout=GIT_CLONE_TIMEOUT,

                env=git_environment,

                check=False,
            )

        except subprocess.TimeoutExpired:

            raise RuntimeError(
                "Repository 복제 시간이 초과되었습니다."
            )

        except OSError as error:

            raise RuntimeError(
                "Git 명령을 실행할 수 없습니다. "
                f"{error}"
            )


        if clone_result.returncode != 0:

            error_message = (
                clone_result.stderr
                or
                clone_result.stdout
                or
                "알 수 없는 Git 오류"
            )

            raise RuntimeError(
                "Repository 복제에 실패했습니다.\n"
                + truncate_log(
                    error_message
                )
            )


        if not clone_path.exists():

            raise RuntimeError(
                "Repository 복제 후 분석 경로를 찾을 수 없습니다."
            )


        yield clone_path


# ========================================
# SourceVersion 분석 대상 준비
# ========================================

@contextmanager
def prepare_analysis_target(
    source_version
):

    # ------------------------------------
    # Upload
    # ------------------------------------

    if (
        source_version.source_type
        ==
        SourceVersion.SourceType.UPLOAD
    ):

        with prepare_upload_target(
            source_version
        ) as target_path:

            yield target_path

        return


    # ------------------------------------
    # Repository
    # ------------------------------------

    if (
        source_version.source_type
        ==
        SourceVersion.SourceType.REPOSITORY
    ):

        with prepare_repository_target(
            source_version
        ) as target_path:

            yield target_path

        return


    # ------------------------------------
    # Internal
    # ------------------------------------

    if (
        source_version.source_type
        ==
        SourceVersion.SourceType.INTERNAL
    ):

        yield get_internal_target(
            source_version
        )

        return


    raise RuntimeError(
        "지원하지 않는 SourceVersion 유형입니다."
    )


# ========================================
# 언어 이름 정규화
# ========================================

def normalize_language_name(
    value
):

    normalized = (
        str(
            value
            or ""
        )
        .strip()
        .lower()
    )


    return (
        LANGUAGE_ALIASES.get(
            normalized,
            ""
        )
    )


# ========================================
# 단일 파일 언어 감지
# ========================================

def detect_file_language(
    file_path
):

    path = Path(
        file_path
    )


    return (
        LANGUAGE_EXTENSIONS.get(
            path.suffix.lower()
        )
    )


# ========================================
# 분석 대상 언어 자동 감지
#
# 파일:
# → 해당 파일 확장자 기준
#
# 디렉터리:
# → 하위 파일을 순회하여
#   Java / JavaScript / Python 감지
#
# node_modules, .git, build 등
# 분석과 직접 관련 없는 대형 디렉터리는
# 언어 감지 단계에서 제외한다.
# ========================================

def detect_languages(
    target_path
):

    target_path = Path(
        target_path
    ).resolve()


    detected = set()


    # ------------------------------------
    # 단일 파일
    # ------------------------------------

    if target_path.is_file():

        language = (
            detect_file_language(
                target_path
            )
        )


        if language:

            detected.add(
                language
            )


    # ------------------------------------
    # 디렉터리
    # ------------------------------------

    elif target_path.is_dir():

        for (
            current_root,
            directory_names,
            file_names,
        ) in os.walk(
            target_path,
            followlinks=False,
        ):

            current_root_path = Path(
                current_root
            )


            directory_names[:] = [
                directory_name

                for directory_name
                in directory_names

                if (
                    directory_name
                    not in
                    IGNORED_LANGUAGE_DIRECTORIES
                    and
                    not (
                        current_root_path
                        / directory_name
                    ).is_symlink()
                )
            ]


            for file_name in file_names:

                file_path = (
                    current_root_path
                    / file_name
                )


                if file_path.is_symlink():

                    continue


                language = (
                    detect_file_language(
                        file_path
                    )
                )


                if language:

                    detected.add(
                        language
                    )


                if (
                    len(
                        detected
                    )
                    ==
                    len(
                        SUPPORTED_LANGUAGE_ORDER
                    )
                ):

                    break


            if (
                len(
                    detected
                )
                ==
                len(
                    SUPPORTED_LANGUAGE_ORDER
                )
            ):

                break


    else:

        raise RuntimeError(
            "언어를 감지할 분석 대상이 올바르지 않습니다."
        )


    return [
        language

        for language
        in SUPPORTED_LANGUAGE_ORDER

        if language in detected
    ]


# ========================================
# 기존 단일 언어 필드 호환값
#
# 전환 기간 동안
# SourceVersion.language /
# AnalysisRun.analysis_language에
# 자동 감지 결과를 문자열로도 저장한다.
#
# 예:
# ["javascript", "python"]
# → "JavaScript, Python"
# ========================================

def get_legacy_language_value(
    languages
):

    return ", ".join(
        LANGUAGE_DISPLAY_NAMES.get(
            language,
            language
        )

        for language
        in languages
    )


# ========================================
# 자동 감지 언어 DB 저장
# ========================================

def save_detected_languages(
    source_version,
    analysis_run_id,
    detected_languages
):

    legacy_language = (
        get_legacy_language_value(
            detected_languages
        )
    )


    with transaction.atomic():

        locked_source_version = (
            SourceVersion.objects
            .select_for_update()
            .get(
                pk=
                    source_version.pk
            )
        )


        locked_source_version.detected_languages = (
            list(
                detected_languages
            )
        )

        locked_source_version.language = (
            legacy_language
        )


        locked_source_version.save(
            update_fields=[
                "detected_languages",
                "language",
            ]
        )


        locked_analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .get(
                pk=
                    analysis_run_id
            )
        )


        locked_analysis_run.analysis_languages = (
            list(
                detected_languages
            )
        )

        locked_analysis_run.analysis_language = (
            legacy_language
        )


        locked_analysis_run.save(
            update_fields=[
                "analysis_languages",
                "analysis_language",
                "updated_at",
            ]
        )


# ========================================
# 분석 언어별 KISA Rule 경로
# ========================================

def get_semgrep_rule_path(
    language
):

    language = (
        normalize_language_name(
            language
        )
    )


    if not language:

        raise RuntimeError(
            "지원하지 않는 분석 언어입니다."
        )


    rule_path = (
        SEMGREP_RULE_ROOT
        / language
    )


    if (
        not rule_path.exists()
        or
        not rule_path.is_dir()
    ):

        raise RuntimeError(
            "자동 감지된 언어의 KISA Custom Rule이 "
            "아직 준비되지 않았습니다. "
            f"language={language}, "
            f"rule_path={rule_path}"
        )


    return rule_path


# ========================================
# Semgrep 실행
# ========================================

def execute_semgrep(
    target_path,
    rule_path
):

    command = [
        "semgrep",
        "scan",

        "--config",
        str(rule_path),

        "--metrics=off",

        "--json",

        str(target_path),
    ]


    try:

        result = subprocess.run(
            command,

            capture_output=True,
            text=True,

            timeout=SEMGREP_TIMEOUT,

            check=False,
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "Semgrep 분석 시간이 초과되었습니다."
        )

    except OSError as error:

        raise RuntimeError(
            "Semgrep을 실행할 수 없습니다. "
            f"{error}"
        )


    stdout = (
        result.stdout
        or ""
    ).strip()

    stderr = (
        result.stderr
        or ""
    ).strip()


    if not stdout:

        raise RuntimeError(
            "Semgrep이 JSON 결과를 반환하지 않았습니다."
            + (
                "\n"
                + truncate_log(
                    stderr
                )
                if stderr
                else ""
            )
        )


    try:

        raw_result = json.loads(
            stdout
        )

    except json.JSONDecodeError:

        raise RuntimeError(
            "Semgrep 결과를 JSON으로 해석할 수 없습니다."
            + (
                "\n"
                + truncate_log(
                    stderr
                )
                if stderr
                else ""
            )
        )


    if result.returncode != 0:

        error_message = (
            stderr
            or
            raw_result.get(
                "errors"
            )
            or
            "알 수 없는 Semgrep 오류"
        )

        raise RuntimeError(
            "Semgrep 분석에 실패했습니다.\n"
            + truncate_log(
                str(
                    error_message
                )
            )
        )


    return {
        "raw_result":
            raw_result,

        "logs":
            truncate_log(
                stderr
            ),
    }


# ========================================
# 다중 언어 Semgrep 실행
#
# 언어별 KISA Rule 디렉터리로
# 각각 Semgrep을 실행한다.
#
# raw_result에는
# - 전체 통합 results
# - 언어별 원본 결과
# 를 함께 보관한다.
# ========================================

def execute_semgrep_for_languages(
    target_path,
    languages
):

    language_results = {}

    combined_results = []

    combined_errors = []

    log_sections = []


    for language in languages:

        rule_path = (
            get_semgrep_rule_path(
                language
            )
        )


        semgrep_result = (
            execute_semgrep(
                target_path,
                rule_path
            )
        )


        language_raw_result = (
            semgrep_result[
                "raw_result"
            ]
        )


        language_results[
            language
        ] = language_raw_result


        combined_results.extend(
            language_raw_result.get(
                "results"
            )
            or []
        )


        combined_errors.extend(
            language_raw_result.get(
                "errors"
            )
            or []
        )


        language_logs = (
            semgrep_result.get(
                "logs"
            )
            or ""
        )


        if language_logs:

            log_sections.append(
                (
                    "["
                    + LANGUAGE_DISPLAY_NAMES.get(
                        language,
                        language
                    )
                    + "]\n"
                    + language_logs
                )
            )


    return {
        "raw_result": {
            "analysis_languages":
                list(
                    languages
                ),

            "results":
                combined_results,

            "errors":
                combined_errors,

            "language_results":
                language_results,
        },

        "logs":
            truncate_log(
                "\n\n".join(
                    log_sections
                )
            ),
    }


# ========================================
# Severity 변환
# ========================================

def normalize_severity(
    value
):

    severity = (
        str(
            value
            or ""
        )
        .strip()
        .lower()
    )


    if severity == "critical":

        return (
            Vulnerability
            .Severity
            .CRITICAL
        )


    if severity in [
        "high",
        "error",
    ]:

        return (
            Vulnerability
            .Severity
            .HIGH
        )


    if severity in [
        "medium",
        "warning",
    ]:

        return (
            Vulnerability
            .Severity
            .MEDIUM
        )


    return (
        Vulnerability
        .Severity
        .LOW
    )


# ========================================
# Confidence 변환
# ========================================

def normalize_confidence(
    value
):

    confidence = (
        str(
            value
            or ""
        )
        .strip()
        .lower()
    )


    if confidence == "high":

        return (
            Vulnerability
            .Confidence
            .HIGH
        )


    if confidence == "medium":

        return (
            Vulnerability
            .Confidence
            .MEDIUM
        )


    if confidence == "low":

        return (
            Vulnerability
            .Confidence
            .LOW
        )


    return ""


# ========================================
# 문자열 변환
# ========================================

def normalize_text(
    value
):

    if value is None:
        return ""

    if isinstance(
        value,
        str
    ):

        return value


    try:

        return json.dumps(
            value,
            ensure_ascii=False
        )

    except (
        TypeError,
        ValueError,
    ):

        return str(
            value
        )


# ========================================
# Placeholder 값 확인
# ========================================

def is_placeholder_value(
    value
):

    if value is None:
        return True


    normalized = (
        str(
            value
        )
        .strip()
        .lower()
    )


    return normalized in [
        "",
        "false",
        "none",
        "null",
        "requires login",
    ]


# ========================================
# KISA 항목 조회
# ========================================

def get_kisa_security_weakness(
    metadata
):

    kisa_identifier = (
        metadata.get(
            "kisa_identifier"
        )
        or ""
    ).strip()


    if not kisa_identifier:

        raise RuntimeError(
            "Semgrep Rule에 "
            "kisa_identifier가 없습니다."
        )


    try:

        return (
            KisaSecurityWeakness.objects
            .get(
                identifier=
                    kisa_identifier
            )
        )

    except KisaSecurityWeakness.DoesNotExist:

        raise RuntimeError(
            "KISA 진단 기준 Master Data를 "
            "찾을 수 없습니다. "
            f"identifier={kisa_identifier}"
        )


# ========================================
# 취약점 이름
# ========================================

def get_vulnerability_name(
    metadata,
    rule_id
):

    kisa_name = (
        metadata.get(
            "kisa_name"
        )
    )


    if kisa_name:

        return str(
            kisa_name
        )


    metadata_name = (
        metadata.get(
            "name"
        )
        or
        metadata.get(
            "title"
        )
    )


    if metadata_name:

        return str(
            metadata_name
        )


    return str(
        rule_id
    )


# ========================================
# 실제 결과 파일 경로
# ========================================

def resolve_result_file_path(
    semgrep_result,
    analysis_target
):

    raw_result_path = (
        semgrep_result.get(
            "path"
        )
        or
        ""
    )


    target_path = Path(
        analysis_target
    ).resolve()


    if not raw_result_path:

        if target_path.is_file():

            return target_path

        return None


    result_path = Path(
        raw_result_path
    )


    if result_path.is_absolute():

        candidate_path = (
            result_path.resolve()
        )

    else:

        if target_path.is_file():

            candidate_path = (
                target_path
            )

        else:

            candidate_path = (
                target_path
                / result_path
            ).resolve()


    if not candidate_path.exists():

        return None


    if not candidate_path.is_file():

        return None


    return candidate_path


# ========================================
# 화면 표시용 파일 경로
# ========================================

def get_display_file_path(
    semgrep_result,
    analysis_target
):

    raw_result_path = (
        semgrep_result.get(
            "path"
        )
        or
        ""
    )


    target_path = Path(
        analysis_target
    ).resolve()


    resolved_file = (
        resolve_result_file_path(
            semgrep_result,
            analysis_target
        )
    )


    if resolved_file is None:

        return str(
            raw_result_path
        )[:1000]


    if target_path.is_file():

        return (
            resolved_file.name
        )[:1000]


    try:

        relative_path = (
            resolved_file
            .relative_to(
                target_path
            )
        )

        return str(
            relative_path
        )[:1000]

    except ValueError:

        return (
            resolved_file.name
        )[:1000]


# ========================================
# 실제 코드 Evidence 추출
# ========================================

def extract_evidence(
    semgrep_result,
    analysis_target
):

    source_file = (
        resolve_result_file_path(
            semgrep_result,
            analysis_target
        )
    )


    if source_file is None:

        return ""


    start = (
        semgrep_result.get(
            "start"
        )
        or {}
    )

    end = (
        semgrep_result.get(
            "end"
        )
        or {}
    )


    start_line = (
        start.get(
            "line"
        )
    )

    end_line = (
        end.get(
            "line"
        )
        or
        start_line
    )


    if not start_line:

        return ""


    try:

        start_line = int(
            start_line
        )

        end_line = int(
            end_line
        )

    except (
        TypeError,
        ValueError,
    ):

        return ""


    if start_line < 1:

        return ""


    if end_line < start_line:

        end_line = start_line


    end_line = min(
        end_line,
        start_line
        + MAX_EVIDENCE_LINES
        - 1
    )


    try:

        source_lines = (
            source_file
            .read_text(
                encoding="utf-8",
                errors="replace"
            )
            .splitlines()
        )

    except OSError:

        return ""


    if (
        start_line
        >
        len(
            source_lines
        )
    ):

        return ""


    selected_lines = (
        source_lines[
            start_line - 1:
            end_line
        ]
    )


    evidence = "\n".join(
        selected_lines
    )


    if (
        len(
            evidence
        )
        >
        MAX_EVIDENCE_LENGTH
    ):

        evidence = (
            evidence[
                :MAX_EVIDENCE_LENGTH
            ]
            + "\n[코드 일부 생략]"
        )


    return evidence


# ========================================
# 권고 조치 사항
# ========================================

def get_recommendation(
    extra,
    metadata
):

    # ------------------------------------
    # KISA Custom Rule의 recommendation
    # 최우선 사용
    # ------------------------------------

    recommendation = (
        metadata.get(
            "recommendation"
        )
    )


    if not is_placeholder_value(
        recommendation
    ):

        return normalize_text(
            recommendation
        )


    # ------------------------------------
    # Semgrep fix
    # ------------------------------------

    fix = (
        extra.get(
            "fix"
        )
    )


    if not is_placeholder_value(
        fix
    ):

        return normalize_text(
            fix
        )


    remediation = (
        metadata.get(
            "remediation"
        )
    )


    if not is_placeholder_value(
        remediation
    ):

        return normalize_text(
            remediation
        )


    return ""


# ========================================
# Semgrep Result
# → Vulnerability
# ========================================

def build_vulnerability(
    analysis_run,
    semgrep_result,
    analysis_target,
    analysis_language
):

    extra = (
        semgrep_result.get(
            "extra"
        )
        or {}
    )

    metadata = (
        extra.get(
            "metadata"
        )
        or {}
    )

    start = (
        semgrep_result.get(
            "start"
        )
        or {}
    )


    # ------------------------------------
    # KISA Master Data 매칭
    # ------------------------------------

    security_weakness = (
        get_kisa_security_weakness(
            metadata
        )
    )


    # ------------------------------------
    # Semgrep Rule ID
    # ------------------------------------

    rule_id = (
        semgrep_result.get(
            "check_id"
        )
        or
        "unknown-rule"
    )


    # ------------------------------------
    # 진단 명칭
    # ------------------------------------

    name = (
        get_vulnerability_name(
            metadata,
            rule_id
        )
    )


    # ------------------------------------
    # 심각도
    # ------------------------------------

    severity = (
        normalize_severity(
            extra.get(
                "severity"
            )
        )
    )


    # ------------------------------------
    # 신뢰도
    # ------------------------------------

    confidence = (
        normalize_confidence(
            metadata.get(
                "confidence"
            )
        )
    )


    # ------------------------------------
    # 파일 경로
    # ------------------------------------

    file_path = (
        get_display_file_path(
            semgrep_result,
            analysis_target
        )
    )


    # ------------------------------------
    # 위치
    #
    # 현재 모델은 line 하나만 저장
    # ------------------------------------

    line = (
        start.get(
            "line"
        )
    )


    # ------------------------------------
    # 메시지
    # ------------------------------------

    message = (
        normalize_text(
            extra.get(
                "message"
            )
        )
    )


    # ------------------------------------
    # 탐지 근거
    # ------------------------------------

    evidence = (
        extract_evidence(
            semgrep_result,
            analysis_target
        )
    )


    # ------------------------------------
    # 권고 조치 사항
    # ------------------------------------

    recommendation = (
        get_recommendation(
            extra,
            metadata
        )
    )


    return Vulnerability(
        analysis_run=
            analysis_run,

        security_weakness=
            security_weakness,

        analysis_language=
            analysis_language,

        rule_id=
            str(
                rule_id
            )[:200],

        name=
            str(
                name
            )[:300],

        severity=
            severity,

        confidence=
            confidence,

        file_path=
            str(
                file_path
            )[:1000],

        line=
            line,

        message=
            message,

        evidence=
            evidence,

        recommendation=
            recommendation,
    )


# ========================================
# Vulnerability 저장
# ========================================

def save_vulnerabilities(
    analysis_run,
    raw_result,
    analysis_target
):

    vulnerability_objects = []


    language_results = (
        raw_result.get(
            "language_results"
        )
        or {}
    )


    # ------------------------------------
    # 신규 다중 언어 결과
    # ------------------------------------

    if language_results:

        for (
            analysis_language,
            language_raw_result,
        ) in language_results.items():

            normalized_language = (
                normalize_language_name(
                    analysis_language
                )
            )


            results = (
                language_raw_result.get(
                    "results"
                )
                or []
            )


            for semgrep_result in results:

                vulnerability_objects.append(
                    build_vulnerability(
                        analysis_run,
                        semgrep_result,
                        analysis_target,
                        normalized_language,
                    )
                )


    # ------------------------------------
    # 기존 단일 raw_result 호환
    # ------------------------------------

    else:

        results = (
            raw_result.get(
                "results"
            )
            or []
        )


        legacy_language = (
            normalize_language_name(
                analysis_run
                .analysis_language
            )
        )


        for semgrep_result in results:

            result_file_path = (
                get_display_file_path(
                    semgrep_result,
                    analysis_target
                )
            )


            detected_result_language = (
                detect_file_language(
                    result_file_path
                )
            )


            vulnerability_language = (
                detected_result_language
                or
                legacy_language
            )


            vulnerability_objects.append(
                build_vulnerability(
                    analysis_run,
                    semgrep_result,
                    analysis_target,
                    vulnerability_language,
                )
            )


    analysis_run.vulnerabilities.all().delete()


    if vulnerability_objects:

        Vulnerability.objects.bulk_create(
            vulnerability_objects
        )


    return len(
        vulnerability_objects
    )


# ========================================
# Chunk Worker Exception
# ========================================

class ChunkOwnershipLostError(
    RuntimeError
):

    pass


class NonRetryableChunkError(
    RuntimeError
):

    pass


# ========================================
# Chunk Relative Path 검증
#
# AnalysisChunkFile.relative_path는
# DB 내부 값이지만 Worker 경계에서 다시 검증한다.
# ========================================

def normalize_chunk_relative_path(
    relative_path
):

    value = str(
        relative_path
        or ""
    )


    if not value:

        raise NonRetryableChunkError(
            "Chunk File 상대 경로가 비어 있습니다."
        )


    if (
        "\\" in value
        or
        "\x00" in value
    ):

        raise NonRetryableChunkError(
            "Chunk File 경로에 허용되지 않는 문자가 "
            "포함되어 있습니다."
        )


    posix_path = PurePosixPath(
        value
    )


    if posix_path.is_absolute():

        raise NonRetryableChunkError(
            "Chunk File에 절대 경로를 사용할 수 없습니다."
        )


    normalized_parts = []


    for part in posix_path.parts:

        if part in (
            "",
            ".",
        ):

            continue


        if part == "..":

            raise NonRetryableChunkError(
                "Chunk File 경로에 상위 경로 이동(..)이 "
                "포함되어 있습니다."
            )


        normalized_parts.append(
            part
        )


    if not normalized_parts:

        raise NonRetryableChunkError(
            "Chunk File 상대 경로가 올바르지 않습니다."
        )


    return PurePosixPath(
        *normalized_parts
    )


# ========================================
# Chunk File → 실행 Workspace 복사
#
# Persistent Workspace의 Source를
# 실제 Semgrep 실행용 TemporaryDirectory로
# 복사하면서 다음을 검증한다.
#
# - Path containment
# - Symbolic Link
# - File size
# - SHA-256
# ========================================

def copy_verified_chunk_file(
    chunk_file,
    workspace_source_root,
    execution_source_root,
):

    relative_path = (
        normalize_chunk_relative_path(
            chunk_file.relative_path
        )
    )


    if (
        chunk_file.file_class
        ==
        AnalysisChunkFile.FileClass.OVERSIZED
    ):

        raise NonRetryableChunkError(
            "실행 가능한 Chunk에 Oversized File이 "
            "포함되어 있습니다. "
            f"file={relative_path}"
        )


    expected_hash = str(
        chunk_file.content_sha256
        or ""
    ).lower()


    if (
        len(expected_hash)
        !=
        64
    ):

        raise NonRetryableChunkError(
            "Chunk File SHA-256 Snapshot이 올바르지 않습니다. "
            f"file={relative_path}"
        )


    source_path = (
        workspace_source_root
        /
        Path(
            *relative_path.parts
        )
    )


    if source_path.is_symlink():

        raise NonRetryableChunkError(
            "Workspace Source에 Symbolic Link가 감지되었습니다. "
            f"file={relative_path}"
        )


    try:

        resolved_source_path = (
            source_path.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ) as error:

        raise NonRetryableChunkError(
            "Workspace Source File을 찾을 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    try:

        resolved_source_path.relative_to(
            workspace_source_root
        )

    except ValueError:

        raise NonRetryableChunkError(
            "Workspace Source File이 허용 경로를 벗어났습니다. "
            f"file={relative_path}"
        )


    if not resolved_source_path.is_file():

        raise NonRetryableChunkError(
            "Workspace Source가 일반 파일이 아닙니다. "
            f"file={relative_path}"
        )


    try:

        before_stat = (
            resolved_source_path.stat()
        )

    except OSError as error:

        raise NonRetryableChunkError(
            "Workspace Source File 정보를 읽을 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    if (
        before_stat.st_size
        !=
        chunk_file.size_bytes
    ):

        raise NonRetryableChunkError(
            "Workspace Source File 크기가 Snapshot과 "
            "일치하지 않습니다. "
            f"file={relative_path}"
        )


    destination_path = (
        execution_source_root
        /
        Path(
            *relative_path.parts
        )
    )


    try:

        destination_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    except OSError as error:

        raise RuntimeError(
            "Chunk 실행 Directory를 생성할 수 없습니다. "
            f"error={error}"
        )


    sha256 = hashlib.sha256()

    copied_size = 0


    try:

        with (
            resolved_source_path.open(
                mode="rb"
            )
            as source_file,

            destination_path.open(
                mode="xb"
            )
            as destination_file
        ):

            while True:

                data = (
                    source_file.read(
                        1024
                        * 1024
                    )
                )


                if not data:

                    break


                destination_file.write(
                    data
                )


                sha256.update(
                    data
                )


                copied_size += (
                    len(
                        data
                    )
                )


        destination_path.chmod(
            0o600
        )

    except OSError as error:

        raise RuntimeError(
            "Chunk 실행용 Source File을 복사할 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    if (
        copied_size
        !=
        chunk_file.size_bytes
    ):

        raise NonRetryableChunkError(
            "Chunk 실행용 Source File 크기가 Snapshot과 "
            "일치하지 않습니다. "
            f"file={relative_path}"
        )


    actual_hash = (
        sha256.hexdigest()
    )


    if (
        actual_hash
        !=
        expected_hash
    ):

        raise NonRetryableChunkError(
            "Workspace Source File SHA-256이 Snapshot과 "
            "일치하지 않습니다. "
            f"file={relative_path}"
        )


    try:

        after_stat = (
            resolved_source_path.stat()
        )

    except OSError as error:

        raise NonRetryableChunkError(
            "Chunk 복사 후 Workspace Source 정보를 "
            "확인할 수 없습니다. "
            f"file={relative_path}, "
            f"error={error}"
        )


    if (
        before_stat.st_size
        !=
        after_stat.st_size
        or
        before_stat.st_mtime_ns
        !=
        after_stat.st_mtime_ns
    ):

        raise NonRetryableChunkError(
            "Chunk 실행 준비 중 Workspace Source File이 "
            "변경되었습니다. "
            f"file={relative_path}"
        )


    return destination_path


# ========================================
# Chunk 실행 대상 준비
#
# Persistent Workspace 전체를 분석하지 않고
# 해당 Chunk에 할당된 File만 Fresh Temp에
# 복사한다.
# ========================================

@contextmanager
def prepare_chunk_execution_target(
    chunk
):

    workspace_source_root = (
        get_analysis_workspace_source_root(
            chunk.analysis_run_id
        )
    )


    try:

        workspace_source_root = (
            workspace_source_root.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ) as error:

        raise NonRetryableChunkError(
            "Analysis Workspace Source를 찾을 수 없습니다. "
            f"error={error}"
        )


    if not workspace_source_root.is_dir():

        raise NonRetryableChunkError(
            "Analysis Workspace Source가 올바른 "
            "Directory가 아닙니다."
        )


    chunk_files = list(
        chunk.files
        .all()
        .order_by(
            "id"
        )
    )


    if not chunk_files:

        raise NonRetryableChunkError(
            "Chunk에 분석할 Source File이 없습니다."
        )


    if (
        len(chunk_files)
        !=
        chunk.file_count
    ):

        raise NonRetryableChunkError(
            "Chunk File Count가 DB Snapshot과 "
            "일치하지 않습니다."
        )


    actual_total_bytes = sum(
        chunk_file.size_bytes
        for chunk_file
        in chunk_files
    )


    if (
        actual_total_bytes
        !=
        chunk.total_bytes
    ):

        raise NonRetryableChunkError(
            "Chunk Total Bytes가 DB Snapshot과 "
            "일치하지 않습니다."
        )


    with tempfile.TemporaryDirectory(
        prefix=(
            f"sast_chunk_"
            f"{chunk.id}_"
        )
    ) as temp_directory:

        execution_source_root = (
            Path(
                temp_directory
            )
            /
            "source"
        )


        execution_source_root.mkdir(
            parents=True,
            exist_ok=False,
        )


        for chunk_file in chunk_files:

            copy_verified_chunk_file(
                chunk_file,
                workspace_source_root,
                execution_source_root,
            )


        yield execution_source_root


# ========================================
# Semgrep Process 종료
# ========================================

def terminate_semgrep_process(
    process
):

    if process.poll() is not None:

        return


    try:

        process.terminate()


        process.wait(
            timeout=5
        )

    except subprocess.TimeoutExpired:

        process.kill()


        process.wait()

    except OSError:

        pass


# ========================================
# Heartbeat 포함 Semgrep 실행
#
# subprocess pipe 대신 TemporaryFile을 사용해
# stdout/stderr 양이 많아도 pipe deadlock이
# 발생하지 않도록 한다.
# ========================================

def execute_semgrep_with_heartbeat(
    target_path,
    rule_path,
    attempt_id,
    execution_token,
):

    command = [
        "semgrep",
        "scan",

        "--config",
        str(
            rule_path
        ),

        "--metrics=off",
        "--json",

        str(
            target_path
        ),
    ]


    try:

        with (
            tempfile.TemporaryFile(
                mode="w+t",
                encoding="utf-8",
            )
            as stdout_file,

            tempfile.TemporaryFile(
                mode="w+t",
                encoding="utf-8",
            )
            as stderr_file
        ):

            try:

                process = subprocess.Popen(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    text=True,
                )

            except OSError as error:

                raise RuntimeError(
                    "Semgrep을 실행할 수 없습니다. "
                    f"{error}"
                )


            started_monotonic = (
                time.monotonic()
            )


            last_heartbeat_monotonic = (
                started_monotonic
            )


            while True:

                return_code = (
                    process.poll()
                )


                if return_code is not None:

                    break


                current_monotonic = (
                    time.monotonic()
                )


                if (
                    current_monotonic
                    -
                    started_monotonic
                    >
                    SEMGREP_TIMEOUT
                ):

                    terminate_semgrep_process(
                        process
                    )


                    raise RuntimeError(
                        "Semgrep 분석 시간이 초과되었습니다."
                    )


                if (
                    current_monotonic
                    -
                    last_heartbeat_monotonic
                    >=
                    CHUNK_HEARTBEAT_INTERVAL_SECONDS
                ):

                    heartbeat_result = (
                        heartbeat_attempt(
                            attempt_id,
                            execution_token,
                        )
                    )


                    if not heartbeat_result.get(
                        "updated"
                    ):

                        terminate_semgrep_process(
                            process
                        )


                        raise ChunkOwnershipLostError(
                            "Chunk Attempt 실행권을 잃어 "
                            "Semgrep 실행을 중단합니다. "
                            f"reason="
                            f"{heartbeat_result.get('reason')}"
                        )


                    last_heartbeat_monotonic = (
                        current_monotonic
                    )


                time.sleep(
                    1
                )


            stdout_file.seek(
                0
            )


            stderr_file.seek(
                0
            )


            stdout = (
                stdout_file.read()
                or ""
            ).strip()


            stderr = (
                stderr_file.read()
                or ""
            ).strip()


    except ChunkOwnershipLostError:

        raise


    if not stdout:

        raise RuntimeError(
            "Semgrep이 JSON 결과를 반환하지 않았습니다."
            + (
                "\n"
                + truncate_log(
                    stderr
                )
                if stderr
                else ""
            )
        )


    try:

        raw_result = json.loads(
            stdout
        )

    except json.JSONDecodeError:

        raise RuntimeError(
            "Semgrep 결과를 JSON으로 해석할 수 없습니다."
            + (
                "\n"
                + truncate_log(
                    stderr
                )
                if stderr
                else ""
            )
        )


    if return_code != 0:

        error_message = (
            stderr
            or
            raw_result.get(
                "errors"
            )
            or
            "알 수 없는 Semgrep 오류"
        )


        raise RuntimeError(
            "Semgrep 분석에 실패했습니다.\n"
            + truncate_log(
                str(
                    error_message
                )
            )
        )


    return {
        "raw_result":
            raw_result,

        "logs":
            truncate_log(
                stderr
            ),
    }


# ========================================
# Vulnerability Fingerprint
#
# 같은 Attempt 내부에서 동일 Semgrep Result가
# 중복 저장되는 것을 방지한다.
# ========================================

def build_vulnerability_fingerprint(
    semgrep_result,
    analysis_target
):

    rule_id = str(
        semgrep_result.get(
            "check_id"
        )
        or
        "unknown-rule"
    )


    file_path = (
        get_display_file_path(
            semgrep_result,
            analysis_target,
        )
    )


    start = (
        semgrep_result.get(
            "start"
        )
        or {}
    )


    end = (
        semgrep_result.get(
            "end"
        )
        or {}
    )


    payload = {
        "rule_id":
            rule_id,

        "file_path":
            str(
                file_path
            ).replace(
                "\\",
                "/",
            ),

        "start_line":
            start.get(
                "line"
            ),

        "start_col":
            start.get(
                "col"
            ),

        "end_line":
            end.get(
                "line"
            ),

        "end_col":
            end.get(
                "col"
            ),
    }


    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )


    return (
        hashlib.sha256(
            serialized.encode(
                "utf-8"
            )
        )
        .hexdigest()
    )


# ========================================
# Attempt-scoped Vulnerability 생성
# ========================================

def build_attempt_vulnerability(
    analysis_run,
    analysis_attempt,
    semgrep_result,
    analysis_target,
    analysis_language,
):

    vulnerability = (
        build_vulnerability(
            analysis_run,
            semgrep_result,
            analysis_target,
            analysis_language,
        )
    )


    vulnerability.analysis_attempt = (
        analysis_attempt
    )


    vulnerability.fingerprint = (
        build_vulnerability_fingerprint(
            semgrep_result,
            analysis_target,
        )
    )


    return vulnerability


# ========================================
# Attempt-scoped Vulnerability 저장
#
# 기존 save_vulnerabilities()처럼
# AnalysisRun 전체 결과를 삭제하지 않는다.
#
# 오직 현재 Attempt 결과만 저장한다.
# ========================================

def save_attempt_vulnerabilities(
    analysis_run_id,
    attempt_id,
    execution_token,
    raw_result,
    analysis_target,
    analysis_language,
):

    try:

        analysis_run = (
            AnalysisRun.objects
            .get(
                pk=
                    analysis_run_id
            )
        )


        analysis_attempt = (
            AnalysisChunkAttempt.objects
            .select_related(
                "chunk"
            )
            .get(
                pk=
                    attempt_id
            )
        )

    except (
        AnalysisRun.DoesNotExist,
        AnalysisChunkAttempt.DoesNotExist,
    ):

        raise ChunkOwnershipLostError(
            "취약점 저장 전에 AnalysisRun 또는 "
            "AnalysisChunkAttempt를 찾을 수 없습니다."
        )


    results = (
        raw_result.get(
            "results"
        )
        or []
    )


    vulnerability_objects = []


    for semgrep_result in results:

        vulnerability_objects.append(
            build_attempt_vulnerability(
                analysis_run,
                analysis_attempt,
                semgrep_result,
                analysis_target,
                analysis_language,
            )
        )


    # ====================================
    # 실제 DB Publish 전 실행권 재확인
    # ====================================

    with transaction.atomic():

        locked_analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .get(
                pk=
                    analysis_run_id
            )
        )


        locked_chunk = (
            AnalysisChunk.objects
            .select_for_update()
            .get(
                pk=
                    analysis_attempt.chunk_id
            )
        )


        locked_attempt = (
            AnalysisChunkAttempt.objects
            .select_for_update()
            .get(
                pk=
                    attempt_id
            )
        )


        if (
            locked_analysis_run.status
            !=
            AnalysisRun.Status.RUNNING
        ):

            raise ChunkOwnershipLostError(
                "AnalysisRun이 더 이상 running 상태가 아닙니다."
            )


        if (
            locked_chunk.status
            !=
            AnalysisChunk.Status.RUNNING
        ):

            raise ChunkOwnershipLostError(
                "AnalysisChunk가 더 이상 running 상태가 아닙니다."
            )


        if (
            locked_attempt.status
            !=
            AnalysisChunkAttempt.Status.RUNNING
        ):

            raise ChunkOwnershipLostError(
                "AnalysisChunkAttempt가 더 이상 running 상태가 아닙니다."
            )


        if (
            str(
                locked_attempt.execution_token
            )
            !=
            str(
                execution_token
                or ""
            )
        ):

            raise ChunkOwnershipLostError(
                "AnalysisChunkAttempt execution_token이 "
                "일치하지 않습니다."
            )


        # --------------------------------
        # 같은 Attempt 안의 이전 Partial 결과는
        # 현재 결과로 원자적으로 교체한다.
        # --------------------------------

        locked_attempt.vulnerabilities.all().delete()


        for vulnerability in vulnerability_objects:

            vulnerability.analysis_run = (
                locked_analysis_run
            )


            vulnerability.analysis_attempt = (
                locked_attempt
            )


        if vulnerability_objects:

            Vulnerability.objects.bulk_create(
                vulnerability_objects
            )


    return len(
        vulnerability_objects
    )


# ========================================
# AnalysisChunk Celery Worker
#
# IMPORTANT:
#
# Celery 자체 Retry를 사용하지 않는다.
#
# Retry의 Source of Truth는 PostgreSQL의
# Chunk / Attempt / Outbox이다.
# ========================================

@shared_task(
    bind=True,
    name=ANALYSIS_CHUNK_TASK_NAME,
    acks_late=True,
    reject_on_worker_lost=True,
)
def run_analysis_chunk(
    self,
    chunk_id
):

    celery_task_id = str(
        getattr(
            self.request,
            "id",
            "",
        )
        or ""
    )


    claim_result = (
        claim_chunk(
            chunk_id,
            celery_task_id=
                celery_task_id,
        )
    )


    if not claim_result.get(
        "claimed"
    ):

        return {
            "success":
                False,

            "claimed":
                False,

            "chunk_id":
                chunk_id,

            "reason":
                claim_result.get(
                    "reason"
                ),
        }


    analysis_run_id = (
        claim_result[
            "analysis_run_id"
        ]
    )


    attempt_id = (
        claim_result[
            "attempt_id"
        ]
    )


    execution_token = (
        claim_result[
            "execution_token"
        ]
    )


    try:

        chunk = (
            AnalysisChunk.objects
            .select_related(
                "analysis_run"
            )
            .prefetch_related(
                "files"
            )
            .get(
                pk=
                    chunk_id
            )
        )


        # =================================
        # KISA Rule
        #
        # Rule Directory가 없는 것은
        # 재시도로 해결되지 않는 설정 오류.
        # =================================

        try:

            rule_path = (
                get_semgrep_rule_path(
                    chunk.language
                )
            )

        except RuntimeError as error:

            raise NonRetryableChunkError(
                str(
                    error
                )
            )


        # =================================
        # Chunk Source 준비
        # =================================

        with prepare_chunk_execution_target(
            chunk
        ) as analysis_target:

            # =============================
            # Semgrep
            # =============================

            semgrep_result = (
                execute_semgrep_with_heartbeat(
                    analysis_target,
                    rule_path,
                    attempt_id,
                    execution_token,
                )
            )


            raw_result = (
                semgrep_result[
                    "raw_result"
                ]
            )


            logs = (
                semgrep_result.get(
                    "logs"
                )
                or ""
            )


            # =============================
            # Semgrep 종료 직후
            # 실행권 재확인 + Lease 연장
            # =============================

            heartbeat_result = (
                heartbeat_attempt(
                    attempt_id,
                    execution_token,
                )
            )


            if not heartbeat_result.get(
                "updated"
            ):

                raise ChunkOwnershipLostError(
                    "Semgrep 종료 후 Chunk 실행권을 "
                    "확인할 수 없습니다. "
                    f"reason="
                    f"{heartbeat_result.get('reason')}"
                )


            # =============================
            # Attempt-scoped 결과 저장
            # =============================

            try:

                vulnerability_count = (
                    save_attempt_vulnerabilities(
                        analysis_run_id,
                        attempt_id,
                        execution_token,
                        raw_result,
                        analysis_target,
                        chunk.language,
                    )
                )

            except ChunkOwnershipLostError:

                raise

            except RuntimeError as error:

                # KISA Master / Rule Metadata 문제 등은
                # 같은 Source를 재시도해도 해결되지 않는다.
                raise NonRetryableChunkError(
                    str(
                        error
                    )
                )


        # =================================
        # Chunk 완료 확정
        # =================================

        complete_result = (
            complete_chunk_attempt(
                attempt_id,
                execution_token,
                result_count=
                    vulnerability_count,
                raw_result=
                    raw_result,
                logs=
                    logs,
            )
        )


        if not complete_result.get(
            "completed"
        ):

            return {
                "success":
                    False,

                "claimed":
                    True,

                "chunk_id":
                    chunk_id,

                "attempt_id":
                    attempt_id,

                "reason":
                    complete_result.get(
                        "reason"
                    ),
            }


        return {
            "success":
                True,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "attempt_no":
                claim_result.get(
                    "attempt_no"
                ),

            "status":
                AnalysisChunk.Status.COMPLETED,

            "result_count":
                vulnerability_count,
        }


    except ChunkOwnershipLostError as error:

        # --------------------------------
        # stale Worker는 DB 상태를
        # 더 이상 변경하면 안 된다.
        # --------------------------------

        return {
            "success":
                False,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "reason":
                "ownership_lost",

            "message":
                truncate_log(
                    str(
                        error
                    )
                ),
        }


    except NonRetryableChunkError as error:

        failure_result = (
            fail_chunk_attempt(
                attempt_id,
                execution_token,
                failure_reason=
                    str(
                        error
                    ),
                logs=
                    str(
                        error
                    ),
                retryable=
                    False,
            )
        )


        return {
            "success":
                False,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "reason":
                failure_result.get(
                    "reason"
                ),

            "retryable":
                False,

            "message":
                truncate_log(
                    str(
                        error
                    )
                ),
        }


    except Exception as error:

        failure_result = (
            fail_chunk_attempt(
                attempt_id,
                execution_token,
                failure_reason=
                    str(
                        error
                    ),
                logs=
                    str(
                        error
                    ),
                retryable=
                    True,
            )
        )


        return {
            "success":
                False,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run_id,

            "chunk_id":
                chunk_id,

            "attempt_id":
                attempt_id,

            "reason":
                failure_result.get(
                    "reason"
                ),

            "retryable":
                True,

            "message":
                truncate_log(
                    str(
                        error
                    )
                ),
        }


# ========================================
# 즉시 처리 가능한 Outbox 전체 Dispatch
#
# Planner는 하나의 AnalysisRun에서
# 50개를 넘는 Chunk를 만들 수 있다.
#
# Dispatcher의 한 번 처리량은 제한되어 있으므로
# 현재 available_at <= now 인 Outbox가 없어질 때까지
# 여러 Batch를 반복한다.
#
# Redis publish 실패 Outbox는 available_at이
# 미래로 이동하므로 같은 Loop에서 즉시 재시도되지 않는다.
# ========================================

def dispatch_available_outboxes(
    max_batches=200,
):

    totals = {
        "batch_count": 0,
        "claimed_count": 0,
        "published_count": 0,
        "failed_count": 0,
        "cancelled_count": 0,
        "deferred_count": 0,
        "state_changed_count": 0,
    }


    for _ in range(
        max_batches
    ):

        result = (
            dispatch_pending_outboxes(
                batch_size=
                    OUTBOX_DISPATCH_BATCH_SIZE
            )
        )


        totals[
            "batch_count"
        ] += 1


        for key in (
            "claimed_count",
            "published_count",
            "failed_count",
            "cancelled_count",
            "deferred_count",
            "state_changed_count",
        ):

            totals[key] += int(
                result.get(
                    key,
                    0,
                )
                or 0
            )


        processed_count = (
            int(
                result.get(
                    "claimed_count",
                    0,
                )
                or 0
            )
            +
            int(
                result.get(
                    "cancelled_count",
                    0,
                )
                or 0
            )
            +
            int(
                result.get(
                    "deferred_count",
                    0,
                )
                or 0
            )
        )


        if processed_count == 0:

            break


    return totals


# ========================================
# Outbox Dispatcher Celery Task
#
# 현재 run_analysis()도 Planning 직후
# Dispatcher를 직접 호출한다.
#
# 이 Task는 이후 Celery Beat / Recovery Scanner에서
# 주기적으로 호출할 수 있도록 미리 등록한다.
# ========================================

@shared_task(
    name="scans.tasks.dispatch_analysis_outboxes"
)
def dispatch_analysis_outboxes():

    return (
        dispatch_available_outboxes()
    )


# ========================================
# Analysis Recovery Celery Task
#
# PostgreSQL을 Source of Truth로 사용해:
#
# - 오래된 pending AnalysisRun
# - Lease가 만료된 running Attempt
# - publish 가능한 pending Outbox
#
# 를 한 번의 Recovery Cycle에서 복구한다.
#
# Task는 at-least-once 실행되어도 안전하도록
# Recovery Service 자체가 idempotent하게 설계되어 있다.
# ========================================

@shared_task(
    name="scans.tasks.run_analysis_recovery",
    acks_late=True,
    reject_on_worker_lost=True,
)
def run_analysis_recovery():

    return (
        run_recovery_cycle()
    )


# ========================================
# Snapshot 언어 목록
#
# ScannedSourceFile 목록에서
# 지원 언어 순서대로 고정한다.
# ========================================

def get_snapshot_languages(
    snapshot_files,
):

    detected = {
        item.language
        for item
        in snapshot_files
    }


    return [
        language
        for language
        in SUPPORTED_LANGUAGE_ORDER
        if language in detected
    ]


# ========================================
# AnalysisRun Pipeline 시작 실패 기록
#
# Snapshot / Planning 이전 장애는
# AnalysisRun 자체를 failed 처리한다.
#
# 이미 Chunk가 생성되고 Run이 running이라면
# Outbox가 PostgreSQL에 남아 있으므로
# Run을 강제로 failed로 덮어쓰지 않는다.
# ========================================

def record_analysis_start_failure(
    analysis_run_id,
    error,
):

    error_message = (
        truncate_log(
            str(
                error
            )
        )
    )


    try:

        with transaction.atomic():

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .get(
                    pk=
                        analysis_run_id
                )
            )


            has_chunks = (
                analysis_run
                .analysis_chunks
                .exists()
            )


            # --------------------------------
            # Planning 이전 / 중간 실패
            # --------------------------------

            if (
                analysis_run.status
                in (
                    AnalysisRun.Status.PENDING,
                    AnalysisRun.Status.PLANNING,
                )
                or
                not has_chunks
            ):

                analysis_run.status = (
                    AnalysisRun
                    .Status
                    .FAILED
                )

                analysis_run.completed_at = (
                    timezone.now()
                )

                analysis_run.failure_reason = (
                    error_message
                )


            # --------------------------------
            # 이미 Chunk / Outbox Pipeline이
            # 만들어졌다면 Run 상태는 유지.
            #
            # Recovery Dispatcher가 DB를 기준으로
            # 이어서 처리할 수 있어야 한다.
            # --------------------------------

            existing_logs = (
                analysis_run.logs
                or ""
            )


            if existing_logs:

                analysis_run.logs = (
                    truncate_log(
                        existing_logs
                        + "\n\n"
                        + error_message
                    )
                )

            else:

                analysis_run.logs = (
                    error_message
                )


            update_fields = [
                "logs",
                "updated_at",
            ]


            if (
                analysis_run.status
                ==
                AnalysisRun.Status.FAILED
            ):

                update_fields.extend([
                    "status",
                    "completed_at",
                    "failure_reason",
                ])


            analysis_run.save(
                update_fields=
                    update_fields
            )


    except AnalysisRun.DoesNotExist:

        pass


# ========================================
# AnalysisRun 비동기 시작 Task
#
# OLD:
#
# prepare source
# → detect language
# → Semgrep 전체 실행
# → Vulnerability 저장
# → Run completed
#
# NEW:
#
# PENDING
# → PLANNING claim
# → prepare_analysis_target()
# → Persistent Workspace Snapshot
# → Chunk Planner
# → AnalysisChunk / File / Outbox
# → Outbox Dispatcher
# → run_analysis_chunk(chunk_id)
#
# 실제 Semgrep은 이 Task에서 실행하지 않는다.
# ========================================

@shared_task(
    name="scans.tasks.run_analysis"
)
def run_analysis(
    analysis_run_id
):

    try:

        # =================================
        # Bootstrap Claim
        #
        # duplicate run_analysis 메시지가 와도
        # PENDING → PLANNING 전환에 성공한
        # 하나의 Worker만 Source 준비를 수행한다.
        # =================================

        with transaction.atomic():

            analysis_run = (
                AnalysisRun.objects
                .select_for_update()
                .select_related(
                    "project",
                    "source_version",
                    "executed_by",
                )
                .get(
                    pk=
                        analysis_run_id
                )
            )


            if (
                analysis_run.status
                !=
                AnalysisRun.Status.PENDING
            ):

                return {
                    "success":
                        False,

                    "claimed":
                        False,

                    "reason":
                        "analysis_run_not_pending",

                    "message":
                        "실행 가능한 pending 상태가 아닙니다.",

                    "analysis_run_id":
                        analysis_run.id,

                    "status":
                        analysis_run.status,
                }


            analysis_run.status = (
                AnalysisRun.Status.PLANNING
            )

            analysis_run.started_at = (
                timezone.now()
            )

            analysis_run.completed_at = None

            analysis_run.failure_reason = ""

            analysis_run.logs = ""

            analysis_run.raw_result = None

            analysis_run.analysis_languages = []

            analysis_run.analysis_language = ""


            analysis_run.save(
                update_fields=[
                    "status",
                    "started_at",
                    "completed_at",
                    "failure_reason",
                    "logs",
                    "raw_result",
                    "analysis_languages",
                    "analysis_language",
                    "updated_at",
                ]
            )


            source_version = (
                analysis_run
                .source_version
            )


        # =================================
        # Source 준비
        #
        # Upload:
        # 안전한 TemporaryDirectory 압축 해제
        #
        # Repository:
        # TemporaryDirectory clone
        #
        # Internal:
        # 허용된 Internal Root
        # =================================

        with prepare_analysis_target(
            source_version
        ) as target_path:

            # =============================
            # Persistent Workspace Snapshot
            #
            # TemporaryDirectory가 사라지기 전에
            # 정확한 분석 입력을 영속화한다.
            # =============================

            snapshot_files = (
                materialize_analysis_workspace(
                    analysis_run_id,
                    target_path,
                )
            )


        # =================================
        # 여기서는 Upload / Repository의
        # 원본 TemporaryDirectory가 이미 삭제되어도
        # Persistent Workspace가 남아 있다.
        # =================================

        detected_languages = (
            get_snapshot_languages(
                snapshot_files
            )
        )


        if not detected_languages:

            raise RuntimeError(
                "지원하는 분석 대상 언어를 "
                "찾을 수 없습니다. "
                "현재 자동 감지 대상은 "
                "Java, JavaScript, Python입니다."
            )


        # =================================
        # SourceVersion 감지 언어 Snapshot
        #
        # 기존 UI / API 호환을 위해
        # 기존 함수를 재사용한다.
        #
        # AnalysisRun의 언어 필드는 뒤의 Planner가
        # 최종 Chunk 기준으로 다시 확정한다.
        # =================================

        save_detected_languages(
            source_version,
            analysis_run_id,
            detected_languages,
        )


        # =================================
        # Chunk Planning
        #
        # Snapshot Metadata를 직접 전달한다.
        # 원본 Temporary Source를 다시 읽지 않는다.
        #
        # 같은 DB Transaction 안에서:
        #
        # AnalysisChunk
        # AnalysisChunkFile
        # AnalysisDispatchOutbox
        #
        # 생성.
        # =================================

        planning_result = (
            plan_analysis_chunks(
                analysis_run_id,
                scanned_files=
                    snapshot_files,
            )
        )


        # =================================
        # Planner가 모든 파일을 Oversized로
        # 판단한 경우 Run을 failed로 끝낼 수 있다.
        # =================================

        if (
            planning_result.get(
                "queued_chunk_count",
                0,
            )
            <= 0
        ):

            analysis_run = (
                AnalysisRun.objects
                .get(
                    pk=
                        analysis_run_id
                )
            )


            return {
                "success":
                    False,

                "claimed":
                    True,

                "reason":
                    "no_dispatchable_chunks",

                "analysis_run_id":
                    analysis_run.id,

                "status":
                    analysis_run.status,

                "analysis_languages":
                    list(
                        analysis_run
                        .analysis_languages
                    ),

                "planning":
                    planning_result,
            }


        # =================================
        # Outbox → Redis / Celery
        #
        # 네트워크 실패는 Dispatcher가 Outbox를
        # pending으로 유지하고 Backoff를 기록한다.
        #
        # 여기서는 즉시 publish 가능한 Outbox를
        # 여러 Batch로 처리한다.
        # =================================

        dispatch_result = (
            dispatch_available_outboxes()
        )


        analysis_run = (
            AnalysisRun.objects
            .get(
                pk=
                    analysis_run_id
            )
        )


        return {
            "success":
                True,

            "claimed":
                True,

            "analysis_run_id":
                analysis_run.id,

            "status":
                analysis_run.status,

            "analysis_languages":
                list(
                    analysis_run
                    .analysis_languages
                ),

            "planning":
                planning_result,

            "dispatch":
                dispatch_result,
        }


    except AnalysisRun.DoesNotExist:

        return {
            "success":
                False,

            "claimed":
                False,

            "reason":
                "analysis_run_not_found",

            "message":
                "AnalysisRun을 찾을 수 없습니다.",
        }


    except Exception as error:

        record_analysis_start_failure(
            analysis_run_id,
            error,
        )

        raise
