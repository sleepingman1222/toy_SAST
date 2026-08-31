import json
import os
import stat
import subprocess
import tempfile
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

from .models import (
    AnalysisRun,
    KisaSecurityWeakness,
    Vulnerability,
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
# 자동 감지 지원 언어
#
# 현재 요구 대상:
# - Java
# - JavaScript
# - Python
#
# 실제 분석 가능 여부는
# semgrep_rules/kisa/<language>/
# Rule 디렉터리 존재 여부로 다시 확인한다.
# ========================================

SUPPORTED_LANGUAGE_ORDER = (
    "java",
    "javascript",
    "python",
)

LANGUAGE_EXTENSIONS = {
    ".java": "java",

    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",

    ".py": "python",
}

LANGUAGE_ALIASES = {
    "java": "java",

    "javascript": "javascript",
    "js": "javascript",

    "python": "python",
    "py": "python",
}

LANGUAGE_DISPLAY_NAMES = {
    "java": "Java",
    "javascript": "JavaScript",
    "python": "Python",
}

IGNORED_LANGUAGE_DIRECTORIES = {
    ".git",
    ".idea",
    ".vscode",

    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",

    ".venv",
    "venv",
    "env",

    "node_modules",

    "build",
    "dist",
    "target",

    "vendor",
}


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
# AnalysisRun 비동기 실행
# ========================================

@shared_task
def run_analysis(
    analysis_run_id
):

    try:

        # =================================
        # pending → running
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

                    "message":
                        "실행 가능한 pending 상태가 아닙니다.",

                    "analysis_run_id":
                        analysis_run.id,

                    "status":
                        analysis_run.status,
                }


            analysis_run.status = (
                AnalysisRun.Status.RUNNING
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


        # =================================
        # SourceVersion
        # =================================

        source_version = (
            analysis_run
            .source_version
        )


        # =================================
        # 실제 분석 대상 준비
        #
        # Upload / Repository / Internal
        # 모두 최종 target_path를 만든 뒤
        # 동일한 언어 감지 흐름을 사용한다.
        # =================================

        with prepare_analysis_target(
            source_version
        ) as target_path:

            # =============================
            # 언어 자동 감지
            # =============================

            detected_languages = (
                detect_languages(
                    target_path
                )
            )


            # =============================
            # 감지 결과 Snapshot 저장
            #
            # SourceVersion
            # → detected_languages
            #
            # AnalysisRun
            # → analysis_languages
            #
            # 기존 단일 language 필드도
            # 전환 기간 동안 자동 갱신
            # =============================

            save_detected_languages(
                source_version,
                analysis_run_id,
                detected_languages,
            )


            if not detected_languages:

                raise RuntimeError(
                    "지원하는 분석 대상 언어를 "
                    "찾을 수 없습니다. "
                    "현재 자동 감지 대상은 "
                    "Java, JavaScript, Python입니다."
                )


            # =============================
            # 언어별 KISA Semgrep 실행
            # =============================

            semgrep_result = (
                execute_semgrep_for_languages(
                    target_path,
                    detected_languages,
                )
            )


            raw_result = (
                semgrep_result[
                    "raw_result"
                ]
            )

            logs = (
                semgrep_result[
                    "logs"
                ]
            )


            # =============================
            # 결과 DB 저장
            # =============================

            with transaction.atomic():

                analysis_run = (
                    AnalysisRun.objects
                    .select_for_update()
                    .get(
                        pk=
                            analysis_run_id
                    )
                )


                analysis_run.raw_result = (
                    raw_result
                )

                analysis_run.logs = (
                    logs
                )


                vulnerability_count = (
                    save_vulnerabilities(
                        analysis_run,
                        raw_result,
                        target_path
                    )
                )


                analysis_run.status = (
                    AnalysisRun
                    .Status
                    .COMPLETED
                )

                analysis_run.completed_at = (
                    timezone.now()
                )

                analysis_run.failure_reason = ""


                analysis_run.save(
                    update_fields=[
                        "status",
                        "completed_at",
                        "failure_reason",
                        "logs",
                        "raw_result",
                        "updated_at",
                    ]
                )


        return {
            "success":
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

            "result_count":
                vulnerability_count,
        }


    except AnalysisRun.DoesNotExist:

        return {
            "success":
                False,

            "message":
                "AnalysisRun을 찾을 수 없습니다.",
        }


    except Exception as error:

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


                analysis_run.status = (
                    AnalysisRun
                    .Status
                    .FAILED
                )

                analysis_run.completed_at = (
                    timezone.now()
                )

                analysis_run.failure_reason = (
                    truncate_log(
                        str(
                            error
                        )
                    )
                )


                existing_logs = (
                    analysis_run.logs
                    or ""
                )


                if existing_logs:

                    analysis_run.logs = (
                        truncate_log(
                            existing_logs
                            + "\n\n"
                            + str(
                                error
                            )
                        )
                    )

                else:

                    analysis_run.logs = (
                        truncate_log(
                            str(
                                error
                            )
                        )
                    )


                analysis_run.save(
                    update_fields=[
                        "status",
                        "completed_at",
                        "failure_reason",
                        "logs",
                        "updated_at",
                    ]
                )


        except AnalysisRun.DoesNotExist:

            pass


        raise

