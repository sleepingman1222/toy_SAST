# backend/scans/services/source_acquisition.py

import os
import subprocess
import tempfile
import zipfile

from contextlib import contextmanager
from pathlib import Path

from django.conf import settings
from projects.models import SourceVersion

from .archive_security import (
    MAX_UPLOAD_ZIP_SIZE,
    safely_extract_zip,
)
from .execution_utils import truncate_log

GIT_CLONE_TIMEOUT = 120


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
