# backend/scans/services/archive_security.py

import stat
import zipfile

from pathlib import (
    Path,
    PurePosixPath,
    PureWindowsPath,
)

from ..constants import (
    IGNORED_LANGUAGE_DIRECTORIES,
    LANGUAGE_EXTENSIONS,
)

MAX_UPLOAD_ZIP_SIZE = (100 * 1024 * 1024)
MAX_ZIP_TOTAL_UNCOMPRESSED_SIZE = (200 * 1024 * 1024)
MAX_ZIP_MEMBER_UNCOMPRESSED_SIZE = (10 * 1024 * 1024)
MAX_ZIP_MEMBER_COUNT = 100000
MAX_ZIP_COMPRESSION_RATIO = 100
MAX_ZIP_MEMBER_NAME_LENGTH = 512
ZIP_EXTRACT_CHUNK_SIZE = (1024 * 1024)
ALLOWED_ZIP_COMPRESSION_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
NESTED_ARCHIVE_EXTENSIONS = {'.war', '.ear', '.apk'}


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
