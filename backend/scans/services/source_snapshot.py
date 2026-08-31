import hashlib
import json
import os
import shutil
import tempfile

from pathlib import Path

from django.conf import settings
from django.utils import timezone

from scans.constants import (
    ANALYSIS_WORKSPACE_DIRECTORY,
    ANALYSIS_WORKSPACE_MANIFEST_NAME,
    ANALYSIS_WORKSPACE_SOURCE_DIRECTORY,
    IGNORED_LANGUAGE_DIRECTORIES,
    MAX_PLANNABLE_ANALYZABLE_BYTES,
    MAX_PLANNABLE_SOURCE_FILES,
    WORKSPACE_COPY_BUFFER_SIZE,
)

from scans.models import (
    AnalysisChunkFile,
)

from scans.services.chunk_planner import (
    ScannedSourceFile,
    classify_source_file,
    detect_file_language,
)


# ========================================
# Source Snapshot Error
# ========================================

class SourceSnapshotError(
    RuntimeError
):

    pass


# ========================================
# Workspace Base Root
#
# MEDIA_ROOT/
# └ analysis_workspaces/
# ========================================

def get_workspace_base_root():

    media_root_value = getattr(
        settings,
        "MEDIA_ROOT",
        "",
    )


    if not media_root_value:

        raise SourceSnapshotError(
            "MEDIA_ROOT가 설정되어 있지 않아 "
            "Analysis Workspace를 생성할 수 없습니다."
        )


    media_root = Path(
        media_root_value
    ).resolve()


    workspace_root = (
        media_root
        /
        ANALYSIS_WORKSPACE_DIRECTORY
    )


    try:

        workspace_root.mkdir(
            parents=True,
            exist_ok=True,
        )


        # --------------------------------
        # Workspace 자체를 일반 사용자에게
        # 공개하지 않도록 권한 제한
        # --------------------------------

        workspace_root.chmod(
            0o700
        )


    except OSError as error:

        raise SourceSnapshotError(
            "Analysis Workspace Root를 "
            "생성할 수 없습니다. "
            f"error={error}"
        )


    return (
        workspace_root.resolve()
    )


# ========================================
# AnalysisRun Workspace Root
#
# analysis_workspaces/
# └ run_<AnalysisRun.id>/
# ========================================

def get_analysis_workspace_run_root(
    analysis_run_id,
):

    workspace_base_root = (
        get_workspace_base_root()
    )


    run_root = (
        workspace_base_root
        /
        f"run_{int(analysis_run_id)}"
    )


    # ------------------------------------
    # AnalysisRun ID를 int로 변환하므로
    # path traversal 입력은 들어올 수 없지만
    # 추가 containment 검증
    # ------------------------------------

    if (
        run_root.parent.resolve()
        !=
        workspace_base_root
    ):

        raise SourceSnapshotError(
            "잘못된 Analysis Workspace 경로입니다."
        )


    return run_root


# ========================================
# Source Root
# ========================================

def get_analysis_workspace_source_root(
    analysis_run_id,
):

    return (
        get_analysis_workspace_run_root(
            analysis_run_id
        )
        /
        ANALYSIS_WORKSPACE_SOURCE_DIRECTORY
    )


# ========================================
# Manifest Path
# ========================================

def get_analysis_workspace_manifest_path(
    analysis_run_id,
):

    return (
        get_analysis_workspace_run_root(
            analysis_run_id
        )
        /
        ANALYSIS_WORKSPACE_MANIFEST_NAME
    )


# ========================================
# Manifest Relative Path 검증
# ========================================

def validate_manifest_relative_path(
    relative_path,
):

    path = Path(
        relative_path
    )


    if path.is_absolute():

        raise SourceSnapshotError(
            "Workspace Manifest에 "
            "절대 경로가 포함되어 있습니다."
        )


    if (
        ".."
        in
        path.parts
    ):

        raise SourceSnapshotError(
            "Workspace Manifest에 "
            "상위 경로 이동이 포함되어 있습니다."
        )


    normalized = (
        path.as_posix()
    )


    if not normalized:

        raise SourceSnapshotError(
            "Workspace Manifest의 "
            "파일 경로가 비어 있습니다."
        )


    return normalized


# ========================================
# Stable Copy + SHA256
#
# 파일을 Workspace로 복사하면서
# SHA256을 동시에 계산한다.
#
# 복사 전/후 Source:
#
# - size
# - mtime_ns
#
# 비교
#
# 복사 도중 파일이 바뀌면 실패.
# ========================================

def copy_file_with_stable_hash(
    source_path,
    destination_path,
):

    source_path = Path(
        source_path
    )

    destination_path = Path(
        destination_path
    )


    if source_path.is_symlink():

        raise SourceSnapshotError(
            "Symbolic Link Source는 "
            "Snapshot에 포함할 수 없습니다. "
            f"file={source_path}"
        )


    try:

        before_stat = (
            source_path.stat()
        )

    except OSError as error:

        raise SourceSnapshotError(
            "Snapshot Source File 정보를 "
            "읽을 수 없습니다. "
            f"file={source_path}, "
            f"error={error}"
        )


    try:

        destination_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    except OSError as error:

        raise SourceSnapshotError(
            "Workspace Directory를 "
            "생성할 수 없습니다. "
            f"error={error}"
        )


    sha256 = hashlib.sha256()

    written_size = 0


    try:

        with (
            source_path.open(
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
                        WORKSPACE_COPY_BUFFER_SIZE
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


                written_size += (
                    len(
                        data
                    )
                )


        destination_path.chmod(
            0o600
        )


    except OSError as error:

        raise SourceSnapshotError(
            "Source File을 Workspace에 "
            "복사할 수 없습니다. "
            f"file={source_path}, "
            f"error={error}"
        )


    # ------------------------------------
    # 읽은 실제 크기 검증
    # ------------------------------------

    if (
        written_size
        !=
        before_stat.st_size
    ):

        raise SourceSnapshotError(
            "Snapshot 복사 중 파일 크기가 "
            "변경되었습니다. "
            f"file={source_path}"
        )


    try:

        after_stat = (
            source_path.stat()
        )

    except OSError as error:

        raise SourceSnapshotError(
            "Snapshot 이후 Source File 정보를 "
            "확인할 수 없습니다. "
            f"file={source_path}, "
            f"error={error}"
        )


    # ------------------------------------
    # Source 변경 감지
    # ------------------------------------

    if (
        before_stat.st_size
        !=
        after_stat.st_size

        or

        before_stat.st_mtime_ns
        !=
        after_stat.st_mtime_ns
    ):

        raise SourceSnapshotError(
            "Snapshot 생성 도중 Source File이 "
            "변경되었습니다. "
            f"file={source_path}"
        )


    return (
        sha256.hexdigest(),
        written_size,
    )


# ========================================
# Source Tree 순회
#
# 지원 언어 파일만 반환한다.
# ========================================

def iterate_supported_source_files(
    target_path,
):

    raw_target = Path(
        target_path
    )


    if raw_target.is_symlink():

        raise SourceSnapshotError(
            "Symbolic Link 형태의 분석 대상은 "
            "허용되지 않습니다."
        )


    try:

        analysis_root = (
            raw_target.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ) as error:

        raise SourceSnapshotError(
            "분석 대상 경로를 확인할 수 없습니다. "
            f"error={error}"
        )


    # ====================================
    # Single File
    # ====================================

    if analysis_root.is_file():

        language = (
            detect_file_language(
                analysis_root
            )
        )


        if language:

            yield (
                analysis_root,
                analysis_root.name,
                language,
            )


        return


    # ====================================
    # Directory
    # ====================================

    if not analysis_root.is_dir():

        raise SourceSnapshotError(
            "분석 대상이 올바른 파일 또는 "
            "디렉터리가 아닙니다."
        )


    for (
        current_root,
        directory_names,
        file_names,
    ) in os.walk(
        analysis_root,
        followlinks=False,
    ):

        current_root_path = Path(
            current_root
        )


        # --------------------------------
        # Directory 순서 고정
        #
        # Symbolic Link / ignored 제외
        # --------------------------------

        directory_names[:] = sorted(
            [
                directory_name

                for directory_name
                in directory_names

                if (
                    directory_name.lower()
                    not in
                    IGNORED_LANGUAGE_DIRECTORIES

                    and

                    not (
                        current_root_path
                        /
                        directory_name
                    ).is_symlink()
                )
            ]
        )


        # --------------------------------
        # File 순서 고정
        # --------------------------------

        for file_name in sorted(
            file_names
        ):

            source_path = (
                current_root_path
                /
                file_name
            )


            if source_path.is_symlink():

                continue


            if not source_path.is_file():

                continue


            language = (
                detect_file_language(
                    source_path
                )
            )


            if not language:

                continue


            try:

                relative_path = (
                    source_path
                    .relative_to(
                        analysis_root
                    )
                    .as_posix()
                )

            except ValueError:

                raise SourceSnapshotError(
                    "분석 대상 파일이 Source Root를 "
                    "벗어났습니다. "
                    f"file={source_path}"
                )


            yield (
                source_path,
                relative_path,
                language,
            )


# ========================================
# Manifest 저장
# ========================================

def write_workspace_manifest(
    manifest_path,
    analysis_run_id,
    scanned_files,
):

    manifest_path = Path(
        manifest_path
    )


    manifest = {

        "schema_version":
            1,

        "analysis_run_id":
            int(
                analysis_run_id
            ),

        "created_at":
            timezone.now()
            .isoformat(),

        "files": [

            {
                "relative_path":
                    item.relative_path,

                "language":
                    item.language,

                "size_bytes":
                    item.size_bytes,

                "file_class":
                    item.file_class,

                "content_sha256":
                    item.content_sha256,
            }

            for item
            in scanned_files
        ],
    }


    try:

        with manifest_path.open(
            mode="x",
            encoding="utf-8",
        ) as manifest_file:

            json.dump(
                manifest,
                manifest_file,
                ensure_ascii=False,
                indent=2,
            )


        manifest_path.chmod(
            0o600
        )


    except OSError as error:

        raise SourceSnapshotError(
            "Workspace Manifest를 "
            "저장할 수 없습니다. "
            f"error={error}"
        )


# ========================================
# Workspace Snapshot Load
#
# Worker가 이후 실행될 때
# Manifest 기준으로 동일 파일 집합을
# 다시 구성한다.
# ========================================

def load_analysis_workspace_snapshot(
    analysis_run_id,
):

    run_root = (
        get_analysis_workspace_run_root(
            analysis_run_id
        )
    )


    source_root = (
        run_root
        /
        ANALYSIS_WORKSPACE_SOURCE_DIRECTORY
    )


    manifest_path = (
        run_root
        /
        ANALYSIS_WORKSPACE_MANIFEST_NAME
    )


    if (
        not run_root.is_dir()

        or

        not source_root.is_dir()

        or

        not manifest_path.is_file()
    ):

        raise SourceSnapshotError(
            "완료된 Analysis Workspace "
            "Snapshot을 찾을 수 없습니다."
        )


    try:

        with manifest_path.open(
            mode="r",
            encoding="utf-8",
        ) as manifest_file:

            manifest = (
                json.load(
                    manifest_file
                )
            )


    except (
        OSError,
        ValueError,
        TypeError,
    ) as error:

        raise SourceSnapshotError(
            "Workspace Manifest를 "
            "읽을 수 없습니다. "
            f"error={error}"
        )


    if (
        manifest.get(
            "schema_version"
        )
        !=
        1
    ):

        raise SourceSnapshotError(
            "지원하지 않는 Workspace "
            "Manifest 버전입니다."
        )


    if (
        manifest.get(
            "analysis_run_id"
        )
        !=
        int(
            analysis_run_id
        )
    ):

        raise SourceSnapshotError(
            "Workspace Manifest의 "
            "AnalysisRun ID가 일치하지 않습니다."
        )


    raw_files = (
        manifest.get(
            "files"
        )
    )


    if not isinstance(
        raw_files,
        list,
    ):

        raise SourceSnapshotError(
            "Workspace Manifest의 "
            "파일 목록이 올바르지 않습니다."
        )


    scanned_files = []


    for item in raw_files:

        if not isinstance(
            item,
            dict,
        ):

            raise SourceSnapshotError(
                "Workspace Manifest File 정보가 "
                "올바르지 않습니다."
            )


        relative_path = (
            validate_manifest_relative_path(
                item.get(
                    "relative_path",
                    "",
                )
            )
        )


        file_class = (
            item.get(
                "file_class"
            )
        )


        absolute_path = (
            source_root
            /
            Path(
                relative_path
            )
        )


        # --------------------------------
        # Oversized 파일은 실제 내용을
        # Workspace에 저장하지 않는다.
        # --------------------------------

        if (
            file_class
            !=
            AnalysisChunkFile
            .FileClass
            .OVERSIZED
        ):

            if not absolute_path.is_file():

                raise SourceSnapshotError(
                    "Workspace Source File이 "
                    "존재하지 않습니다. "
                    f"file={relative_path}"
                )


        scanned_files.append(
            ScannedSourceFile(

                absolute_path=
                    absolute_path,

                relative_path=
                    relative_path,

                language=
                    str(
                        item.get(
                            "language",
                            "",
                        )
                    ),

                size_bytes=
                    int(
                        item.get(
                            "size_bytes",
                            0,
                        )
                    ),

                file_class=
                    file_class,

                content_sha256=
                    str(
                        item.get(
                            "content_sha256",
                            "",
                        )
                    ),
            )
        )


    if not scanned_files:

        raise SourceSnapshotError(
            "Workspace Manifest에 "
            "분석 Source가 없습니다."
        )


    return scanned_files


# ========================================
# Workspace Snapshot 생성
#
# Normal / Large
# → Persistent Workspace로 실제 복사
#
# Oversized
# → Manifest Metadata만 저장
#
#
# 중요한 점:
#
# 최종 run_<id> Directory는
# Snapshot이 전부 완성된 마지막 순간에만
# 보이도록 staging directory를 사용한다.
# ========================================

def materialize_analysis_workspace(
    analysis_run_id,
    target_path,
):

    final_run_root = (
        get_analysis_workspace_run_root(
            analysis_run_id
        )
    )


    final_manifest_path = (
        final_run_root
        /
        ANALYSIS_WORKSPACE_MANIFEST_NAME
    )


    # ====================================
    # 이미 완성된 Snapshot
    #
    # Redis / Celery Recovery 이후에도
    # 원본 Source를 다시 준비하지 않고
    # 기존 Snapshot을 재사용한다.
    # ====================================

    if final_manifest_path.is_file():

        return (
            load_analysis_workspace_snapshot(
                analysis_run_id
            )
        )


    # ------------------------------------
    # Directory는 있는데 Manifest가 없음
    #
    # 불완전 Workspace로 간주
    # ------------------------------------

    if final_run_root.exists():

        raise SourceSnapshotError(
            "완료되지 않은 Analysis Workspace가 "
            "이미 존재합니다. "
            "Recovery/Cleanup이 필요합니다."
        )


    workspace_base_root = (
        get_workspace_base_root()
    )


    # ====================================
    # Staging Workspace
    #
    # .run_25_xxxxxx/
    # ====================================

    staging_directory = (
        tempfile.mkdtemp(

            prefix=(
                f".run_"
                f"{int(analysis_run_id)}_"
            ),

            dir=
                workspace_base_root,
        )
    )


    staging_run_root = Path(
        staging_directory
    )


    staging_source_root = (
        staging_run_root
        /
        ANALYSIS_WORKSPACE_SOURCE_DIRECTORY
    )


    try:

        staging_run_root.chmod(
            0o700
        )


        staging_source_root.mkdir(
            parents=True,
            exist_ok=False,
        )


        staging_source_root.chmod(
            0o700
        )


        scanned_files = []

        analyzable_total_bytes = 0


        for (
            source_path,
            relative_path,
            language,
        ) in iterate_supported_source_files(
            target_path
        ):

            # --------------------------------
            # File Count 제한
            # --------------------------------

            if (
                len(
                    scanned_files
                )
                >=
                MAX_PLANNABLE_SOURCE_FILES
            ):

                raise SourceSnapshotError(
                    "분석 가능한 Source File 수가 "
                    "허용 한도를 초과했습니다."
                )


            try:

                source_stat = (
                    source_path.stat()
                )

            except OSError as error:

                raise SourceSnapshotError(
                    "Source File 크기를 "
                    "확인할 수 없습니다. "
                    f"file={source_path}, "
                    f"error={error}"
                )


            size_bytes = (
                source_stat.st_size
            )


            if size_bytes < 0:

                raise SourceSnapshotError(
                    "Source File 크기 정보가 "
                    "올바르지 않습니다."
                )


            file_class = (
                classify_source_file(
                    size_bytes
                )
            )


            # =================================
            # Oversized
            #
            # 실제 내용은 복사하지 않는다.
            #
            # Manifest에는 남겨
            # skipped Chunk를 생성할 수 있게 한다.
            # =================================

            if (
                file_class
                ==
                AnalysisChunkFile
                .FileClass
                .OVERSIZED
            ):

                scanned_files.append(
                    ScannedSourceFile(

                        absolute_path=(
                            staging_source_root
                            /
                            relative_path
                        ),

                        relative_path=
                            relative_path,

                        language=
                            language,

                        size_bytes=
                            size_bytes,

                        file_class=
                            file_class,

                        content_sha256=
                            "",
                    )
                )


                continue


            # =================================
            # Normal / Large 총 크기 제한
            # =================================

            analyzable_total_bytes += (
                size_bytes
            )


            if (
                analyzable_total_bytes
                >
                MAX_PLANNABLE_ANALYZABLE_BYTES
            ):

                raise SourceSnapshotError(
                    "분석 가능한 Source File 전체 크기가 "
                    "허용 한도를 초과했습니다."
                )


            destination_path = (
                staging_source_root
                /
                Path(
                    relative_path
                )
            )


            # --------------------------------
            # Workspace containment 검증
            # --------------------------------

            try:

                (
                    destination_path
                    .resolve()
                    .relative_to(
                        staging_source_root
                        .resolve()
                    )
                )

            except ValueError:

                raise SourceSnapshotError(
                    "Workspace 경로가 허용된 "
                    "Source Root를 벗어났습니다."
                )


            (
                content_sha256,
                copied_size,
            ) = (
                copy_file_with_stable_hash(
                    source_path,
                    destination_path,
                )
            )


            if (
                copied_size
                !=
                size_bytes
            ):

                raise SourceSnapshotError(
                    "Snapshot Source 크기가 "
                    "원본과 일치하지 않습니다."
                )


            scanned_files.append(
                ScannedSourceFile(

                    absolute_path=
                        destination_path,

                    relative_path=
                        relative_path,

                    language=
                        language,

                    size_bytes=
                        size_bytes,

                    file_class=
                        file_class,

                    content_sha256=
                        content_sha256,
                )
            )


        if not scanned_files:

            raise SourceSnapshotError(
                "지원하는 Source File을 "
                "찾을 수 없습니다."
            )


        # ====================================
        # Manifest 저장
        # ====================================

        write_workspace_manifest(

            staging_run_root
            /
            ANALYSIS_WORKSPACE_MANIFEST_NAME,

            analysis_run_id,

            scanned_files,
        )


        # ====================================
        # Atomic Publish
        #
        # 완성된 staging directory만
        # run_<id> 이름으로 변경한다.
        # ====================================

        try:

            os.replace(
                staging_run_root,
                final_run_root,
            )


        except OSError as error:

            # --------------------------------
            # 다른 동일 작업이 먼저
            # Snapshot을 완성한 경우
            # --------------------------------

            if final_manifest_path.is_file():

                return (
                    load_analysis_workspace_snapshot(
                        analysis_run_id
                    )
                )


            raise SourceSnapshotError(
                "Analysis Workspace를 "
                "최종 경로로 전환하지 못했습니다. "
                f"error={error}"
            )


        # ====================================
        # 최종 Snapshot을 Manifest에서
        # 다시 읽어서 반환
        # ====================================

        return (
            load_analysis_workspace_snapshot(
                analysis_run_id
            )
        )


    finally:

        # ------------------------------------
        # 실패한 Staging Directory만 제거
        #
        # 성공한 경우 os.replace 때문에
        # staging path는 이미 존재하지 않는다.
        # ------------------------------------

        if staging_run_root.exists():

            shutil.rmtree(
                staging_run_root,
                ignore_errors=True,
            )


# ========================================
# Workspace Cleanup
#
# 이후:
#
# completed / failed AnalysisRun의
# Workspace TTL Cleanup 등에 사용 가능
#
# 현재는 테스트에서도 사용한다.
# ========================================

def remove_analysis_workspace(
    analysis_run_id,
):

    run_root = (
        get_analysis_workspace_run_root(
            analysis_run_id
        )
    )


    if not run_root.exists():

        return False


    workspace_base_root = (
        get_workspace_base_root()
    )


    try:

        resolved_run_root = (
            run_root.resolve()
        )


        resolved_run_root.relative_to(
            workspace_base_root
        )


    except ValueError:

        raise SourceSnapshotError(
            "Workspace 삭제 경로가 "
            "허용 범위를 벗어났습니다."
        )


    try:

        shutil.rmtree(
            resolved_run_root
        )


    except OSError as error:

        raise SourceSnapshotError(
            "Analysis Workspace를 "
            "삭제할 수 없습니다. "
            f"error={error}"
        )


    return True