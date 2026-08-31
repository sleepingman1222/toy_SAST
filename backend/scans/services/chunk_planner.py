import hashlib
import os

from dataclasses import dataclass
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from scans.constants import (
    FILE_HASH_BUFFER_SIZE,
    IGNORED_LANGUAGE_DIRECTORIES,
    LANGUAGE_EXTENSIONS,
    LARGE_FILE_BYTES,
    MAX_ANALYZABLE_FILE_BYTES,
    MAX_CHUNK_BYTES,
    MAX_CHUNK_RETRIES,
    MAX_FILES_PER_CHUNK,
    MAX_PLANNABLE_ANALYZABLE_BYTES,
    MAX_PLANNABLE_SOURCE_FILES,
    SUPPORTED_LANGUAGE_ORDER,
)

from scans.models import (
    AnalysisChunk,
    AnalysisChunkFile,
    AnalysisDispatchOutbox,
    AnalysisRun,
)


# ========================================
# Planner Exception
# ========================================

class ChunkPlanningError(
    RuntimeError
):

    pass


# ========================================
# Scanned Source File
#
# DB에 저장하기 전 Planner 내부에서
# 사용하는 Immutable 구조
#
# Source Snapshot에서도 동일한 구조를
# 사용한다.
# ========================================

@dataclass(
    frozen=True
)
class ScannedSourceFile:

    absolute_path: Path

    relative_path: str

    language: str

    size_bytes: int

    file_class: str

    content_sha256: str


# ========================================
# Chunk Specification
#
# DB 저장 전 Chunk 설계 결과
# ========================================

@dataclass(
    frozen=True
)
class ChunkSpec:

    language: str

    files: tuple

    total_bytes: int

    status: str

    status_reason: str


# ========================================
# File Language
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
# File Class
#
# normal
# large
# oversized
# ========================================

def classify_source_file(
    size_bytes
):

    if (
        size_bytes
        >
        MAX_ANALYZABLE_FILE_BYTES
    ):

        return (
            AnalysisChunkFile
            .FileClass
            .OVERSIZED
        )


    if (
        size_bytes
        >=
        LARGE_FILE_BYTES
    ):

        return (
            AnalysisChunkFile
            .FileClass
            .LARGE
        )


    return (
        AnalysisChunkFile
        .FileClass
        .NORMAL
    )


# ========================================
# Stable SHA256
#
# Hash 계산 전후:
#
# - size
# - mtime_ns
#
# 가 동일한지 확인한다.
#
# Hash를 계산하는 사이 파일이 바뀌면
# 분석 Snapshot이 불안정하므로 실패.
# ========================================

def calculate_stable_sha256(
    file_path
):

    file_path = Path(
        file_path
    )


    try:

        before_stat = (
            file_path.stat()
        )

    except OSError as error:

        raise ChunkPlanningError(
            "소스 파일 정보를 읽을 수 없습니다. "
            f"file={file_path}, "
            f"error={error}"
        )


    sha256 = hashlib.sha256()


    try:

        with file_path.open(
            mode="rb"
        ) as source_file:

            while True:

                data = (
                    source_file.read(
                        FILE_HASH_BUFFER_SIZE
                    )
                )


                if not data:

                    break


                sha256.update(
                    data
                )

    except OSError as error:

        raise ChunkPlanningError(
            "소스 파일 Hash를 계산할 수 없습니다. "
            f"file={file_path}, "
            f"error={error}"
        )


    try:

        after_stat = (
            file_path.stat()
        )

    except OSError as error:

        raise ChunkPlanningError(
            "Hash 계산 후 소스 파일 정보를 "
            "확인할 수 없습니다. "
            f"file={file_path}, "
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

        raise ChunkPlanningError(
            "Chunk Planning 도중 소스 파일이 "
            "변경되었습니다. "
            f"file={file_path}"
        )


    return (
        sha256.hexdigest()
    )


# ========================================
# Source File 생성
#
# 기존 target_path 직접 분석 방식에서 사용
# ========================================

def build_scanned_source_file(
    file_path,
    analysis_root,
):

    file_path = Path(
        file_path
    )

    analysis_root = Path(
        analysis_root
    )


    # ------------------------------------
    # Symbolic Link 제외
    # ------------------------------------

    if file_path.is_symlink():

        return None


    # ------------------------------------
    # Regular File만 허용
    # ------------------------------------

    if not file_path.is_file():

        return None


    # ------------------------------------
    # 지원 언어 확인
    # ------------------------------------

    language = (
        detect_file_language(
            file_path
        )
    )


    if not language:

        return None


    # ------------------------------------
    # File Size
    # ------------------------------------

    try:

        file_stat = (
            file_path.stat()
        )

    except OSError as error:

        raise ChunkPlanningError(
            "소스 파일 크기를 확인할 수 없습니다. "
            f"file={file_path}, "
            f"error={error}"
        )


    size_bytes = (
        file_stat.st_size
    )


    if size_bytes < 0:

        raise ChunkPlanningError(
            "소스 파일 크기 정보가 올바르지 않습니다. "
            f"file={file_path}"
        )


    # ------------------------------------
    # Relative Path
    # ------------------------------------

    if analysis_root.is_file():

        relative_path = (
            file_path.name
        )

    else:

        try:

            relative_path = (
                file_path
                .relative_to(
                    analysis_root
                )
                .as_posix()
            )

        except ValueError:

            raise ChunkPlanningError(
                "분석 대상 파일이 Analysis Root를 "
                "벗어났습니다. "
                f"file={file_path}"
            )


    # ------------------------------------
    # File Class
    # ------------------------------------

    file_class = (
        classify_source_file(
            size_bytes
        )
    )


    # ------------------------------------
    # Oversized는 실제 분석하지 않는다.
    #
    # 따라서 큰 파일 전체를 읽어
    # Hash 계산하지 않는다.
    # ------------------------------------

    if (
        file_class
        ==
        AnalysisChunkFile
        .FileClass
        .OVERSIZED
    ):

        content_sha256 = ""

    else:

        content_sha256 = (
            calculate_stable_sha256(
                file_path
            )
        )


    return (
        ScannedSourceFile(

            absolute_path=
                file_path,

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


# ========================================
# Source Tree Scan
#
# 기존 직접 Path 방식에서 사용
#
# 반환:
#
# [
#   ScannedSourceFile(...),
#   ...
# ]
# ========================================

def scan_source_files(
    target_path
):

    raw_target_path = Path(
        target_path
    )


    # ------------------------------------
    # 최상위 Symbolic Link 차단
    # ------------------------------------

    if raw_target_path.is_symlink():

        raise ChunkPlanningError(
            "Symbolic Link 형태의 분석 대상은 "
            "허용되지 않습니다."
        )


    try:

        analysis_root = (
            raw_target_path.resolve(
                strict=True
            )
        )

    except (
        OSError,
        RuntimeError,
    ) as error:

        raise ChunkPlanningError(
            "분석 대상 경로를 확인할 수 없습니다. "
            f"error={error}"
        )


    scanned_files = []

    analyzable_total_bytes = 0


    # ====================================
    # Single File
    # ====================================

    if analysis_root.is_file():

        scanned_file = (
            build_scanned_source_file(
                analysis_root,
                analysis_root,
            )
        )


        if scanned_file:

            scanned_files.append(
                scanned_file
            )


    # ====================================
    # Directory
    # ====================================

    elif analysis_root.is_dir():

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
            # 재현 가능한 Chunk 결과
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
            # File 순서도 고정
            # --------------------------------

            for file_name in sorted(
                file_names
            ):

                file_path = (
                    current_root_path
                    /
                    file_name
                )


                scanned_file = (
                    build_scanned_source_file(
                        file_path,
                        analysis_root,
                    )
                )


                if scanned_file is None:

                    continue


                scanned_files.append(
                    scanned_file
                )


                # --------------------------------
                # Source File 개수 제한
                # --------------------------------

                if (
                    len(
                        scanned_files
                    )
                    >
                    MAX_PLANNABLE_SOURCE_FILES
                ):

                    raise ChunkPlanningError(
                        "분석 가능한 소스 파일 수가 "
                        "허용 한도를 초과했습니다. "
                        f"limit="
                        f"{MAX_PLANNABLE_SOURCE_FILES}"
                    )


                # --------------------------------
                # Oversized는 분석 대상 총량에서 제외
                # --------------------------------

                if (
                    scanned_file.file_class
                    !=
                    AnalysisChunkFile
                    .FileClass
                    .OVERSIZED
                ):

                    analyzable_total_bytes += (
                        scanned_file
                        .size_bytes
                    )


                    if (
                        analyzable_total_bytes
                        >
                        MAX_PLANNABLE_ANALYZABLE_BYTES
                    ):

                        raise ChunkPlanningError(
                            "분석 가능한 소스 파일의 "
                            "전체 크기가 허용 한도를 "
                            "초과했습니다."
                        )


    else:

        raise ChunkPlanningError(
            "분석 대상은 파일 또는 "
            "디렉터리여야 합니다."
        )


    if not scanned_files:

        raise ChunkPlanningError(
            "지원하는 분석 대상 소스 파일을 "
            "찾을 수 없습니다."
        )


    # ------------------------------------
    # 최종 안정 정렬
    #
    # language
    # +
    # relative_path
    # ------------------------------------

    language_order = {

        language:
            index

        for (
            index,
            language,
        )
        in enumerate(
            SUPPORTED_LANGUAGE_ORDER
        )
    }


    scanned_files.sort(
        key=lambda item: (

            language_order.get(
                item.language,
                999,
            ),

            item.relative_path,
        )
    )


    return scanned_files


# ========================================
# Normal Chunk Flush
# ========================================

def flush_normal_chunk(
    chunk_specs,
    language,
    normal_files,
):

    if not normal_files:

        return


    total_bytes = sum(

        item.size_bytes

        for item
        in normal_files
    )


    chunk_specs.append(
        ChunkSpec(

            language=
                language,

            files=
                tuple(
                    normal_files
                ),

            total_bytes=
                total_bytes,

            status=
                AnalysisChunk
                .Status
                .QUEUED,

            status_reason=
                "",
        )
    )


# ========================================
# Chunk Specification 생성
# ========================================

def build_chunk_specs(
    scanned_files
):

    chunk_specs = []


    for language in (
        SUPPORTED_LANGUAGE_ORDER
    ):

        language_files = [

            item

            for item
            in scanned_files

            if (
                item.language
                ==
                language
            )
        ]


        if not language_files:

            continue


        normal_files = []

        normal_total_bytes = 0


        for source_file in (
            language_files
        ):

            # =================================
            # Oversized
            #
            # 단독 skipped Chunk
            # =================================

            if (
                source_file.file_class
                ==
                AnalysisChunkFile
                .FileClass
                .OVERSIZED
            ):

                flush_normal_chunk(
                    chunk_specs,
                    language,
                    normal_files,
                )


                normal_files = []

                normal_total_bytes = 0


                chunk_specs.append(
                    ChunkSpec(

                        language=
                            language,

                        files=(
                            source_file,
                        ),

                        total_bytes=
                            source_file
                            .size_bytes,

                        status=
                            AnalysisChunk
                            .Status
                            .SKIPPED,

                        status_reason=
                            "FILE_TOO_LARGE",
                    )
                )


                continue


            # =================================
            # Large File
            #
            # 단독 실행 Chunk
            # =================================

            if (
                source_file.file_class
                ==
                AnalysisChunkFile
                .FileClass
                .LARGE
            ):

                flush_normal_chunk(
                    chunk_specs,
                    language,
                    normal_files,
                )


                normal_files = []

                normal_total_bytes = 0


                chunk_specs.append(
                    ChunkSpec(

                        language=
                            language,

                        files=(
                            source_file,
                        ),

                        total_bytes=
                            source_file
                            .size_bytes,

                        status=
                            AnalysisChunk
                            .Status
                            .QUEUED,

                        status_reason=
                            "",
                    )
                )


                continue


            # =================================
            # Normal File
            # =================================

            would_exceed_file_count = (

                len(
                    normal_files
                )
                >=
                MAX_FILES_PER_CHUNK
            )


            would_exceed_total_bytes = (

                bool(
                    normal_files
                )

                and

                (
                    normal_total_bytes
                    +
                    source_file.size_bytes
                )
                >
                MAX_CHUNK_BYTES
            )


            if (
                would_exceed_file_count

                or

                would_exceed_total_bytes
            ):

                flush_normal_chunk(
                    chunk_specs,
                    language,
                    normal_files,
                )


                normal_files = []

                normal_total_bytes = 0


            normal_files.append(
                source_file
            )


            normal_total_bytes += (
                source_file
                .size_bytes
            )


        # --------------------------------
        # 해당 언어의 마지막 Normal Chunk
        # --------------------------------

        flush_normal_chunk(
            chunk_specs,
            language,
            normal_files,
        )


    if not chunk_specs:

        raise ChunkPlanningError(
            "생성 가능한 AnalysisChunk가 없습니다."
        )


    return chunk_specs


# ========================================
# Planning 실패 처리
# ========================================

def mark_planning_failed(
    analysis_run_id,
    error,
):

    error_message = str(
        error
    )


    if (
        len(
            error_message
        )
        >
        4000
    ):

        error_message = (
            error_message[:4000]
        )


    with transaction.atomic():

        analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .filter(
                pk=
                    analysis_run_id
            )
            .first()
        )


        if analysis_run is None:

            return


        if (
            analysis_run.status
            !=
            AnalysisRun
            .Status
            .PLANNING
        ):

            return


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


        analysis_run.save(
            update_fields=[
                "status",
                "completed_at",
                "failure_reason",
                "updated_at",
            ]
        )


# ========================================
# Analysis Chunk Planning
#
# 두 가지 입력 지원:
#
# 1.
# target_path
#
# 기존 테스트 / 직접 Path 방식
#
# 2.
# scanned_files
#
# Persistent Workspace Snapshot 방식
#
#
# 중요한 정책:
#
# Filesystem Scan은 긴 작업이므로
# DB Transaction 밖에서 수행
#
# Chunk / File / Outbox 생성은
# 하나의 DB Transaction
# ========================================

def plan_analysis_chunks(
    analysis_run_id,
    target_path=None,
    scanned_files=None,
):

    # ====================================
    # PHASE 1
    #
    # Planning 실행권 확보
    # ====================================

    with transaction.atomic():

        analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .get(
                pk=
                    analysis_run_id
            )
        )


        if (
            analysis_run.status
            not in (
                AnalysisRun
                .Status
                .PENDING,

                AnalysisRun
                .Status
                .PLANNING,
            )
        ):

            raise ChunkPlanningError(
                "Chunk Planning 가능한 "
                "AnalysisRun 상태가 아닙니다. "
                f"status="
                f"{analysis_run.status}"
            )


        # --------------------------------
        # 이미 Attempt가 존재하면
        # 다시 Planning 금지
        # --------------------------------

        has_attempts = (
            AnalysisChunk.objects
            .filter(
                analysis_run=
                    analysis_run,

                attempts__isnull=False,
            )
            .exists()
        )


        # --------------------------------
        # 이미 Outbox가 존재하면
        # Dispatch가 시작됐다고 판단
        # --------------------------------

        has_outboxes = (
            AnalysisChunk.objects
            .filter(
                analysis_run=
                    analysis_run,

                dispatch_outboxes__isnull=False,
            )
            .exists()
        )


        if (
            has_attempts
            or
            has_outboxes
        ):

            raise ChunkPlanningError(
                "이미 실행 또는 Dispatch가 시작된 "
                "AnalysisRun은 다시 Planning할 수 없습니다."
            )


        analysis_run.status = (
            AnalysisRun
            .Status
            .PLANNING
        )


        analysis_run.completed_at = None

        analysis_run.failure_reason = ""


        analysis_run.save(
            update_fields=[
                "status",
                "completed_at",
                "failure_reason",
                "updated_at",
            ]
        )


    # ====================================
    # PHASE 2
    #
    # Chunk Specification 생성
    #
    # DB Transaction 없음
    # ====================================

    try:

        # =================================
        # Persistent Snapshot 방식
        # =================================

        if scanned_files is not None:

            scanned_files = list(
                scanned_files
            )


            if not scanned_files:

                raise ChunkPlanningError(
                    "Chunk Planning에 사용할 "
                    "Snapshot File이 없습니다."
                )


        # =================================
        # 기존 Path Scan 방식
        # =================================

        else:

            if target_path is None:

                raise ChunkPlanningError(
                    "Chunk Planning 대상 경로가 "
                    "지정되지 않았습니다."
                )


            scanned_files = (
                scan_source_files(
                    target_path
                )
            )


        chunk_specs = (
            build_chunk_specs(
                scanned_files
            )
        )


    except Exception as error:

        mark_planning_failed(
            analysis_run_id,
            error,
        )

        raise


    # ====================================
    # PHASE 3
    #
    # DB에 Planning 결과를 원자적으로 저장
    # ====================================

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


            if (
                analysis_run.status
                !=
                AnalysisRun
                .Status
                .PLANNING
            ):

                raise ChunkPlanningError(
                    "Planning 결과 저장 시 "
                    "AnalysisRun 상태가 변경되었습니다. "
                    f"status="
                    f"{analysis_run.status}"
                )


            # --------------------------------
            # 다른 Worker가 실행을
            # 시작하지 않았는지 재검사
            # --------------------------------

            has_attempts = (
                AnalysisChunk.objects
                .filter(
                    analysis_run=
                        analysis_run,

                    attempts__isnull=False,
                )
                .exists()
            )


            has_outboxes = (
                AnalysisChunk.objects
                .filter(
                    analysis_run=
                        analysis_run,

                    dispatch_outboxes__isnull=False,
                )
                .exists()
            )


            if (
                has_attempts
                or
                has_outboxes
            ):

                raise ChunkPlanningError(
                    "Planning 중 실행 상태가 변경되어 "
                    "결과를 저장할 수 없습니다."
                )


            # --------------------------------
            # 이전 미완성 Planning 결과 정리
            #
            # Attempt / Outbox가 없는 경우만
            # 여기까지 도달할 수 있다.
            # --------------------------------

            AnalysisChunk.objects.filter(
                analysis_run=
                    analysis_run
            ).delete()


            created_chunks = []

            queued_chunk_count = 0

            skipped_chunk_count = 0

            now = timezone.now()


            # =================================
            # Chunk 생성
            # =================================

            for (
                index,
                chunk_spec,
            ) in enumerate(
                chunk_specs,
                start=1,
            ):

                is_skipped = (

                    chunk_spec.status
                    ==
                    AnalysisChunk
                    .Status
                    .SKIPPED
                )


                chunk = (
                    AnalysisChunk.objects.create(

                        analysis_run=
                            analysis_run,

                        language=
                            chunk_spec.language,

                        sequence=
                            index,

                        status=
                            chunk_spec.status,

                        file_count=
                            len(
                                chunk_spec.files
                            ),

                        total_bytes=
                            chunk_spec.total_bytes,

                        retry_count=
                            0,

                        max_retries=
                            MAX_CHUNK_RETRIES,

                        status_reason=
                            chunk_spec.status_reason,

                        completed_at=(
                            now
                            if is_skipped
                            else None
                        ),
                    )
                )


                # -----------------------------
                # Chunk Files
                # -----------------------------

                AnalysisChunkFile.objects.bulk_create(
                    [
                        AnalysisChunkFile(

                            chunk=
                                chunk,

                            relative_path=
                                source_file
                                .relative_path,

                            size_bytes=
                                source_file
                                .size_bytes,

                            file_class=
                                source_file
                                .file_class,

                            content_sha256=
                                source_file
                                .content_sha256,
                        )

                        for source_file
                        in chunk_spec.files
                    ]
                )


                # -----------------------------
                # 실행 가능한 Chunk만
                # Outbox 생성
                # -----------------------------

                if is_skipped:

                    skipped_chunk_count += 1


                else:

                    AnalysisDispatchOutbox.objects.create(

                        chunk=
                            chunk,

                        dispatch_no=
                            1,

                        status=(
                            AnalysisDispatchOutbox
                            .Status
                            .PENDING
                        ),
                    )


                    queued_chunk_count += 1


                created_chunks.append(
                    chunk
                )


            # =================================
            # Language Snapshot
            # =================================

            detected_languages = [

                language

                for language
                in SUPPORTED_LANGUAGE_ORDER

                if any(
                    source_file.language
                    ==
                    language

                    for source_file
                    in scanned_files
                )
            ]


            analysis_run.analysis_languages = (
                detected_languages
            )


            # --------------------------------
            # Legacy 단일 언어 필드
            # --------------------------------

            if (
                len(
                    detected_languages
                )
                ==
                1
            ):

                analysis_run.analysis_language = (
                    detected_languages[0]
                )

            else:

                analysis_run.analysis_language = ""


            # =================================
            # 실행 가능한 Chunk가 없는 경우
            # =================================

            if queued_chunk_count == 0:

                analysis_run.status = (
                    AnalysisRun
                    .Status
                    .FAILED
                )


                analysis_run.completed_at = (
                    now
                )


                analysis_run.failure_reason = (
                    "분석 가능한 크기의 "
                    "소스 파일이 없습니다."
                )


            # =================================
            # 실행 가능한 Chunk 존재
            # =================================

            else:

                analysis_run.status = (
                    AnalysisRun
                    .Status
                    .RUNNING
                )


                if (
                    analysis_run.started_at
                    is None
                ):

                    analysis_run.started_at = (
                        now
                    )


                analysis_run.completed_at = None

                analysis_run.failure_reason = ""


            analysis_run.save(
                update_fields=[
                    "status",
                    "started_at",
                    "completed_at",
                    "failure_reason",
                    "analysis_languages",
                    "analysis_language",
                    "updated_at",
                ]
            )


            return {

                "analysis_run_id":
                    analysis_run.id,

                "status":
                    analysis_run.status,

                "languages":
                    detected_languages,

                "source_file_count":
                    len(
                        scanned_files
                    ),

                "chunk_count":
                    len(
                        created_chunks
                    ),

                "queued_chunk_count":
                    queued_chunk_count,

                "skipped_chunk_count":
                    skipped_chunk_count,
            }


    except Exception as error:

        mark_planning_failed(
            analysis_run_id,
            error,
        )

        raise