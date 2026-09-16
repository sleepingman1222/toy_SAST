# ========================================
# Analysis Progress Service
#
# AnalysisRun에 속한 AnalysisChunk 상태를
# PostgreSQL 기준으로 집계하여 Frontend에
# 표시할 진행 정보를 만든다.
#
# IMPORTANT:
# - Redis / Celery 상태를 조회하지 않는다.
# - DB만 Source of Truth로 사용한다.
# - 상태를 변경하지 않는 Read-only Service다.
# ========================================


ACTIVE_CHUNK_STATUSES = {
    "pending",
    "queued",
    "running",
    "retry_pending",
}


TERMINAL_CHUNK_STATUSES = {
    "completed",
    "failed",
    "skipped",
    "cancelled",
}


REPOSITORY_PROGRESS_MILESTONES = {
    "pending": 0,
    "queued": 10,
    "running": 25,
    "retry_pending": 25,
    "normalization_pending": 50,
    "normalizing": 75,
    "completed": 100,
    "failed": 100,
    "cancelled": 100,
}


def _build_repository_progress(analysis_run):
    try:
        execution = analysis_run.scan_execution
    except Exception:
        execution = None
    languages = list(getattr(analysis_run, "analysis_languages", []) or [])
    if execution is None:
        return {
            "analysis_run_id": analysis_run.id,
            "pipeline_version": "repository_v2",
            "status": analysis_run.status,
            "progress_percent": 0,
            "total_executions": 0,
            "terminal_executions": 0,
            "total_chunks": 0,
            "terminal_chunks": 0,
            "executions": [],
            "chunks": [],
            "languages": [],
        }
    artifact = execution.artifacts.filter(is_canonical=True).order_by("-id").first()
    terminal = execution.status in {"completed", "failed", "cancelled"}
    compatibility_status = (
        "running"
        if execution.status in {"normalization_pending", "normalizing"}
        else execution.status
    )
    execution_payload = {
        "sequence": 1,
        "scope_kind": "repository",
        "scope_root": ".",
        "languages": languages,
        "status": execution.status,
        "artifact_status": getattr(artifact, "state", ""),
        "capabilities": execution.capabilities,
        "coverage": execution.coverage,
        "coverage_complete": execution.coverage_complete,
        "result_count": execution.result_count,
        "raw_occurrence_count": execution.raw_occurrence_count,
    }
    return {
        "analysis_run_id": analysis_run.id,
        "pipeline_version": "repository_v2",
        "status": analysis_run.status,
        "progress_percent": REPOSITORY_PROGRESS_MILESTONES.get(execution.status, 0),
        "total_executions": 1,
        "terminal_executions": int(terminal),
        "active_executions": int(not terminal),
        "executions": [execution_payload],
        "total_chunks": 1,
        "terminal_chunks": int(terminal),
        "active_chunks": int(not terminal),
        "unknown_chunks": 0,
        "pending_chunks": int(execution.status == "pending"),
        "queued_chunks": int(execution.status == "queued"),
        "running_chunks": int(execution.status in {"running", "normalization_pending", "normalizing"}),
        "retry_pending_chunks": int(execution.status == "retry_pending"),
        "completed_chunks": int(execution.status == "completed"),
        "failed_chunks": int(execution.status == "failed"),
        "skipped_chunks": 0,
        "cancelled_chunks": int(execution.status == "cancelled"),
        "chunks": [{
            "sequence": 1,
            "language": "mixed",
            "languages": languages,
            "status": compatibility_status,
            "result_count": execution.result_count,
        }],
        "result_count": execution.result_count,
        "raw_occurrence_count": execution.raw_occurrence_count,
        "languages": [
            {"language": language, "file_count": 0, "coverage": {}}
            for language in languages
        ],
    }


KNOWN_CHUNK_STATUSES = (
    "pending",
    "queued",
    "running",
    "retry_pending",
    "completed",
    "failed",
    "skipped",
    "cancelled",
)


# ========================================
# 기본 값 Helper
# ========================================

def _safe_int(
    value,
    default=0,
):

    try:
        return int(
            value
            if value is not None
            else default
        )

    except (
        TypeError,
        ValueError,
    ):
        return default


# ========================================
# DateTime → ISO 문자열
# ========================================

def _serialize_datetime(
    value,
):

    if value is None:
        return None


    isoformat = getattr(
        value,
        "isoformat",
        None,
    )


    if callable(
        isoformat
    ):
        return isoformat()


    return str(
        value
    )


# ========================================
# Chunk 실패 / 상태 사유
#
# 최신 Model은 status_reason을 사용하고,
# 이전 데이터 / 전환 코드와의 호환을 위해
# failure_reason도 fallback으로 확인한다.
# ========================================

def _get_chunk_status_reason(
    chunk,
):

    return (
        getattr(
            chunk,
            "status_reason",
            "",
        )
        or
        getattr(
            chunk,
            "failure_reason",
            "",
        )
        or
        ""
    )


# ========================================
# Status Count 초기값
# ========================================

def _new_status_counts():

    return {
        status: 0
        for status
        in KNOWN_CHUNK_STATUSES
    }


# ========================================
# 단일 Chunk 직렬화
# ========================================

def _serialize_chunk(
    chunk,
):

    return {
        "id":
            chunk.id,

        "sequence":
            _safe_int(
                getattr(
                    chunk,
                    "sequence",
                    0,
                )
            ),

        "language":
            getattr(
                chunk,
                "language",
                "",
            )
            or "",

        "status":
            getattr(
                chunk,
                "status",
                "",
            )
            or "",

        "file_count":
            _safe_int(
                getattr(
                    chunk,
                    "file_count",
                    0,
                )
            ),

        "total_bytes":
            _safe_int(
                getattr(
                    chunk,
                    "total_bytes",
                    0,
                )
            ),

        "retry_count":
            _safe_int(
                getattr(
                    chunk,
                    "retry_count",
                    0,
                )
            ),

        "max_retries":
            _safe_int(
                getattr(
                    chunk,
                    "max_retries",
                    0,
                )
            ),

        "result_count":
            _safe_int(
                getattr(
                    chunk,
                    "result_count",
                    0,
                )
            ),

        "status_reason":
            _get_chunk_status_reason(
                chunk
            ),

        "started_at":
            _serialize_datetime(
                getattr(
                    chunk,
                    "started_at",
                    None,
                )
            ),

        "completed_at":
            _serialize_datetime(
                getattr(
                    chunk,
                    "completed_at",
                    None,
                )
            ),
    }


# ========================================
# 언어별 집계
# ========================================

def _build_language_progress(
    chunks,
):

    language_map = {}


    for chunk in chunks:

        language = (
            getattr(
                chunk,
                "language",
                "",
            )
            or "unknown"
        )


        if language not in language_map:

            language_map[
                language
            ] = {
                "language":
                    language,

                "total":
                    0,

                "terminal":
                    0,

                "active":
                    0,

                "pending":
                    0,

                "queued":
                    0,

                "running":
                    0,

                "retry_pending":
                    0,

                "completed":
                    0,

                "failed":
                    0,

                "skipped":
                    0,

                "cancelled":
                    0,

                "result_count":
                    0,

                "retry_count":
                    0,
            }


        item = language_map[
            language
        ]


        status = (
            getattr(
                chunk,
                "status",
                "",
            )
            or ""
        )


        item[
            "total"
        ] += 1


        if status in item:
            item[
                status
            ] += 1


        if (
            status
            in
            TERMINAL_CHUNK_STATUSES
        ):
            item[
                "terminal"
            ] += 1


        if (
            status
            in
            ACTIVE_CHUNK_STATUSES
        ):
            item[
                "active"
            ] += 1


        item[
            "result_count"
        ] += _safe_int(
            getattr(
                chunk,
                "result_count",
                0,
            )
        )


        item[
            "retry_count"
        ] += _safe_int(
            getattr(
                chunk,
                "retry_count",
                0,
            )
        )


    results = []


    for item in language_map.values():

        total = item[
            "total"
        ]

        terminal = item[
            "terminal"
        ]


        item[
            "progress_percent"
        ] = (
            round(
                terminal
                * 100
                / total
            )
            if total > 0
            else 0
        )


        results.append(
            item
        )


    return results


# ========================================
# AnalysisRun Chunk Progress
# ========================================

def build_analysis_progress(
    analysis_run,
):

    if (
        getattr(analysis_run, "pipeline_version", "chunk_v1")
        == "repository_v2"
    ):
        return _build_repository_progress(analysis_run)

    # ------------------------------------
    # View에서 prefetch_related를 사용하면
    # 추가 Query 없이 캐시된 Chunk를 사용한다.
    # ------------------------------------

    chunks = list(
        analysis_run
        .analysis_chunks
        .all()
    )


    chunks.sort(
        key=lambda chunk: (
            _safe_int(
                getattr(
                    chunk,
                    "sequence",
                    0,
                )
            ),
            _safe_int(
                getattr(
                    chunk,
                    "id",
                    0,
                )
            ),
        )
    )


    status_counts = (
        _new_status_counts()
    )


    total_files = 0
    total_bytes = 0
    result_count = 0
    retry_count = 0


    for chunk in chunks:

        status = (
            getattr(
                chunk,
                "status",
                "",
            )
            or ""
        )


        if status in status_counts:
            status_counts[
                status
            ] += 1


        total_files += _safe_int(
            getattr(
                chunk,
                "file_count",
                0,
            )
        )


        total_bytes += _safe_int(
            getattr(
                chunk,
                "total_bytes",
                0,
            )
        )


        result_count += _safe_int(
            getattr(
                chunk,
                "result_count",
                0,
            )
        )


        retry_count += _safe_int(
            getattr(
                chunk,
                "retry_count",
                0,
            )
        )


    total_chunks = len(
        chunks
    )


    terminal_chunks = sum(
        status_counts[
            status
        ]
        for status
        in TERMINAL_CHUNK_STATUSES
    )


    active_chunks = sum(
        status_counts[
            status
        ]
        for status
        in ACTIVE_CHUNK_STATUSES
    )


    known_chunks = (
        terminal_chunks
        + active_chunks
    )


    unknown_chunks = max(
        total_chunks
        - known_chunks,
        0,
    )


    progress_percent = (
        round(
            terminal_chunks
            * 100
            / total_chunks
        )
        if total_chunks > 0
        else 0
    )


    return {
        "analysis_run_id":
            analysis_run.id,

        "status":
            analysis_run.status,

        "progress_percent":
            progress_percent,

        "total_chunks":
            total_chunks,

        "terminal_chunks":
            terminal_chunks,

        "active_chunks":
            active_chunks,

        "unknown_chunks":
            unknown_chunks,

        "pending_chunks":
            status_counts[
                "pending"
            ],

        "queued_chunks":
            status_counts[
                "queued"
            ],

        "running_chunks":
            status_counts[
                "running"
            ],

        "retry_pending_chunks":
            status_counts[
                "retry_pending"
            ],

        "completed_chunks":
            status_counts[
                "completed"
            ],

        "failed_chunks":
            status_counts[
                "failed"
            ],

        "skipped_chunks":
            status_counts[
                "skipped"
            ],

        "cancelled_chunks":
            status_counts[
                "cancelled"
            ],

        "total_files":
            total_files,

        "total_bytes":
            total_bytes,

        "result_count":
            result_count,

        "retry_count":
            retry_count,

        "languages":
            _build_language_progress(
                chunks
            ),

        "chunks": [
            _serialize_chunk(
                chunk
            )
            for chunk
            in chunks
        ],

        "updated_at":
            _serialize_datetime(
                getattr(
                    analysis_run,
                    "updated_at",
                    None,
                )
            ),
    }
