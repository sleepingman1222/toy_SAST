# ========================================
# Analysis / Language Constants
# ========================================


# ========================================
# 지원 언어
#
# Chunk sequence도 이 순서를 기준으로
# 안정적으로 생성한다.
# ========================================

SUPPORTED_LANGUAGE_ORDER = (
    "java",
    "javascript",
    "python",
)


# ========================================
# Source Extension → Language
# ========================================

LANGUAGE_EXTENSIONS = {

    ".java":
        "java",

    ".js":
        "javascript",

    ".jsx":
        "javascript",

    ".mjs":
        "javascript",

    ".cjs":
        "javascript",

    ".py":
        "python",
}


# ========================================
# Language Alias
# ========================================

LANGUAGE_ALIASES = {

    "java":
        "java",

    "javascript":
        "javascript",

    "js":
        "javascript",

    "python":
        "python",

    "py":
        "python",
}


# ========================================
# Display Name
# ========================================

LANGUAGE_DISPLAY_NAMES = {

    "java":
        "Java",

    "javascript":
        "JavaScript",

    "python":
        "Python",
}


# ========================================
# 분석 대상에서 제외할 디렉터리
# ========================================

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
# Chunk Planner
# ========================================


# ----------------------------------------
# 한 Chunk에 들어갈 최대 파일 수
# ----------------------------------------

MAX_FILES_PER_CHUNK = 30


# ----------------------------------------
# 하나의 일반 Chunk 최대 총 크기
#
# 5 MB
# ----------------------------------------

MAX_CHUNK_BYTES = (
    5
    * 1024
    * 1024
)


# ----------------------------------------
# Large File 판단 기준
#
# 2 MB 이상부터 단독 Chunk
# ----------------------------------------

LARGE_FILE_BYTES = (
    2
    * 1024
    * 1024
)


# ----------------------------------------
# 분석 가능한 단일 Source File 최대 크기
#
# 10 MB
#
# 초과 파일은 Oversized로 기록하고
# 분석에서는 제외한다.
# ----------------------------------------

MAX_ANALYZABLE_FILE_BYTES = (
    10
    * 1024
    * 1024
)


# ----------------------------------------
# 하나의 AnalysisRun에서 처리할
# 최대 Source File 수
# ----------------------------------------

MAX_PLANNABLE_SOURCE_FILES = 5000


# ----------------------------------------
# 실제 분석 가능한 Source File
# 전체 크기 제한
#
# 200 MB
# ----------------------------------------

MAX_PLANNABLE_ANALYZABLE_BYTES = (
    200
    * 1024
    * 1024
)


# ----------------------------------------
# Chunk 최대 Retry 횟수
#
# 최초 Attempt는 Retry가 아니다.
#
# max_retries = 3이면
#
# Attempt #1
# +
# Retry 3회
#
# 최대 총 Attempt 수 = 4
# ----------------------------------------

MAX_CHUNK_RETRIES = 3


# ----------------------------------------
# SHA256 Streaming Buffer
#
# 1 MB
# ----------------------------------------

FILE_HASH_BUFFER_SIZE = (
    1024
    * 1024
)


# ========================================
# AnalysisChunkAttempt
# ========================================


# ----------------------------------------
# Chunk Attempt Lease
#
# Worker가 Heartbeat를 갱신하지 못하고
# 이 시간이 지나면 stale Attempt 후보가 된다.
#
# 120 seconds
# ----------------------------------------

CHUNK_ATTEMPT_LEASE_SECONDS = 120


# ----------------------------------------
# 정상 Worker Heartbeat 주기
#
# 실제 Worker 구현 시
# 약 30초마다 Lease를 연장한다.
#
# Lease보다 충분히 짧아야 한다.
# ----------------------------------------

CHUNK_HEARTBEAT_INTERVAL_SECONDS = 30


# ========================================
# Outbox Dispatcher
# ========================================


# ----------------------------------------
# Celery Chunk Task 이름
#
# 이후 tasks.py에 만드는 Task 이름과
# 반드시 동일해야 한다.
# ----------------------------------------

ANALYSIS_CHUNK_TASK_NAME = (
    "scans.tasks.run_analysis_chunk"
)


# ----------------------------------------
# 한 번에 처리할 Outbox 최대 개수
# ----------------------------------------

OUTBOX_DISPATCH_BATCH_SIZE = 50


# ----------------------------------------
# Dispatcher Claim Lease
#
# seconds
# ----------------------------------------

OUTBOX_CLAIM_SECONDS = 30


# ----------------------------------------
# Redis Publish 실패 Retry Backoff
#
# 5 → 10 → 20 → 40 ...
#
# 최대 300초
# ----------------------------------------

OUTBOX_RETRY_BASE_SECONDS = 5

OUTBOX_RETRY_MAX_SECONDS = 300


# ----------------------------------------
# Outbox Error 저장 최대 길이
# ----------------------------------------

OUTBOX_ERROR_MAX_LENGTH = 2000


# ========================================
# Analysis Workspace
# ========================================


# ----------------------------------------
# MEDIA_ROOT 아래 Workspace Directory
#
# MEDIA_ROOT/
# └ analysis_workspaces/
# ----------------------------------------

ANALYSIS_WORKSPACE_DIRECTORY = (
    "analysis_workspaces"
)


# ----------------------------------------
# AnalysisRun Workspace 내부
# Source Directory
#
# analysis_workspaces/
# └ run_10/
#    └ source/
# ----------------------------------------

ANALYSIS_WORKSPACE_SOURCE_DIRECTORY = (
    "source"
)


# ----------------------------------------
# Snapshot Manifest
# ----------------------------------------

ANALYSIS_WORKSPACE_MANIFEST_NAME = (
    "manifest.json"
)


# ----------------------------------------
# Workspace File Copy Buffer
#
# 1 MB
# ----------------------------------------

WORKSPACE_COPY_BUFFER_SIZE = (
    1024
    * 1024
)