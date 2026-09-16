import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


# ========================================
# KISA Software Security Weakness
# ========================================

class KisaSecurityWeakness(models.Model):

    # ====================================
    # 구현 상태
    # ====================================

    class ImplementationStatus(
        models.TextChoices
    ):

        IMPLEMENTED = (
            "implemented",
            "구현 완료"
        )

        PARTIAL = (
            "partial",
            "부분 구현"
        )

        MANUAL = (
            "manual",
            "수동 점검"
        )

        NOT_IMPLEMENTED = (
            "not_implemented",
            "미구현"
        )


    # ====================================
    # 식별자
    #
    # 예:
    # KISA-SW-01
    # ====================================

    identifier = models.CharField(
        max_length=50,
        unique=True
    )


    # ====================================
    # 분류
    #
    # 예:
    # 입력데이터 검증 및 표현
    # ====================================

    category = models.CharField(
        max_length=100
    )


    # ====================================
    # 항목 번호
    #
    # 1 ~ 49
    # ====================================

    item_number = (
        models.PositiveSmallIntegerField(
            unique=True
        )
    )


    # ====================================
    # 보안약점 명칭
    # ====================================

    name = models.CharField(
        max_length=200
    )


    # ====================================
    # 보안약점 설명
    # ====================================

    description = models.TextField()


    # ====================================
    # 구현 상태
    # ====================================

    implementation_status = (
        models.CharField(
            max_length=20,

            choices=
                ImplementationStatus.choices,

            default=
                ImplementationStatus
                .NOT_IMPLEMENTED
        )
    )


    # ====================================
    # 생성 / 수정 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )


    class Meta:

        ordering = [
            "item_number"
        ]

        constraints = [

            # --------------------------------
            # KISA 보안약점 항목 번호는
            # 1 ~ 49 범위만 허용
            # --------------------------------

            models.CheckConstraint(
                condition=(
                    models.Q(
                        item_number__gte=1
                    )
                    &
                    models.Q(
                        item_number__lte=49
                    )
                ),

                name=
                    "kisa_item_number_range"
            ),
        ]


    def __str__(self):

        return (
            f"{self.identifier} - "
            f"{self.name}"
        )


class AnalysisRunQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if "pipeline_version" in kwargs:
            raise ValueError("pipeline_version is immutable after creation")
        return super().update(**kwargs)

    def bulk_update(self, objs, fields, batch_size=None):
        if "pipeline_version" in fields:
            raise ValueError("pipeline_version is immutable after creation")
        return super().bulk_update(objs, fields, batch_size=batch_size)


# ========================================
# AnalysisRun
#
# 사용자가 요청한 전체 분석 1회
#
# 실제 분석 작업은 AnalysisChunk로
# 분리하여 실행한다.
# ========================================

class AnalysisRun(models.Model):

    objects = AnalysisRunQuerySet.as_manager()

    class PipelineVersion(models.TextChoices):
        CHUNK_V1 = "chunk_v1", "Chunk v1"
        REPOSITORY_V2 = "repository_v2", "Repository v2"

    # ====================================
    # Status
    # ====================================

    class Status(models.TextChoices):

        PENDING = (
            "pending",
            "Pending"
        )

        PLANNING = (
            "planning",
            "Planning"
        )

        RUNNING = (
            "running",
            "Running"
        )

        COMPLETED = (
            "completed",
            "Completed"
        )

        FAILED = (
            "failed",
            "Failed"
        )

        CANCELLED = (
            "cancelled",
            "Cancelled"
        )


    # ====================================
    # Project
    # ====================================

    project = models.ForeignKey(
        "projects.Project",

        on_delete=models.CASCADE,

        related_name="analysis_runs"
    )


    # ====================================
    # SourceVersion
    # ====================================

    source_version = models.ForeignKey(
        "projects.SourceVersion",

        on_delete=models.PROTECT,

        related_name="analysis_runs"
    )


    # ====================================
    # Project별 분석 순번
    #
    # 1, 2, 3 ...
    # ====================================

    sequence = models.PositiveIntegerField()


    # ====================================
    # 분석 상태
    # ====================================

    status = models.CharField(
        max_length=20,

        choices=Status.choices,

        default=Status.PENDING
    )


    # ====================================
    # 분석 Engine
    # ====================================

    engine = models.CharField(
        max_length=100,

        default="Semgrep"
    )

    pipeline_version = models.CharField(
        max_length=20,
        choices=PipelineVersion.choices,
        default=PipelineVersion.CHUNK_V1,
        db_index=True,
    )

    snapshot_digest = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )

    finding_fingerprint_version = models.CharField(
        max_length=10,
        default="v2",
    )


    # ====================================
    # 기존 단일 분석 언어 Snapshot
    #
    # [전환용 필드]
    #
    # 기존 AnalysisRun 데이터와
    # 기존 코드 호환을 위해 유지한다.
    #
    # 다중 언어 구조가 안정화되면
    # 추후 제거 가능.
    # ====================================

    analysis_language = models.CharField(
        max_length=50,

        blank=True,

        default=""
    )


    # ====================================
    # 분석 시점 다중 언어 Snapshot
    #
    # 예:
    #
    # [
    #     "java",
    #     "javascript",
    #     "python",
    # ]
    #
    # SourceVersion의 언어 정보가
    # 이후 변경되어도 분석 당시 정보를
    # 그대로 유지한다.
    # ====================================

    analysis_languages = models.JSONField(
        default=list,

        blank=True
    )


    # ====================================
    # 분석 실행 사용자
    # ====================================

    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,

        on_delete=models.PROTECT,

        related_name="executed_analysis_runs"
    )


    # ====================================
    # 분석 시작 / 종료 시간
    # ====================================

    started_at = models.DateTimeField(
        null=True,

        blank=True
    )

    completed_at = models.DateTimeField(
        null=True,

        blank=True
    )


    # ====================================
    # 전체 분석 실패 정보
    #
    # Chunk 기반 구조가 안정화되면
    # Chunk 상태를 집계하여 설정한다.
    # ====================================

    failure_reason = models.TextField(
        blank=True
    )


    # ====================================
    # 기존 전체 분석 로그
    #
    # [Legacy / 호환용]
    # ====================================

    logs = models.TextField(
        blank=True
    )


    # ====================================
    # 기존 전체 Semgrep Raw Result
    #
    # [Legacy / 호환용]
    # ====================================

    raw_result = models.JSONField(
        null=True,

        blank=True
    )


    # ====================================
    # 생성 / 수정 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )


    class Meta:

        ordering = [
            "-created_at"
        ]

        constraints = [

            models.UniqueConstraint(
                fields=[
                    "project",
                    "sequence"
                ],

                name=
                    "unique_project_analysis_sequence"
            ),
        ]


    def __str__(self):

        return (
            f"{self.project.name} "
            f"Analysis #{self.sequence}"
        )


    def save(self, *args, **kwargs):
        if self.pk:
            persisted = (
                type(self).objects
                .filter(pk=self.pk)
                .values_list("pipeline_version", flat=True)
                .first()
            )
            if persisted and persisted != self.pipeline_version:
                raise ValueError("pipeline_version is immutable after creation")
        return super().save(*args, **kwargs)


# ========================================
# AnalysisChunk
#
# AnalysisRun을 실제 실행 가능한
# 작업 단위로 분할한 모델
#
# 중요:
# 더 이상 "언어당 Chunk 1개"가 아니다.
#
# 예:
#
# AnalysisRun #10
#
# python
#   Chunk #1
#   Chunk #2
#   Chunk #3
#
# javascript
#   Chunk #4
#
# java
#   Chunk #5
# ========================================

class AnalysisChunk(models.Model):

    # ====================================
    # Status
    # ====================================

    class Status(models.TextChoices):

        PENDING = (
            "pending",
            "Pending"
        )

        QUEUED = (
            "queued",
            "Queued"
        )

        RUNNING = (
            "running",
            "Running"
        )

        RETRY_PENDING = (
            "retry_pending",
            "Retry Pending"
        )

        COMPLETED = (
            "completed",
            "Completed"
        )

        FAILED = (
            "failed",
            "Failed"
        )

        SKIPPED = (
            "skipped",
            "Skipped"
        )

        CANCELLED = (
            "cancelled",
            "Cancelled"
        )


    # ====================================
    # AnalysisRun
    # ====================================

    analysis_run = models.ForeignKey(
        AnalysisRun,

        on_delete=models.CASCADE,

        related_name="analysis_chunks"
    )


    # ====================================
    # 분석 언어
    #
    # 예:
    # java
    # javascript
    # python
    #
    # 동일 언어의 Chunk가 여러 개
    # 존재할 수 있다.
    # ====================================

    language = models.CharField(
        max_length=50
    )


    # ====================================
    # AnalysisRun 내부 Chunk 순번
    #
    # 1, 2, 3 ...
    # ====================================

    sequence = models.PositiveIntegerField()


    # ====================================
    # Chunk 상태
    # ====================================

    status = models.CharField(
        max_length=20,

        choices=Status.choices,

        default=Status.PENDING
    )


    # ====================================
    # Chunk에 포함된 파일 개수
    # ====================================

    file_count = models.PositiveIntegerField(
        default=0
    )


    # ====================================
    # Chunk에 포함된 전체 파일 크기
    #
    # byte 단위
    # ====================================

    total_bytes = models.PositiveBigIntegerField(
        default=0
    )


    # ====================================
    # 재시도 횟수
    #
    # Attempt 실패 이후 실제로
    # 재시도된 횟수
    # ====================================

    retry_count = models.PositiveIntegerField(
        default=0
    )


    # ====================================
    # 최대 재시도 횟수
    # ====================================

    max_retries = models.PositiveIntegerField(
        default=3
    )


    # ====================================
    # Chunk 최종 상태 사유
    #
    # 예:
    #
    # FILE_TOO_LARGE
    # MAX_RETRIES_EXCEEDED
    # USER_CANCELLED
    #
    # 개별 실행 오류는
    # AnalysisChunkAttempt.failure_reason에
    # 기록한다.
    # ====================================

    status_reason = models.TextField(
        blank=True
    )


    # ====================================
    # Chunk 최초 실행 시작 시간
    # ====================================

    started_at = models.DateTimeField(
        null=True,

        blank=True
    )


    # ====================================
    # Chunk 최종 완료 시간
    # ====================================

    completed_at = models.DateTimeField(
        null=True,

        blank=True
    )


    # ====================================
    # 아래 필드는 기존 구조 호환용
    #
    # 새 실행 구조에서는
    # AnalysisChunkAttempt가
    # authoritative source가 된다.
    #
    # Celery Chunk Worker 전환 완료 후
    # 제거 예정.
    # ====================================

    heartbeat_at = models.DateTimeField(
        null=True,

        blank=True
    )

    result_count = models.PositiveIntegerField(
        default=0
    )

    failure_reason = models.TextField(
        blank=True
    )

    logs = models.TextField(
        blank=True
    )

    raw_result = models.JSONField(
        null=True,

        blank=True
    )


    # ====================================
    # 생성 / 수정 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )


    class Meta:

        ordering = [
            "sequence"
        ]

        constraints = [

            # --------------------------------
            # 하나의 AnalysisRun 안에서
            # Chunk 순번 중복 방지
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "analysis_run",
                    "sequence"
                ],

                name=
                    "unique_analysis_run_chunk_sequence"
            ),

            # --------------------------------
            # 중요:
            #
            # 기존의
            #
            # analysis_run + language
            #
            # UniqueConstraint는 삭제했다.
            #
            # 이제 같은 언어에서
            # 여러 Chunk 생성 가능.
            # --------------------------------
        ]

        indexes = [

            # --------------------------------
            # AnalysisRun의 Chunk 상태 집계
            # --------------------------------

            models.Index(
                fields=[
                    "analysis_run",
                    "status"
                ],

                name=
                    "chunk_run_status_idx"
            ),

            # --------------------------------
            # Recovery 대상 검색 보조
            # --------------------------------

            models.Index(
                fields=[
                    "status",
                    "updated_at"
                ],

                name=
                    "chunk_status_updated_idx"
            ),
        ]


    def __str__(self):

        return (
            f"{self.analysis_run.project.name} "
            f"Analysis #{self.analysis_run.sequence} "
            f"Chunk #{self.sequence} "
            f"({self.language})"
        )


# ========================================
# AnalysisChunkFile
#
# AnalysisChunk가 담당하는
# 실제 Source 파일
#
# 파일 내용을 DB에 저장하는 것이 아니라
# SourceVersion 기준 상대 경로와
# 메타데이터만 저장한다.
# ========================================

class AnalysisChunkFile(models.Model):

    # ====================================
    # 파일 크기 분류
    # ====================================

    class FileClass(models.TextChoices):

        NORMAL = (
            "normal",
            "Normal"
        )

        LARGE = (
            "large",
            "Large"
        )

        OVERSIZED = (
            "oversized",
            "Oversized"
        )


    # ====================================
    # Chunk
    # ====================================

    chunk = models.ForeignKey(
        AnalysisChunk,

        on_delete=models.CASCADE,

        related_name="files"
    )


    # ====================================
    # SourceVersion 기준 상대 경로
    #
    # 예:
    #
    # accounts/views.py
    #
    # 절대 경로는 저장하지 않는다.
    # ====================================

    relative_path = models.CharField(
        max_length=1000
    )


    # ====================================
    # 파일 크기
    #
    # byte 단위
    # ====================================

    size_bytes = models.PositiveBigIntegerField()


    # ====================================
    # 파일 크기 분류
    #
    # normal
    # large
    # oversized
    # ====================================

    file_class = models.CharField(
        max_length=20,

        choices=FileClass.choices,

        default=FileClass.NORMAL
    )


    # ====================================
    # Source 파일 SHA-256
    #
    # 추후:
    #
    # - 분석 입력 변조 확인
    # - 동일 파일 확인
    # - 캐시
    #
    # 등에 사용할 수 있다.
    #
    # 현재 Planner에서는
    # 빈 값으로 두어도 된다.
    # ====================================

    content_sha256 = models.CharField(
        max_length=64,

        blank=True,

        default=""
    )


    # ====================================
    # 생성 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )


    class Meta:

        ordering = [
            "id"
        ]

        constraints = [

            # --------------------------------
            # 하나의 Chunk에 동일 상대경로가
            # 두 번 등록되는 것을 방지
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "chunk",
                    "relative_path"
                ],

                name=
                    "unique_chunk_relative_path"
            ),
        ]

        indexes = [

            models.Index(
                fields=[
                    "chunk",
                    "file_class"
                ],

                name=
                    "chunk_file_class_idx"
            ),
        ]


    def __str__(self):

        return (
            f"Chunk #{self.chunk.sequence} - "
            f"{self.relative_path}"
        )


# ========================================
# AnalysisChunkAttempt
#
# AnalysisChunk를 실제로 실행한
# "한 번의 실행 시도"
#
# Chunk 하나는 Worker 장애 / Timeout 등으로
# 여러 Attempt를 가질 수 있다.
#
# 예:
#
# Chunk #3
#
# Attempt #1
# worker_lost
#
# Attempt #2
# timed_out
#
# Attempt #3
# completed
# ========================================

class AnalysisChunkAttempt(models.Model):

    # ====================================
    # Status
    # ====================================

    class Status(models.TextChoices):

        RUNNING = (
            "running",
            "Running"
        )

        COMPLETED = (
            "completed",
            "Completed"
        )

        FAILED = (
            "failed",
            "Failed"
        )

        WORKER_LOST = (
            "worker_lost",
            "Worker Lost"
        )

        TIMED_OUT = (
            "timed_out",
            "Timed Out"
        )

        CANCELLED = (
            "cancelled",
            "Cancelled"
        )

        SUPERSEDED = (
            "superseded",
            "Superseded"
        )


    # ====================================
    # Chunk
    # ====================================

    chunk = models.ForeignKey(
        AnalysisChunk,

        on_delete=models.CASCADE,

        related_name="attempts"
    )


    # ====================================
    # 실행 시도 번호
    #
    # 1, 2, 3 ...
    # ====================================

    attempt_no = models.PositiveIntegerField()


    # ====================================
    # 실행 소유권 Token
    #
    # Celery task_id와 별개다.
    #
    # stale Worker가 뒤늦게 결과를
    # 저장하려는 상황을 차단할 때 사용.
    # ====================================

    execution_token = models.UUIDField(
        default=uuid.uuid4,

        unique=True,

        editable=False
    )


    # ====================================
    # Celery Task ID
    #
    # 운영 / 추적용
    #
    # 실행 무결성 판단의 기준으로
    # 사용하지 않는다.
    # ====================================

    celery_task_id = models.CharField(
        max_length=255,

        blank=True,

        default="",

        db_index=True
    )


    # ====================================
    # Attempt 상태
    # ====================================

    status = models.CharField(
        max_length=20,

        choices=Status.choices,

        default=Status.RUNNING
    )


    # ====================================
    # 실행 시작 시간
    # ====================================

    started_at = models.DateTimeField(
        default=timezone.now
    )


    # ====================================
    # Worker Heartbeat
    #
    # 살아있는 Worker가 일정 주기로
    # 갱신한다.
    # ====================================

    heartbeat_at = models.DateTimeField(
        default=timezone.now
    )


    # ====================================
    # 실행권 Lease 만료 시간
    #
    # 현재 시간보다 과거이면서
    # status=running이면
    # stale 작업 후보가 된다.
    #
    # Attempt 생성 시 반드시 설정한다.
    # ====================================

    lease_expires_at = models.DateTimeField(
        db_index=True
    )


    # ====================================
    # Attempt 종료 시간
    # ====================================

    completed_at = models.DateTimeField(
        null=True,

        blank=True
    )


    # ====================================
    # 해당 Attempt의 탐지 결과 수
    # ====================================

    result_count = models.PositiveIntegerField(
        default=0
    )


    # ====================================
    # 실패 원인
    #
    # 내부 상세 정보는 외부 API에
    # 그대로 노출하지 않는다.
    # ====================================

    failure_reason = models.TextField(
        blank=True
    )


    # ====================================
    # Attempt 로그
    # ====================================

    logs = models.TextField(
        blank=True
    )


    # ====================================
    # 해당 Attempt의 Semgrep Raw Result
    # ====================================

    raw_result = models.JSONField(
        null=True,

        blank=True
    )


    # ====================================
    # 생성 / 수정 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )


    class Meta:

        ordering = [
            "attempt_no"
        ]

        constraints = [

            # --------------------------------
            # 같은 Chunk 안에서
            # Attempt 번호 중복 방지
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "chunk",
                    "attempt_no"
                ],

                name=
                    "unique_chunk_attempt_number"
            ),

            # --------------------------------
            # 하나의 Chunk에는 동시에
            # running Attempt가 최대 하나
            #
            # Celery 중복 전달에 대한
            # DB 차원의 방어선
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "chunk"
                ],

                condition=models.Q(
                    status="running"
                ),

                name=
                    "unique_running_attempt_per_chunk"
            ),

            # --------------------------------
            # 하나의 Chunk에는 최종적으로
            # completed Attempt가 최대 하나
            #
            # 성공 결과를 단일화한다.
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "chunk"
                ],

                condition=models.Q(
                    status="completed"
                ),

                name=
                    "unique_completed_attempt_per_chunk"
            ),
        ]

        indexes = [

            # --------------------------------
            # Recovery Scanner:
            #
            # running +
            # lease_expires_at < now
            #
            # 검색 최적화
            # --------------------------------

            models.Index(
                fields=[
                    "status",
                    "lease_expires_at"
                ],

                name=
                    "attempt_lease_idx"
            ),

            models.Index(
                fields=[
                    "chunk",
                    "status"
                ],

                name=
                    "attempt_chunk_status_idx"
            ),
        ]


    def __str__(self):

        return (
            f"Chunk #{self.chunk.sequence} "
            f"Attempt #{self.attempt_no} "
            f"({self.status})"
        )


# ========================================
# AnalysisDispatchOutbox
#
# PostgreSQL Transaction과
# Celery/Redis 메시지 전달 사이에서
# Task 유실을 방지한다.
#
# 중요한 원칙:
#
# PostgreSQL = Source of Truth
# Redis = Transport
# Celery = Executor
# ========================================

class AnalysisDispatchOutbox(models.Model):

    # ====================================
    # Status
    # ====================================

    class Status(models.TextChoices):

        PENDING = (
            "pending",
            "Pending"
        )

        PUBLISHED = (
            "published",
            "Published"
        )

        CANCELLED = (
            "cancelled",
            "Cancelled"
        )


    # ====================================
    # 대상 Chunk
    # ====================================

    chunk = models.ForeignKey(
        AnalysisChunk,

        on_delete=models.CASCADE,

        related_name="dispatch_outboxes"
    )


    # ====================================
    # Chunk 내부 Dispatch 번호
    #
    # 최초 dispatch
    # 1
    #
    # retry dispatch
    # 2, 3 ...
    # ====================================

    dispatch_no = models.PositiveIntegerField()


    # ====================================
    # Outbox Event 고유 식별자
    # ====================================

    event_key = models.UUIDField(
        default=uuid.uuid4,

        unique=True,

        editable=False
    )


    # ====================================
    # Outbox 상태
    # ====================================

    status = models.CharField(
        max_length=20,

        choices=Status.choices,

        default=Status.PENDING
    )


    # ====================================
    # Redis/Celery publish 시도 횟수
    # ====================================

    publish_attempts = models.PositiveIntegerField(
        default=0
    )


    # ====================================
    # Publish 성공 후 생성된
    # Celery Task ID
    # ====================================

    celery_task_id = models.CharField(
        max_length=255,

        blank=True,

        default=""
    )


    # ====================================
    # 다음 publish 시도 가능 시간
    #
    # Redis 장애 발생 시
    # exponential backoff 구현에 사용
    # ====================================

    available_at = models.DateTimeField(
        default=timezone.now
    )


    # ====================================
    # 가장 최근 publish 오류
    # ====================================

    last_error = models.TextField(
        blank=True
    )


    # ====================================
    # Publish 완료 시간
    # ====================================

    published_at = models.DateTimeField(
        null=True,

        blank=True
    )


    # ====================================
    # 생성 / 수정 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )


    class Meta:

        ordering = [
            "created_at"
        ]

        constraints = [

            # --------------------------------
            # 하나의 Chunk 안에서
            # dispatch 번호 중복 방지
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "chunk",
                    "dispatch_no"
                ],

                name=
                    "unique_chunk_dispatch_number"
            ),
        ]

        indexes = [

            # --------------------------------
            # Dispatcher가
            #
            # pending +
            # available_at <= now
            #
            # 조회할 때 사용
            # --------------------------------

            models.Index(
                fields=[
                    "status",
                    "available_at"
                ],

                name=
                    "outbox_dispatch_idx"
            ),
        ]


    def __str__(self):

        return (
            f"Chunk #{self.chunk.sequence} "
            f"Dispatch #{self.dispatch_no} "
            f"({self.status})"
        )


# ========================================
# Repository-v2 scan domain
# ========================================

class ScanExecution(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        RETRY_PENDING = "retry_pending", "Retry pending"
        NORMALIZATION_PENDING = "normalization_pending", "Normalization pending"
        NORMALIZING = "normalizing", "Normalizing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    analysis_run = models.OneToOneField(
        AnalysisRun, on_delete=models.CASCADE, related_name="scan_execution"
    )
    sequence = models.PositiveSmallIntegerField(default=1)
    scope_kind = models.CharField(max_length=20, default="repository")
    scope_root = models.CharField(max_length=255, default=".")
    status = models.CharField(max_length=30, choices=Status.choices, default=Status.PENDING)
    retry_count = models.PositiveSmallIntegerField(default=0)
    max_retries = models.PositiveSmallIntegerField(default=3)
    normalization_retry_count = models.PositiveSmallIntegerField(default=0)
    max_normalization_retries = models.PositiveSmallIntegerField(default=3)
    result_count = models.PositiveIntegerField(default=0)
    raw_occurrence_count = models.PositiveIntegerField(default=0)
    discovered_supported = models.PositiveIntegerField(default=0)
    coverage = models.JSONField(default=dict, blank=True)
    coverage_complete = models.BooleanField(default=False)
    status_reason = models.CharField(max_length=80, blank=True, default="")
    engine = models.CharField(max_length=30, default="semgrep")
    engine_version = models.CharField(max_length=40, blank=True, default="")
    capabilities = models.JSONField(default=dict, blank=True)
    snapshot_digest = models.CharField(max_length=64, blank=True, default="")
    ruleset_digest = models.CharField(max_length=64, blank=True, default="")
    options_digest = models.CharField(max_length=64, blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(sequence=1), name="scan_execution_sequence_one"),
            models.CheckConstraint(condition=models.Q(scope_kind="repository"), name="scan_execution_repository_scope"),
            models.CheckConstraint(condition=models.Q(scope_root="."), name="scan_execution_root_dot"),
            models.CheckConstraint(condition=models.Q(retry_count__lte=models.F("max_retries")), name="scan_execution_retry_bounds"),
            models.CheckConstraint(condition=models.Q(normalization_retry_count__lte=models.F("max_normalization_retries")), name="scan_normalization_retry_bounds"),
            models.CheckConstraint(
                condition=(
                    models.Q(status__in=["completed", "failed", "cancelled"], completed_at__isnull=False)
                    | models.Q(status__in=["pending", "queued", "running", "retry_pending", "normalization_pending", "normalizing"], completed_at__isnull=True)
                ),
                name="scan_execution_terminal_time",
            ),
        ]


class ScanAttempt(models.Model):
    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        WORKER_LOST = "worker_lost", "Worker lost"
        TIMED_OUT = "timed_out", "Timed out"
        CANCELLED = "cancelled", "Cancelled"
        SUPERSEDED = "superseded", "Superseded"

    execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name="attempts")
    attempt_no = models.PositiveIntegerField()
    execution_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    celery_task_id = models.CharField(max_length=255, blank=True, default="", db_index=True)
    process_group_id = models.PositiveIntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.RUNNING)
    started_at = models.DateTimeField(default=timezone.now)
    heartbeat_at = models.DateTimeField(default=timezone.now)
    lease_expires_at = models.DateTimeField(db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)
    logs = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["execution", "attempt_no"], name="unique_scan_attempt_number"),
            models.UniqueConstraint(fields=["execution"], condition=models.Q(status="running"), name="unique_running_scan_attempt"),
            models.UniqueConstraint(fields=["execution"], condition=models.Q(status="completed"), name="unique_completed_scan_attempt"),
            models.CheckConstraint(
                condition=(
                    models.Q(status="running", completed_at__isnull=True)
                    | models.Q(status__in=["completed", "failed", "worker_lost", "timed_out", "cancelled", "superseded"], completed_at__isnull=False)
                ),
                name="scan_attempt_status_time",
            ),
        ]


class ScanArtifact(models.Model):
    class State(models.TextChoices):
        WRITING = "writing", "Writing"
        READY = "ready", "Ready"
        INVALID = "invalid", "Invalid"
        DELETED = "deleted", "Deleted"

    class Kind(models.TextChoices):
        SEMGREP_JSON = "semgrep_json", "Semgrep JSON"
        DIAGNOSTIC = "diagnostic", "Diagnostic"

    execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name="artifacts")
    attempt = models.ForeignKey(ScanAttempt, on_delete=models.PROTECT, related_name="artifacts")
    kind = models.CharField(max_length=30, choices=Kind.choices, default=Kind.SEMGREP_JSON)
    state = models.CharField(max_length=20, choices=State.choices, default=State.WRITING)
    is_canonical = models.BooleanField(default=False)
    relative_path = models.CharField(max_length=500, blank=True, default="")
    sha256 = models.CharField(max_length=64, blank=True, default="")
    size_bytes = models.PositiveBigIntegerField(default=0)
    schema_version = models.PositiveSmallIntegerField(default=1)
    content_type = models.CharField(max_length=100, default="application/json")
    published_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["execution"], condition=models.Q(kind="semgrep_json", is_canonical=True), name="unique_canonical_scan_artifact"),
            models.CheckConstraint(
                condition=(
                    ~models.Q(state="ready")
                    | (
                        models.Q(published_at__isnull=False, size_bytes__gt=0)
                        & ~models.Q(relative_path="")
                        & ~models.Q(sha256="")
                    )
                ),
                name="scan_artifact_ready_metadata",
            ),
        ]


class ScanDispatchOutbox(models.Model):
    class Kind(models.TextChoices):
        ENGINE = "engine", "Engine"
        NORMALIZATION = "normalization", "Normalization"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PUBLISHED = "published", "Published"
        CANCELLED = "cancelled", "Cancelled"

    execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name="dispatch_outboxes")
    kind = models.CharField(max_length=20, choices=Kind.choices)
    dispatch_no = models.PositiveIntegerField()
    event_key = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    payload = models.JSONField(default=dict)
    task_name = models.CharField(max_length=120)
    deterministic_task_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    publish_attempts = models.PositiveSmallIntegerField(default=0)
    max_publish_attempts = models.PositiveSmallIntegerField(default=5)
    available_at = models.DateTimeField(default=timezone.now)
    published_at = models.DateTimeField(null=True, blank=True)
    claim_deadline_at = models.DateTimeField(null=True, blank=True, db_index=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    claimed_attempt = models.ForeignKey(ScanAttempt, on_delete=models.SET_NULL, null=True, blank=True, related_name="claimed_outboxes")
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["execution", "kind", "dispatch_no"], name="unique_scan_dispatch_number"),
            models.UniqueConstraint(fields=["execution", "kind"], condition=models.Q(status="pending"), name="unique_pending_scan_dispatch"),
            models.CheckConstraint(condition=models.Q(publish_attempts__lte=models.F("max_publish_attempts")), name="scan_dispatch_publish_bounds"),
        ]


class ScanNormalizationAttempt(models.Model):
    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        WORKER_LOST = "worker_lost", "Worker lost"
        TIMED_OUT = "timed_out", "Timed out"
        CANCELLED = "cancelled", "Cancelled"

    execution = models.ForeignKey(ScanExecution, on_delete=models.CASCADE, related_name="normalization_attempts")
    attempt_no = models.PositiveIntegerField()
    execution_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.RUNNING)
    started_at = models.DateTimeField(default=timezone.now)
    heartbeat_at = models.DateTimeField(default=timezone.now)
    lease_expires_at = models.DateTimeField(db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)
    logs = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["execution", "attempt_no"], name="unique_normalization_attempt_number"),
            models.UniqueConstraint(fields=["execution"], condition=models.Q(status="running"), name="unique_running_normalization_attempt"),
            models.UniqueConstraint(fields=["execution"], condition=models.Q(status="completed"), name="unique_completed_normalization_attempt"),
            models.CheckConstraint(
                condition=(
                    models.Q(status="running", completed_at__isnull=True)
                    | models.Q(status__in=["completed", "failed", "worker_lost", "timed_out", "cancelled"], completed_at__isnull=False)
                ),
                name="normalization_attempt_status_time",
            ),
        ]


class ScanFinding(models.Model):
    analysis_run = models.ForeignKey(AnalysisRun, on_delete=models.CASCADE, related_name="scan_findings")
    fingerprint_version = models.CharField(max_length=10, default="v2")
    aggregate_fingerprint = models.CharField(max_length=64)
    lineage_signature = models.CharField(max_length=64, db_index=True)
    rule_id = models.CharField(max_length=255)
    language = models.CharField(max_length=50, blank=True, default="")
    file_path = models.CharField(max_length=1000)
    start_line = models.PositiveIntegerField(default=1)
    start_column = models.PositiveIntegerField(default=1)
    end_line = models.PositiveIntegerField(default=1)
    end_column = models.PositiveIntegerField(default=1)
    severity = models.CharField(max_length=30, blank=True, default="")
    message = models.TextField(blank=True)
    canonical_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["analysis_run", "fingerprint_version", "aggregate_fingerprint"], name="unique_scan_aggregate_fingerprint"),
        ]


class ScanOccurrence(models.Model):
    artifact = models.ForeignKey(ScanArtifact, on_delete=models.CASCADE, related_name="occurrences")
    finding = models.ForeignKey(ScanFinding, on_delete=models.CASCADE, related_name="occurrences")
    occurrence_key = models.CharField(max_length=64)
    raw_result_index = models.PositiveIntegerField()
    raw_payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["artifact", "occurrence_key"], name="unique_scan_occurrence_key"),
            models.UniqueConstraint(fields=["artifact", "raw_result_index"], name="unique_scan_raw_result_index"),
        ]


# ========================================
# Vulnerability
# ========================================

class Vulnerability(models.Model):

    # ====================================
    # Severity
    # ====================================

    class Severity(models.TextChoices):

        CRITICAL = (
            "critical",
            "Critical"
        )

        HIGH = (
            "high",
            "High"
        )

        MEDIUM = (
            "medium",
            "Medium"
        )

        LOW = (
            "low",
            "Low"
        )


    # ====================================
    # Confidence
    # ====================================

    class Confidence(models.TextChoices):

        HIGH = (
            "high",
            "High"
        )

        MEDIUM = (
            "medium",
            "Medium"
        )

        LOW = (
            "low",
            "Low"
        )


    # ====================================
    # AnalysisRun
    #
    # 기존 API / 데이터 구조와의
    # 호환성을 위해 유지한다.
    # ====================================

    analysis_run = models.ForeignKey(
        AnalysisRun,

        on_delete=models.CASCADE,

        related_name="vulnerabilities"
    )


    # ====================================
    # AnalysisChunkAttempt
    #
    # 실제 어떤 실행 Attempt에서
    # 생성된 결과인지 기록한다.
    #
    # 기존 Vulnerability 데이터는
    # Attempt 정보가 없으므로
    # null / blank 허용.
    #
    # 새 Chunk Worker에서는
    # 반드시 값을 지정한다.
    # ====================================

    analysis_attempt = models.ForeignKey(
        AnalysisChunkAttempt,

        on_delete=models.CASCADE,

        null=True,

        blank=True,

        related_name="vulnerabilities"
    )


    # ====================================
    # Vulnerability Fingerprint
    #
    # 동일 Attempt에서 동일 결과가
    # 중복 저장되는 것을 방지한다.
    #
    # 추후 예:
    #
    # sha256(
    #     rule_id
    #     + file_path
    #     + start_line
    #     + start_column
    # )
    #
    # 기존 데이터 호환을 위해
    # null 허용.
    # ====================================

    fingerprint = models.CharField(
        max_length=64,

        null=True,

        blank=True
    )


    # ====================================
    # KISA 보안약점
    #
    # 현재 기존 Semgrep 분석 데이터에는
    # KISA 매핑 정보가 없을 수 있으므로
    # null 허용
    # ====================================

    security_weakness = models.ForeignKey(
        KisaSecurityWeakness,

        on_delete=models.PROTECT,

        null=True,

        blank=True,

        related_name="vulnerabilities"
    )


    # ====================================
    # 취약점 분석 언어
    #
    # 예:
    #
    # python
    # javascript
    # java
    #
    # 기존 데이터 호환을 위해
    # blank 허용
    # ====================================

    analysis_language = models.CharField(
        max_length=50,

        blank=True,

        default=""
    )


    # ====================================
    # Semgrep Rule ID
    # ====================================

    rule_id = models.CharField(
        max_length=200
    )


    # ====================================
    # 취약점 이름
    # ====================================

    name = models.CharField(
        max_length=300
    )


    # ====================================
    # Severity
    # ====================================

    severity = models.CharField(
        max_length=20,

        choices=Severity.choices
    )


    # ====================================
    # Confidence
    # ====================================

    confidence = models.CharField(
        max_length=20,

        choices=Confidence.choices,

        blank=True
    )


    # ====================================
    # 파일 경로
    # ====================================

    file_path = models.CharField(
        max_length=1000
    )


    # ====================================
    # 취약 코드 Line
    # ====================================

    line = models.PositiveIntegerField(
        null=True,

        blank=True
    )


    # ====================================
    # 메시지
    # ====================================

    message = models.TextField(
        blank=True
    )


    # ====================================
    # 취약 코드
    # ====================================

    evidence = models.TextField(
        blank=True
    )


    # ====================================
    # 개선 방법
    # ====================================

    recommendation = models.TextField(
        blank=True
    )


    # ====================================
    # 생성 시간
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )


    class Meta:

        ordering = [
            "id"
        ]

        constraints = [

            # --------------------------------
            # 동일 Attempt 안에서
            # 동일 fingerprint의 취약점이
            # 중복 저장되는 것을 방지한다.
            #
            # Legacy Vulnerability에는
            # analysis_attempt / fingerprint가
            # null일 수 있으므로 제외.
            # --------------------------------

            models.UniqueConstraint(
                fields=[
                    "analysis_attempt",
                    "fingerprint"
                ],

                condition=(
                    models.Q(
                        analysis_attempt__isnull=False
                    )
                    &
                    models.Q(
                        fingerprint__isnull=False
                    )
                ),

                name=
                    "unique_attempt_vulnerability_fingerprint"
            ),
        ]

        indexes = [

            # --------------------------------
            # AnalysisRun 결과 조회 +
            # Attempt별 결과 조회
            # --------------------------------

            models.Index(
                fields=[
                    "analysis_run",
                    "analysis_attempt"
                ],

                name=
                    "vuln_run_attempt_idx"
            ),
        ]


    def __str__(self):

        return (
            f"{self.rule_id} - "
            f"{self.file_path}"
        )
