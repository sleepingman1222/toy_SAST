from django.conf import settings
from django.db import models

from projects.models import (
    Project,
    SourceVersion,
)


# ========================================
# AnalysisRun
# ========================================

class AnalysisRun(models.Model):

    # ====================================
    # Analysis Status
    # ====================================

    class Status(models.TextChoices):

        PENDING = (
            "pending",
            "Pending"
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


    # ====================================
    # Project
    # ====================================

    project = models.ForeignKey(
        Project,

        on_delete=models.CASCADE,

        related_name="analysis_runs"
    )


    # ====================================
    # 분석 대상 SourceVersion
    # ====================================

    source_version = models.ForeignKey(
        SourceVersion,

        on_delete=models.PROTECT,

        related_name="analysis_runs"
    )


    # ====================================
    # Project 내부 Analysis 순번
    #
    # Analysis #1
    # Analysis #2
    # ...
    # ====================================

    sequence = models.PositiveIntegerField()


    # ====================================
    # Status
    # ====================================

    status = models.CharField(
        max_length=20,

        choices=Status.choices,

        default=Status.PENDING
    )


    # ====================================
    # 분석 엔진
    # ====================================

    engine = models.CharField(
        max_length=100,

        default="Semgrep"
    )


    # ====================================
    # 분석 당시 Language Snapshot
    #
    # SourceVersion.language와 별도로
    # 분석 실행 시점 언어를 보존
    # ====================================

    analysis_language = models.CharField(
        max_length=50
    )


    # ====================================
    # 실행자
    # ====================================

    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,

        on_delete=models.PROTECT,

        related_name="executed_analysis_runs"
    )


    # ====================================
    # 시간
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
    # 실패 정보
    # ====================================

    failure_reason = models.TextField(
        blank=True
    )

    logs = models.TextField(
        blank=True
    )


    # ====================================
    # Semgrep Raw Result
    #
    # 나중에 원본 분석 결과를
    # 보존하기 위한 JSON
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

            # 같은 Project에서
            # sequence 중복 방지

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
    # ====================================

    analysis_run = models.ForeignKey(
        AnalysisRun,

        on_delete=models.CASCADE,

        related_name="vulnerabilities"
    )


    # ====================================
    # Rule
    # ====================================

    rule_id = models.CharField(
        max_length=200
    )

    name = models.CharField(
        max_length=300
    )


    # ====================================
    # Severity / Confidence
    # ====================================

    severity = models.CharField(
        max_length=20,

        choices=Severity.choices
    )


    confidence = models.CharField(
        max_length=20,

        choices=Confidence.choices,

        blank=True
    )


    # ====================================
    # File Location
    # ====================================

    file_path = models.CharField(
        max_length=1000
    )

    line = models.PositiveIntegerField(
        null=True,
        blank=True
    )


    # ====================================
    # 취약점 정보
    # ====================================

    message = models.TextField(
        blank=True
    )

    evidence = models.TextField(
        blank=True
    )

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


    def __str__(self):

        return (
            f"{self.rule_id} - "
            f"{self.file_path}"
        )