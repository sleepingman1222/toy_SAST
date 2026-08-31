from django.conf import settings
from django.db import models


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


# ========================================
# AnalysisRun
# ========================================

class AnalysisRun(models.Model):

    # ====================================
    # Status
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


    # ====================================
    # 기존 단일 분석 언어 Snapshot
    #
    # [전환용 필드]
    #
    # 기존 AnalysisRun 데이터와
    # 기존 코드 호환을 위해 유지한다.
    #
    # 자동 감지 / 다중 언어 구조가
    # 안정화되면 제거한다.
    # ====================================

    analysis_language = models.CharField(
        max_length=50,

        blank=True,
        default=""
    )


    # ====================================
    # 분석 시점 다중 언어 Snapshot
    #
    # SourceVersion의 detected_languages를
    # 그대로 참조하는 것이 아니라
    # 분석 실행 당시의 언어 정보를
    # 별도로 보존한다.
    #
    # 예:
    #
    # [
    #     "java",
    #     "javascript",
    #     "python",
    # ]
    #
    # SourceVersion 정보가 이후 변경되어도
    # 과거 AnalysisRun의 분석 당시 언어는
    # 그대로 유지된다.
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
    # 실패 정보
    # ====================================

    failure_reason = models.TextField(
        blank=True
    )


    # ====================================
    # 분석 로그
    # ====================================

    logs = models.TextField(
        blank=True
    )


    # ====================================
    # Semgrep Raw Result
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
    # KISA 보안약점
    #
    # 현재 기존 Semgrep 분석 데이터에는
    # KISA 매핑 정보가 없으므로
    # null 허용
    #
    # 이후 KISA Rule Set 적용 시
    # 자동 매칭
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
    # AnalysisRun은 여러 언어를 분석할 수 있지만
    # 개별 Vulnerability는 실제 탐지된
    # 소스 파일의 언어 하나를 저장한다.
    #
    # 예:
    #
    # AnalysisRun.analysis_languages
    # [
    #     "javascript",
    #     "python",
    # ]
    #
    # Vulnerability #1
    # analysis_language = "python"
    #
    # Vulnerability #2
    # analysis_language = "javascript"
    #
    # 기존 Vulnerability 데이터에는
    # 언어 정보가 없을 수 있으므로
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


    def __str__(self):

        return (
            f"{self.rule_id} - "
            f"{self.file_path}"
        )