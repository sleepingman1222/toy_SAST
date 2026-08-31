from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


# ========================================
# Project
# ========================================

class Project(models.Model):

    # ====================================
    # 기본 정보
    # ====================================

    name = models.CharField(
        max_length=200
    )

    description = models.TextField(
        blank=True
    )


    # ====================================
    # 프로젝트 등록자
    # ====================================

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,

        on_delete=models.PROTECT,

        related_name="created_projects"
    )


    # ====================================
    # 현재 분석 대상 SourceVersion
    #
    # 프로젝트 생성 직후에는
    # 분석 대상이 없을 수 있으므로
    # null=True
    # ====================================

    current_source_version = models.ForeignKey(
        "SourceVersion",

        on_delete=models.SET_NULL,

        null=True,
        blank=True,

        related_name="+"
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


    def __str__(self):

        return self.name


# ========================================
# SourceVersion
# ========================================

class SourceVersion(models.Model):

    # ====================================
    # Source Type
    # ====================================

    class SourceType(models.TextChoices):

        UPLOAD = (
            "upload",
            "Upload"
        )

        REPOSITORY = (
            "repository",
            "Repository"
        )

        INTERNAL = (
            "internal",
            "Internal Path"
        )


    # ====================================
    # 프로젝트
    # ====================================

    project = models.ForeignKey(
        Project,

        on_delete=models.CASCADE,

        related_name="source_versions"
    )


    # ====================================
    # Version
    #
    # Project별
    # 1, 2, 3 ...
    # ====================================

    version = models.PositiveIntegerField()


    # ====================================
    # 기존 단일 Language
    #
    # [전환용 필드]
    #
    # 기존 데이터 / 기존 코드 호환을 위해
    # 일단 유지한다.
    #
    # 앞으로 신규 SourceVersion의 언어는
    # 관리자가 직접 입력하지 않고
    # Backend가 실제 소스에서 자동 감지한다.
    #
    # 다중 언어 구조가 안정화된 후
    # 이 필드는 제거한다.
    # ====================================

    language = models.CharField(
        max_length=50,

        blank=True,
        default=""
    )


    # ====================================
    # 자동 감지 언어
    #
    # 예:
    #
    # [
    #     "java",
    #     "javascript",
    #     "python",
    # ]
    #
    # 관리자가 직접 입력하는 값이 아니라
    # 실제 분석 대상 소스에서
    # Backend가 자동으로 감지하여 저장한다.
    #
    # JSONField를 사용하는 이유:
    # - 한 SourceVersion에 여러 언어 가능
    # - 향후 언어 확장 용이
    # ====================================

    detected_languages = models.JSONField(
        default=list,
        blank=True
    )


    # ====================================
    # Source Type
    # ====================================

    source_type = models.CharField(
        max_length=20,

        choices=SourceType.choices
    )


    # ====================================
    # Upload
    # ====================================

    source_file = models.FileField(
        upload_to="project_sources/%Y/%m/%d/",

        null=True,
        blank=True
    )


    # ====================================
    # Repository
    # ====================================

    repository_url = models.URLField(
        max_length=500,

        blank=True
    )


    # ====================================
    # Internal Path
    # ====================================

    internal_path = models.CharField(
        max_length=500,

        blank=True
    )


    # ====================================
    # 등록자
    # ====================================

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,

        on_delete=models.PROTECT,

        related_name="created_source_versions"
    )


    # ====================================
    # 등록 일시
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )


    class Meta:

        ordering = [
            "version"
        ]

        constraints = [

            # 같은 프로젝트에서
            # 같은 version 금지

            models.UniqueConstraint(
                fields=[
                    "project",
                    "version"
                ],

                name=
                    "unique_project_source_version"
            ),
        ]


    # ====================================
    # SourceType별 입력값 검사
    # ====================================

    def clean(self):

        super().clean()


        # --------------------------------
        # detected_languages 형식 검사
        #
        # 실제 값은 Backend에서 생성하지만
        # 잘못된 데이터가 DB에 들어가는 것을
        # 방지하기 위한 기본 검증
        # --------------------------------

        if not isinstance(
            self.detected_languages,
            list
        ):

            raise ValidationError({
                "detected_languages":
                    "감지된 언어 정보는 목록 형식이어야 합니다."
            })


        for language in self.detected_languages:

            if (
                not isinstance(
                    language,
                    str
                )
                or
                not language.strip()
            ):

                raise ValidationError({
                    "detected_languages":
                        "감지된 언어는 비어 있지 않은 문자열이어야 합니다."
                })


        # --------------------------------
        # Upload
        # --------------------------------

        if (
            self.source_type
            == self.SourceType.UPLOAD
        ):

            if not self.source_file:

                raise ValidationError({
                    "source_file":
                        "업로드 방식은 소스 파일이 필요합니다."
                })


        # --------------------------------
        # Repository
        # --------------------------------

        elif (
            self.source_type
            == self.SourceType.REPOSITORY
        ):

            if not self.repository_url:

                raise ValidationError({
                    "repository_url":
                        "Repository 방식은 URL이 필요합니다."
                })


        # --------------------------------
        # Internal Path
        # --------------------------------

        elif (
            self.source_type
            == self.SourceType.INTERNAL
        ):

            if not self.internal_path:

                raise ValidationError({
                    "internal_path":
                        "내부 경로 방식은 경로가 필요합니다."
                })


    def __str__(self):

        return (
            f"{self.project.name} "
            f"v{self.version}"
        )


# ========================================
# ProjectAccess
# ========================================

class ProjectAccess(models.Model):

    # ====================================
    # Project
    # ====================================

    project = models.ForeignKey(
        Project,

        on_delete=models.CASCADE,

        related_name="accesses"
    )


    # ====================================
    # 권한을 받은 사용자
    # ====================================

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,

        on_delete=models.CASCADE,

        related_name="project_accesses"
    )


    # ====================================
    # 권한 부여 관리자
    # ====================================

    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,

        on_delete=models.PROTECT,

        related_name="granted_project_accesses"
    )


    # ====================================
    # 권한 부여 일시
    # ====================================

    created_at = models.DateTimeField(
        auto_now_add=True
    )


    class Meta:

        ordering = [
            "-created_at"
        ]

        constraints = [

            # 한 사용자가 동일 프로젝트 권한을
            # 두 번 받을 수 없음

            models.UniqueConstraint(
                fields=[
                    "project",
                    "user"
                ],

                name=
                    "unique_project_user_access"
            ),
        ]


    def __str__(self):

        return (
            f"{self.project.name} - "
            f"{self.user}"
        )