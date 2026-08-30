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
    # Language
    #
    # Java / JavaScript / Python 등
    #
    # choices로 막지 않는 이유:
    # 앞으로 언어 추가 가능
    # ====================================

    language = models.CharField(
        max_length=50
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