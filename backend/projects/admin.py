from django.contrib import admin

from .models import (
    Project,
    ProjectAccess,
    SourceVersion,
)


# ========================================
# Project Admin
# ========================================

@admin.register(Project)
class ProjectAdmin(
    admin.ModelAdmin
):

    list_display = [
        "id",
        "name",
        "created_by",
        "current_source_version",
        "created_at",
        "updated_at",
    ]

    search_fields = [
        "name",
        "description",
        "created_by__username",
    ]

    list_select_related = [
        "created_by",
        "current_source_version",
    ]

    ordering = [
        "-created_at",
    ]


# ========================================
# SourceVersion Admin
# ========================================

@admin.register(SourceVersion)
class SourceVersionAdmin(
    admin.ModelAdmin
):

    list_display = [
        "id",
        "project",
        "version",
        "language",
        "source_type",
        "created_by",
        "created_at",
    ]

    list_filter = [
        "language",
        "source_type",
    ]

    search_fields = [
        "project__name",
        "language",
        "repository_url",
        "internal_path",
    ]

    list_select_related = [
        "project",
        "created_by",
    ]

    ordering = [
        "project",
        "version",
    ]


# ========================================
# ProjectAccess Admin
# ========================================

@admin.register(ProjectAccess)
class ProjectAccessAdmin(
    admin.ModelAdmin
):

    list_display = [
        "id",
        "project",
        "user",
        "granted_by",
        "created_at",
    ]

    search_fields = [
        "project__name",
        "user__username",
        "granted_by__username",
    ]

    list_select_related = [
        "project",
        "user",
        "granted_by",
    ]

    ordering = [
        "-created_at",
    ]