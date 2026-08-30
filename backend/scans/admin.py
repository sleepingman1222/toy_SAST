from django.contrib import admin

from .models import (
    AnalysisRun,
    Vulnerability,
)


# ========================================
# AnalysisRun Admin
# ========================================

@admin.register(AnalysisRun)
class AnalysisRunAdmin(
    admin.ModelAdmin
):

    list_display = [
        "id",
        "project",
        "sequence",
        "source_version",
        "status",
        "engine",
        "analysis_language",
        "executed_by",
        "started_at",
        "completed_at",
        "created_at",
    ]

    list_filter = [
        "status",
        "engine",
        "analysis_language",
    ]

    search_fields = [
        "project__name",
        "source_version__project__name",
        "executed_by__username",
    ]

    list_select_related = [
        "project",
        "source_version",
        "executed_by",
    ]

    ordering = [
        "-created_at",
    ]


# ========================================
# Vulnerability Admin
# ========================================

@admin.register(Vulnerability)
class VulnerabilityAdmin(
    admin.ModelAdmin
):

    list_display = [
        "id",
        "analysis_run",
        "rule_id",
        "name",
        "severity",
        "confidence",
        "file_path",
        "line",
    ]

    list_filter = [
        "severity",
        "confidence",
    ]

    search_fields = [
        "rule_id",
        "name",
        "file_path",
        "message",
    ]

    list_select_related = [
        "analysis_run",
    ]