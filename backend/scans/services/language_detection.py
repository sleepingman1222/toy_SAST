# backend/scans/services/language_detection.py

from django.db import (
    transaction,
)

from projects.models import (
    SourceVersion,
)

from ..constants import (
    LANGUAGE_ALIASES,
    LANGUAGE_DISPLAY_NAMES,
)

from ..models import (
    AnalysisRun,
)


def normalize_language_name(
    value
):

    normalized = (
        str(
            value
            or ""
        )
        .strip()
        .lower()
    )


    return (
        LANGUAGE_ALIASES.get(
            normalized,
            ""
        )
    )

def get_legacy_language_value(
    languages
):

    return ", ".join(
        LANGUAGE_DISPLAY_NAMES.get(
            language,
            language
        )

        for language
        in languages
    )

def save_detected_languages(
    source_version,
    analysis_run_id,
    detected_languages
):

    legacy_language = (
        get_legacy_language_value(
            detected_languages
        )
    )


    with transaction.atomic():

        locked_source_version = (
            SourceVersion.objects
            .select_for_update()
            .get(
                pk=
                    source_version.pk
            )
        )


        locked_source_version.detected_languages = (
            list(
                detected_languages
            )
        )

        locked_source_version.language = (
            legacy_language
        )


        locked_source_version.save(
            update_fields=[
                "detected_languages",
                "language",
            ]
        )


        locked_analysis_run = (
            AnalysisRun.objects
            .select_for_update()
            .get(
                pk=
                    analysis_run_id
            )
        )


        locked_analysis_run.analysis_languages = (
            list(
                detected_languages
            )
        )

        locked_analysis_run.analysis_language = (
            legacy_language
        )


        locked_analysis_run.save(
            update_fields=[
                "analysis_languages",
                "analysis_language",
                "updated_at",
            ]
        )
