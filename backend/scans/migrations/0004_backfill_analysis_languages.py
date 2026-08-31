from django.db import migrations


# ========================================
# 기존 단일 언어 정규화
# ========================================

def normalize_language(value):

    normalized = (
        value
        or ""
    ).strip().lower()


    language_mapping = {
        "python": "python",
        "py": "python",

        "javascript": "javascript",
        "java script": "javascript",
        "js": "javascript",

        "java": "java",
    }


    return language_mapping.get(
        normalized,
        ""
    )


# ========================================
# Forward
#
# 기존:
#
# AnalysisRun.analysis_language
# = "Python"
#
# 신규:
#
# AnalysisRun.analysis_languages
# = ["python"]
#
#
# 기존 Vulnerability도
# 연결된 AnalysisRun의 기존 언어를
# 기준으로 언어를 채운다.
# ========================================

def forwards(
    apps,
    schema_editor,
):

    AnalysisRun = apps.get_model(
        "scans",
        "AnalysisRun",
    )

    Vulnerability = apps.get_model(
        "scans",
        "Vulnerability",
    )


    # ====================================
    # AnalysisRun
    # ====================================

    for analysis_run in (
        AnalysisRun.objects.all()
        .iterator()
    ):

        language = normalize_language(
            analysis_run.analysis_language
        )


        # 기존 값이 없다면
        # 새 필드에만 이전

        if (
            not analysis_run.analysis_languages
            and
            language
        ):

            analysis_run.analysis_languages = [
                language
            ]


            analysis_run.save(
                update_fields=[
                    "analysis_languages",
                ]
            )


    # ====================================
    # Vulnerability
    #
    # 기존 시스템에서는 AnalysisRun 하나가
    # 단일 분석 언어를 가졌으므로
    # 그 값을 기존 취약점에 상속한다.
    # ====================================

    vulnerabilities = (
        Vulnerability.objects
        .select_related(
            "analysis_run"
        )
        .all()
        .iterator()
    )


    for vulnerability in vulnerabilities:

        if vulnerability.analysis_language:
            continue


        analysis_run = (
            vulnerability.analysis_run
        )


        language = normalize_language(
            analysis_run.analysis_language
        )


        if not language:
            continue


        vulnerability.analysis_language = (
            language
        )


        vulnerability.save(
            update_fields=[
                "analysis_language",
            ]
        )


# ========================================
# Reverse
#
# 기존 analysis_language는
# 삭제하지 않았으므로 그대로 유지한다.
#
# 새 필드만 초기화한다.
# ========================================

def backwards(
    apps,
    schema_editor,
):

    AnalysisRun = apps.get_model(
        "scans",
        "AnalysisRun",
    )

    Vulnerability = apps.get_model(
        "scans",
        "Vulnerability",
    )


    AnalysisRun.objects.update(
        analysis_languages=[]
    )


    Vulnerability.objects.update(
        analysis_language=""
    )


class Migration(migrations.Migration):

    dependencies = [
        (
            "scans",
            "0003_analysisrun_analysis_languages_and_more",
        ),
    ]


    operations = [
        migrations.RunPython(
            forwards,
            backwards,
        ),
    ]
