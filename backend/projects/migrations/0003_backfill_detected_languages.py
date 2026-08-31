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
# SourceVersion.language = "Python"
#
# 신규:
#
# SourceVersion.detected_languages
# = ["python"]
# ========================================

def forwards(
    apps,
    schema_editor,
):

    SourceVersion = apps.get_model(
        "projects",
        "SourceVersion",
    )


    for source_version in (
        SourceVersion.objects.all()
        .iterator()
    ):

        # 이미 새 값이 존재한다면
        # 덮어쓰지 않는다.

        if source_version.detected_languages:
            continue


        language = normalize_language(
            source_version.language
        )


        if language:

            source_version.detected_languages = [
                language
            ]

        else:

            source_version.detected_languages = []


        source_version.save(
            update_fields=[
                "detected_languages",
            ]
        )


# ========================================
# Reverse
#
# 새 배열 데이터만 제거한다.
#
# 기존 language는 애초에 삭제하지 않았으므로
# 복원 작업이 필요하지 않다.
# ========================================

def backwards(
    apps,
    schema_editor,
):

    SourceVersion = apps.get_model(
        "projects",
        "SourceVersion",
    )


    SourceVersion.objects.update(
        detected_languages=[]
    )


class Migration(migrations.Migration):

    dependencies = [
        (
            "projects",
            "0002_sourceversion_detected_languages_and_more",
        ),
    ]


    operations = [
        migrations.RunPython(
            forwards,
            backwards,
        ),
    ]
