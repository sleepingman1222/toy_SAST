# backend/scans/services/semgrep_executor.py

from pathlib import (
    Path,
)

from django.conf import (
    settings,
)

from .language_detection import (
    normalize_language_name,
)


# ========================================
# Semgrep 실행 제한
#
# Chunk runtime에서 heartbeat 기반 subprocess
# timeout에 사용한다.
# ========================================

SEMGREP_TIMEOUT = 300


# ========================================
# Semgrep Rule Root
# ========================================

SEMGREP_RULE_ROOT = (
    Path(settings.BASE_DIR)
    / "semgrep_rules"
    / "kisa"
)


def get_semgrep_rule_path(
    language
):

    language = (
        normalize_language_name(
            language
        )
    )


    if not language:

        raise RuntimeError(
            "지원하지 않는 분석 언어입니다."
        )


    rule_path = (
        SEMGREP_RULE_ROOT
        / language
    )


    if (
        not rule_path.exists()
        or
        not rule_path.is_dir()
    ):

        raise RuntimeError(
            "자동 감지된 언어의 KISA Custom Rule이 "
            "아직 준비되지 않았습니다. "
            f"language={language}, "
            f"rule_path={rule_path}"
        )


    return rule_path
