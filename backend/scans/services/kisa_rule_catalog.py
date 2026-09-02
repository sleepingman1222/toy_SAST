import re

from dataclasses import (
    dataclass,
    field,
)
from pathlib import Path

from django.conf import settings

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from scans.models import (
    KisaSecurityWeakness,
)


# ========================================
# KISA Rule Catalog
# ========================================

KISA_RULE_ROOT = (
    Path(settings.BASE_DIR)
    / "semgrep_rules"
    / "kisa"
)


SUPPORTED_RULE_LANGUAGES = (
    "java",
    "javascript",
    "python",
)


RULE_FILE_SUFFIXES = {
    ".yml",
    ".yaml",
}


ALLOWED_SEVERITIES = {
    "ERROR",
    "WARNING",
    "INFO",
}


ALLOWED_CONFIDENCES = {
    "HIGH",
    "MEDIUM",
    "LOW",
}


KISA_IDENTIFIER_PATTERN = re.compile(
    r"^KISA-SW-(\d{2})$"
)


RULE_ID_PATTERN = re.compile(
    (
        r"^kisa\.sw(?P<number>\d{2})\."
        r"(?P<language>java|javascript|python)\."
        r"(?P<slug>[a-z0-9][a-z0-9.-]*)$"
    )
)


REQUIRED_RULE_FIELDS = (
    "id",
    "message",
    "languages",
    "severity",
)


REQUIRED_METADATA_FIELDS = (
    "kisa_identifier",
    "kisa_name",
    "confidence",
    "recommendation",
    "rule_version",
    "kisa_guide_version",
)


# ========================================
# Validation Result
# ========================================

@dataclass
class CatalogMessage:

    level: str
    code: str
    message: str
    file_path: str = ""
    rule_id: str = ""


@dataclass
class CatalogRule:

    file_path: str
    rule_id: str
    language: str
    kisa_identifier: str
    kisa_name: str
    severity: str
    confidence: str
    rule_version: str
    cwe: list[str] = field(
        default_factory=list
    )


@dataclass
class CatalogValidationResult:

    rule_root: str
    master_count: int = 0
    rule_file_count: int = 0
    rule_count: int = 0

    rules: list[CatalogRule] = field(
        default_factory=list
    )

    errors: list[CatalogMessage] = field(
        default_factory=list
    )

    warnings: list[CatalogMessage] = field(
        default_factory=list
    )

    coverage_by_kisa: dict = field(
        default_factory=dict
    )

    coverage_by_language: dict = field(
        default_factory=dict
    )

    @property
    def is_valid(self):

        return (
            len(
                self.errors
            )
            == 0
        )

    @property
    def covered_kisa_count(self):

        return len(
            [
                identifier
                for (
                    identifier,
                    data,
                )
                in self
                .coverage_by_kisa
                .items()
                if data.get(
                    "rule_count",
                    0,
                )
                > 0
            ]
        )


# ========================================
# Helper
# ========================================

def _add_error(
    result,
    code,
    message,
    file_path="",
    rule_id="",
):

    result.errors.append(
        CatalogMessage(
            level="error",
            code=code,
            message=message,
            file_path=file_path,
            rule_id=rule_id,
        )
    )


def _add_warning(
    result,
    code,
    message,
    file_path="",
    rule_id="",
):

    result.warnings.append(
        CatalogMessage(
            level="warning",
            code=code,
            message=message,
            file_path=file_path,
            rule_id=rule_id,
        )
    )


def _normalize_string(
    value,
):

    if value is None:
        return ""

    return str(
        value
    ).strip()


def _normalize_upper(
    value,
):

    return (
        _normalize_string(
            value
        )
        .upper()
    )


def _normalize_cwe(
    value,
):

    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
        values = [
            value
        ]

    elif isinstance(
        value,
        list,
    ):
        values = value

    else:
        return []

    normalized = []

    for item in values:

        item_text = (
            _normalize_string(
                item
            )
            .upper()
        )

        if not item_text:
            continue

        normalized.append(
            item_text
        )

    return normalized


def _is_non_empty_value(
    value,
):

    if value is None:
        return False

    if isinstance(
        value,
        str,
    ):
        return bool(
            value.strip()
        )

    if isinstance(
        value,
        (
            list,
            dict,
            tuple,
        ),
    ):
        return bool(
            value
        )

    return True


# ========================================
# Rule File
# ========================================

def iter_kisa_rule_files(
    rule_root=None,
):

    root = Path(
        rule_root
        or
        KISA_RULE_ROOT
    )

    if not root.exists():
        return []

    rule_files = []

    for language in (
        SUPPORTED_RULE_LANGUAGES
    ):

        language_root = (
            root
            / language
        )

        if not language_root.exists():
            continue

        for path in (
            language_root
            .rglob(
                "*"
            )
        ):

            if not path.is_file():
                continue

            if (
                path.suffix.lower()
                not in
                RULE_FILE_SUFFIXES
            ):
                continue

            rule_files.append(
                path
            )

    return sorted(
        rule_files,
        key=lambda path:
            str(
                path
            ),
    )


# ========================================
# YAML
# ========================================

def load_rule_document(
    file_path,
):

    yaml = YAML(
        typ="safe"
    )

    yaml.allow_duplicate_keys = False

    with Path(
        file_path
    ).open(
        "r",
        encoding="utf-8",
    ) as stream:

        document = yaml.load(
            stream
        )

    return document


# ========================================
# Master Data
# ========================================

def load_kisa_master_map():

    rows = (
        KisaSecurityWeakness.objects
        .all()
        .order_by(
            "item_number"
        )
    )

    return {
        row.identifier:
            row
        for row
        in rows
    }


# ========================================
# Rule Structure
# ========================================

def _validate_rule_structure(
    result,
    rule,
    file_path,
    expected_language,
):

    if not isinstance(
        rule,
        dict,
    ):

        _add_error(
            result,
            "RULE_NOT_OBJECT",
            "Rule 항목은 YAML object여야 합니다.",
            file_path=file_path,
        )

        return None

    rule_id = (
        _normalize_string(
            rule.get(
                "id"
            )
        )
    )

    for field_name in (
        REQUIRED_RULE_FIELDS
    ):

        if not _is_non_empty_value(
            rule.get(
                field_name
            )
        ):

            _add_error(
                result,
                "RULE_REQUIRED_FIELD_MISSING",
                (
                    "필수 Rule 필드가 없습니다. "
                    f"field={field_name}"
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

    if not rule_id:
        return None

    rule_id_match = (
        RULE_ID_PATTERN.match(
            rule_id
        )
    )

    if rule_id_match is None:

        _add_error(
            result,
            "RULE_ID_INVALID",
            (
                "Rule ID 규칙이 올바르지 않습니다. "
                "예: "
                "kisa.sw01.python.dbapi-string-built-query"
            ),
            file_path=file_path,
            rule_id=rule_id,
        )

    else:

        rule_language = (
            rule_id_match.group(
                "language"
            )
        )

        if (
            rule_language
            !=
            expected_language
        ):

            _add_error(
                result,
                "RULE_ID_LANGUAGE_MISMATCH",
                (
                    "Rule ID의 언어와 "
                    "Rule 디렉터리 언어가 다릅니다. "
                    f"id_language={rule_language}, "
                    f"directory_language={expected_language}"
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

    languages = (
        rule.get(
            "languages"
        )
    )

    if not isinstance(
        languages,
        list,
    ):

        _add_error(
            result,
            "RULE_LANGUAGES_INVALID",
            "languages는 YAML list여야 합니다.",
            file_path=file_path,
            rule_id=rule_id,
        )

    else:

        normalized_languages = [
            _normalize_string(
                language
            ).lower()
            for language
            in languages
        ]

        if (
            normalized_languages
            !=
            [
                expected_language
            ]
        ):

            _add_error(
                result,
                "RULE_LANGUAGE_DIRECTORY_MISMATCH",
                (
                    "MVP KISA Rule은 언어 디렉터리와 "
                    "정확히 하나의 Semgrep language가 "
                    "일치해야 합니다. "
                    f"expected=[{expected_language}], "
                    f"actual={normalized_languages}"
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

    severity = (
        _normalize_upper(
            rule.get(
                "severity"
            )
        )
    )

    if (
        severity
        not in
        ALLOWED_SEVERITIES
    ):

        _add_error(
            result,
            "RULE_SEVERITY_INVALID",
            (
                "severity는 ERROR/WARNING/INFO 중 "
                "하나여야 합니다."
            ),
            file_path=file_path,
            rule_id=rule_id,
        )

    has_detection_operator = any(
        field_name
        in rule
        for field_name
        in (
            "pattern",
            "patterns",
            "pattern-either",
            "pattern-regex",
            "pattern-sources",
            "pattern-sinks",
        )
    )

    if not has_detection_operator:

        _add_error(
            result,
            "RULE_DETECTION_OPERATOR_MISSING",
            "Semgrep 탐지 pattern이 없습니다.",
            file_path=file_path,
            rule_id=rule_id,
        )

    return rule_id


# ========================================
# Metadata
# ========================================

def _validate_rule_metadata(
    result,
    rule,
    file_path,
    rule_id,
    expected_language,
    master_map,
):

    metadata = (
        rule.get(
            "metadata"
        )
    )

    if not isinstance(
        metadata,
        dict,
    ):

        _add_error(
            result,
            "RULE_METADATA_MISSING",
            "metadata object가 필요합니다.",
            file_path=file_path,
            rule_id=rule_id,
        )

        return None

    for field_name in (
        REQUIRED_METADATA_FIELDS
    ):

        if not _is_non_empty_value(
            metadata.get(
                field_name
            )
        ):

            _add_error(
                result,
                "METADATA_REQUIRED_FIELD_MISSING",
                (
                    "필수 metadata가 없습니다. "
                    f"field={field_name}"
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

    kisa_identifier = (
        _normalize_string(
            metadata.get(
                "kisa_identifier"
            )
        )
    )

    kisa_name = (
        _normalize_string(
            metadata.get(
                "kisa_name"
            )
        )
    )

    confidence = (
        _normalize_upper(
            metadata.get(
                "confidence"
            )
        )
    )

    rule_version = (
        _normalize_string(
            metadata.get(
                "rule_version"
            )
        )
    )

    guide_version = (
        _normalize_string(
            metadata.get(
                "kisa_guide_version"
            )
        )
    )

    identifier_match = (
        KISA_IDENTIFIER_PATTERN.match(
            kisa_identifier
        )
    )

    if identifier_match is None:

        _add_error(
            result,
            "KISA_IDENTIFIER_INVALID",
            (
                "kisa_identifier 형식은 "
                "KISA-SW-01 ~ KISA-SW-49여야 합니다."
            ),
            file_path=file_path,
            rule_id=rule_id,
        )

    else:

        item_number = int(
            identifier_match.group(
                1
            )
        )

        if (
            item_number < 1
            or
            item_number > 49
        ):

            _add_error(
                result,
                "KISA_IDENTIFIER_OUT_OF_RANGE",
                (
                    "KISA item number는 "
                    "1~49 범위여야 합니다."
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

        rule_id_match = (
            RULE_ID_PATTERN.match(
                rule_id
            )
        )

        if rule_id_match is not None:

            rule_item_number = int(
                rule_id_match.group(
                    "number"
                )
            )

            if (
                rule_item_number
                !=
                item_number
            ):

                _add_error(
                    result,
                    "RULE_ID_KISA_MISMATCH",
                    (
                        "Rule ID의 KISA 번호와 "
                        "metadata.kisa_identifier가 다릅니다."
                    ),
                    file_path=file_path,
                    rule_id=rule_id,
                )

    master = (
        master_map.get(
            kisa_identifier
        )
    )

    if master is None:

        _add_error(
            result,
            "KISA_MASTER_NOT_FOUND",
            (
                "DB KISA Master Data에 "
                "해당 identifier가 없습니다. "
                f"identifier={kisa_identifier}"
            ),
            file_path=file_path,
            rule_id=rule_id,
        )

    else:

        if (
            kisa_name
            !=
            master.name
        ):

            _add_error(
                result,
                "KISA_NAME_MISMATCH",
                (
                    "metadata.kisa_name과 "
                    "DB Master의 이름이 다릅니다. "
                    f"metadata={kisa_name!r}, "
                    f"master={master.name!r}"
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

    if (
        confidence
        not in
        ALLOWED_CONFIDENCES
    ):

        _add_error(
            result,
            "CONFIDENCE_INVALID",
            (
                "confidence는 "
                "HIGH/MEDIUM/LOW 중 하나여야 합니다."
            ),
            file_path=file_path,
            rule_id=rule_id,
        )

    if not rule_version:

        _add_error(
            result,
            "RULE_VERSION_MISSING",
            "rule_version이 필요합니다.",
            file_path=file_path,
            rule_id=rule_id,
        )

    if (
        guide_version
        !=
        "2021.12.29"
    ):

        _add_warning(
            result,
            "KISA_GUIDE_VERSION_UNEXPECTED",
            (
                "현재 프로젝트 기준 KISA Guide version은 "
                "2021.12.29입니다. "
                f"actual={guide_version!r}"
            ),
            file_path=file_path,
            rule_id=rule_id,
        )

    cwe_values = (
        _normalize_cwe(
            metadata.get(
                "cwe"
            )
        )
    )

    for cwe in cwe_values:

        if not re.match(
            r"^CWE-\d+$",
            cwe,
        ):

            _add_error(
                result,
                "CWE_INVALID",
                (
                    "CWE 형식은 CWE-숫자 형태여야 합니다. "
                    f"value={cwe}"
                ),
                file_path=file_path,
                rule_id=rule_id,
            )

    return CatalogRule(
        file_path=
            file_path,

        rule_id=
            rule_id,

        language=
            expected_language,

        kisa_identifier=
            kisa_identifier,

        kisa_name=
            kisa_name,

        severity=
            _normalize_upper(
                rule.get(
                    "severity"
                )
            ),

        confidence=
            confidence,

        rule_version=
            rule_version,

        cwe=
            cwe_values,
    )


# ========================================
# Coverage
# ========================================

def _build_coverage(
    result,
    master_map,
):

    coverage_by_kisa = {}

    for (
        identifier,
        master,
    ) in master_map.items():

        coverage_by_kisa[
            identifier
        ] = {
            "identifier":
                identifier,

            "item_number":
                master.item_number,

            "category":
                master.category,

            "name":
                master.name,

            "implementation_status":
                master.implementation_status,

            "rule_count":
                0,

            "languages": {
                language: 0
                for language
                in SUPPORTED_RULE_LANGUAGES
            },
        }

    coverage_by_language = {
        language: 0
        for language
        in SUPPORTED_RULE_LANGUAGES
    }

    for rule in result.rules:

        coverage = (
            coverage_by_kisa.get(
                rule.kisa_identifier
            )
        )

        if coverage is not None:

            coverage[
                "rule_count"
            ] += 1

            coverage[
                "languages"
            ][
                rule.language
            ] += 1

        coverage_by_language[
            rule.language
        ] += 1

    result.coverage_by_kisa = (
        coverage_by_kisa
    )

    result.coverage_by_language = (
        coverage_by_language
    )


# ========================================
# Catalog Validation
# ========================================

def validate_kisa_rule_catalog(
    rule_root=None,
    require_full_master=True,
    require_full_coverage=False,
):

    root = Path(
        rule_root
        or
        KISA_RULE_ROOT
    )

    result = (
        CatalogValidationResult(
            rule_root=
                str(
                    root
                )
        )
    )

    master_map = (
        load_kisa_master_map()
    )

    result.master_count = len(
        master_map
    )

    if (
        require_full_master
        and
        result.master_count
        !=
        49
    ):

        _add_error(
            result,
            "KISA_MASTER_COUNT_INVALID",
            (
                "KISA Master Data는 49개여야 합니다. "
                f"actual={result.master_count}"
            ),
        )

    if not root.exists():

        _add_error(
            result,
            "RULE_ROOT_NOT_FOUND",
            (
                "KISA Semgrep Rule Root가 없습니다. "
                f"path={root}"
            ),
        )

        _build_coverage(
            result,
            master_map,
        )

        return result

    rule_files = (
        iter_kisa_rule_files(
            root
        )
    )

    result.rule_file_count = len(
        rule_files
    )

    seen_rule_ids = {}

    for rule_file in rule_files:

        try:

            relative_path = str(
                rule_file.relative_to(
                    root
                )
            )

        except ValueError:

            relative_path = str(
                rule_file
            )

        try:

            expected_language = (
                rule_file
                .relative_to(
                    root
                )
                .parts[0]
            )

        except (
            ValueError,
            IndexError,
        ):

            _add_error(
                result,
                "RULE_FILE_LANGUAGE_UNKNOWN",
                (
                    "Rule 파일의 언어 디렉터리를 "
                    "확인할 수 없습니다."
                ),
                file_path=
                    relative_path,
            )

            continue

        if (
            expected_language
            not in
            SUPPORTED_RULE_LANGUAGES
        ):

            _add_error(
                result,
                "RULE_FILE_LANGUAGE_UNSUPPORTED",
                (
                    "지원하지 않는 Rule 언어 디렉터리입니다. "
                    f"language={expected_language}"
                ),
                file_path=
                    relative_path,
            )

            continue

        try:

            document = (
                load_rule_document(
                    rule_file
                )
            )

        except (
            OSError,
            YAMLError,
            Exception,
        ) as error:

            _add_error(
                result,
                "RULE_YAML_PARSE_FAILED",
                (
                    "Rule YAML을 읽을 수 없습니다. "
                    f"error={error}"
                ),
                file_path=
                    relative_path,
            )

            continue

        if not isinstance(
            document,
            dict,
        ):

            _add_error(
                result,
                "RULE_DOCUMENT_INVALID",
                "YAML 최상위 값은 object여야 합니다.",
                file_path=
                    relative_path,
            )

            continue

        rules = document.get(
            "rules"
        )

        if not isinstance(
            rules,
            list,
        ):

            _add_error(
                result,
                "RULES_LIST_MISSING",
                "최상위 rules list가 필요합니다.",
                file_path=
                    relative_path,
            )

            continue

        for rule in rules:

            rule_id = (
                _validate_rule_structure(
                    result,
                    rule,
                    relative_path,
                    expected_language,
                )
            )

            if not rule_id:
                continue

            if (
                rule_id
                in
                seen_rule_ids
            ):

                _add_error(
                    result,
                    "RULE_ID_DUPLICATED",
                    (
                        "Rule ID가 중복되었습니다. "
                        f"first={seen_rule_ids[rule_id]}"
                    ),
                    file_path=
                        relative_path,
                    rule_id=
                        rule_id,
                )

            else:

                seen_rule_ids[
                    rule_id
                ] = relative_path

            catalog_rule = (
                _validate_rule_metadata(
                    result,
                    rule,
                    relative_path,
                    rule_id,
                    expected_language,
                    master_map,
                )
            )

            if catalog_rule is not None:

                result.rules.append(
                    catalog_rule
                )

    result.rule_count = len(
        result.rules
    )

    _build_coverage(
        result,
        master_map,
    )

    if require_full_coverage:

        uncovered = [
            identifier
            for (
                identifier,
                coverage,
            )
            in result
            .coverage_by_kisa
            .items()
            if coverage.get(
                "rule_count",
                0,
            )
            == 0
        ]

        if uncovered:

            _add_error(
                result,
                "KISA_FULL_COVERAGE_MISSING",
                (
                    "자동 Rule이 하나도 없는 "
                    "KISA 항목이 존재합니다. "
                    f"count={len(uncovered)}, "
                    f"items={','.join(uncovered)}"
                ),
            )

    return result


# ========================================
# Serializable Report
# ========================================

def build_catalog_report(
    result,
):

    return {
        "valid":
            result.is_valid,

        "rule_root":
            result.rule_root,

        "master_count":
            result.master_count,

        "rule_file_count":
            result.rule_file_count,

        "rule_count":
            result.rule_count,

        "covered_kisa_count":
            result.covered_kisa_count,

        "coverage_by_language":
            result.coverage_by_language,

        "coverage_by_kisa":
            result.coverage_by_kisa,

        "errors": [
            {
                "code":
                    item.code,

                "message":
                    item.message,

                "file_path":
                    item.file_path,

                "rule_id":
                    item.rule_id,
            }
            for item
            in result.errors
        ],

        "warnings": [
            {
                "code":
                    item.code,

                "message":
                    item.message,

                "file_path":
                    item.file_path,

                "rule_id":
                    item.rule_id,
            }
            for item
            in result.warnings
        ],
    }
