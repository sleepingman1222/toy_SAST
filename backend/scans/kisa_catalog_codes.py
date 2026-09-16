"""
KISA 구현단계 보안약점 서비스 카탈로그 코드.

중요:
- item_number는 KISA 원본 전체 순번 1~49를 유지한다.
- identifier는 서비스에서 사용하는 카테고리 기반 코드다.
- Semgrep Rule ID의 kisa.swNN은 원본 전체 순번을 유지한다.

예:
    item_number=1  -> KISA-INP-01
    item_number=23 -> KISA-SEC-06
    item_number=49 -> KISA-API-02
"""

import re


KISA_CATEGORY_CODE_SCHEMES = (
    {
        "category": "입력데이터 검증 및 표현",
        "prefix": "INP",
        "start_item_number": 1,
        "end_item_number": 17,
    },
    {
        "category": "보안기능",
        "prefix": "SEC",
        "start_item_number": 18,
        "end_item_number": 33,
    },
    {
        "category": "시간 및 상태",
        "prefix": "TIM",
        "start_item_number": 34,
        "end_item_number": 35,
    },
    {
        "category": "에러처리",
        "prefix": "ERR",
        "start_item_number": 36,
        "end_item_number": 38,
    },
    {
        "category": "코드오류",
        "prefix": "COD",
        "start_item_number": 39,
        "end_item_number": 43,
    },
    {
        "category": "캡슐화",
        "prefix": "ENC",
        "start_item_number": 44,
        "end_item_number": 47,
    },
    {
        "category": "API 오용",
        "prefix": "API",
        "start_item_number": 48,
        "end_item_number": 49,
    },
)


def _build_maps():

    identifier_by_item_number = {}
    category_by_item_number = {}
    item_number_by_identifier = {}

    for scheme in KISA_CATEGORY_CODE_SCHEMES:

        category = scheme["category"]
        prefix = scheme["prefix"]
        start = scheme["start_item_number"]
        end = scheme["end_item_number"]

        for item_number in range(
            start,
            end + 1,
        ):

            local_number = (
                item_number
                - start
                + 1
            )

            identifier = (
                f"KISA-{prefix}-{local_number:02d}"
            )

            identifier_by_item_number[
                item_number
            ] = identifier

            category_by_item_number[
                item_number
            ] = category

            item_number_by_identifier[
                identifier
            ] = item_number

    return (
        identifier_by_item_number,
        category_by_item_number,
        item_number_by_identifier,
    )


(
    KISA_IDENTIFIER_BY_ITEM_NUMBER,
    KISA_CATEGORY_BY_ITEM_NUMBER,
    KISA_ITEM_NUMBER_BY_IDENTIFIER,
) = _build_maps()


KISA_CATALOG_IDENTIFIER_PATTERN = re.compile(
    r"^KISA-(INP|SEC|TIM|ERR|COD|ENC|API)-(\d{2})$"
)


def get_kisa_catalog_identifier(
    item_number,
):

    try:
        normalized_item_number = int(
            item_number
        )
    except (
        TypeError,
        ValueError,
    ) as exc:

        raise ValueError(
            "KISA item_number는 정수여야 합니다."
        ) from exc

    try:
        return (
            KISA_IDENTIFIER_BY_ITEM_NUMBER[
                normalized_item_number
            ]
        )
    except KeyError as exc:

        raise ValueError(
            "KISA item_number는 1~49 범위여야 합니다."
        ) from exc


def get_kisa_category(
    item_number,
):

    normalized_item_number = int(
        item_number
    )

    try:
        return (
            KISA_CATEGORY_BY_ITEM_NUMBER[
                normalized_item_number
            ]
        )
    except KeyError as exc:

        raise ValueError(
            "KISA item_number는 1~49 범위여야 합니다."
        ) from exc


def get_kisa_item_number(
    identifier,
):

    normalized_identifier = str(
        identifier or ""
    ).strip()

    try:
        return (
            KISA_ITEM_NUMBER_BY_IDENTIFIER[
                normalized_identifier
            ]
        )
    except KeyError as exc:

        raise ValueError(
            "등록되지 않은 KISA 카탈로그 코드입니다. "
            f"identifier={normalized_identifier!r}"
        ) from exc
