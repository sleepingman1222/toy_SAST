from django.db.models import Prefetch

from ..models import (
    AnalysisRun,
    Vulnerability,
)
from ..serializers import (
    AnalysisRunSerializer,
)


USER_VULNERABILITY_FIELDS = (
    "id",
    "analysis_language",
    "name",
    "severity",
    "confidence",
    "file_path",
    "line",
    "start_line",
    "start_column",
    "end_line",
    "end_column",
    "message",
    "evidence",
    "recommendation",
)


# ========================================
# AnalysisRun API 응답용 QuerySet 준비
#
# Vulnerability + security_weakness까지
# 미리 가져와 목록 응답의 N+1 조회를 막는다.
# ========================================

def prepare_analysis_response_queryset(
    queryset,
):

    return (
        queryset
        .select_related(
            "project",
            "source_version",
            "executed_by",
        )
        .prefetch_related(
            Prefetch(
                "vulnerabilities",
                queryset=(
                    Vulnerability.objects
                    .select_related(
                        "security_weakness"
                    )
                ),
            )
        )
    )


# ========================================
# Vulnerability 객체 조회
#
# prepare_analysis_response_queryset()로
# prefetch된 경우 DB를 다시 조회하지 않는다.
# 단일 호출 등 prefetch가 없는 경우에만
# 안전한 fallback query를 수행한다.
# ========================================

def _get_vulnerability_objects(
    analysis_run,
):

    prefetched_cache = getattr(
        analysis_run,
        "_prefetched_objects_cache",
        {},
    )

    if "vulnerabilities" in prefetched_cache:

        return list(
            analysis_run
            .vulnerabilities
            .all()
        )

    return list(
        Vulnerability.objects
        .filter(
            analysis_run=analysis_run
        )
        .select_related(
            "security_weakness"
        )
    )


# ========================================
# KISA Catalog 필드 보강
# ========================================

def _enrich_vulnerability_with_kisa(
    vulnerability_payload,
    vulnerability_object,
):

    payload = dict(
        vulnerability_payload
    )

    security_weakness = (
        vulnerability_object
        .security_weakness
        if vulnerability_object is not None
        else None
    )

    payload[
        "security_weakness_identifier"
    ] = (
        payload.get(
            "security_weakness_identifier"
        )
        or
        (
            security_weakness.identifier
            if security_weakness
            else None
        )
    )

    payload[
        "security_weakness_item_number"
    ] = (
        payload.get(
            "security_weakness_item_number"
        )
        or
        (
            security_weakness.item_number
            if security_weakness
            else None
        )
    )

    return payload


# ========================================
# 분석 결과 공통 준비
# ========================================

def _serialize_analysis_with_kisa(
    analysis_run,
):

    serialized = dict(
        AnalysisRunSerializer(
            analysis_run
        ).data
    )

    serialized_vulnerabilities = list(
        serialized.get(
            "vulnerabilities",
            [],
        )
        or []
    )

    if not serialized_vulnerabilities:

        serialized[
            "vulnerabilities"
        ] = []

        return serialized

    vulnerability_objects = (
        _get_vulnerability_objects(
            analysis_run
        )
    )

    vulnerability_by_id = {
        vulnerability.id:
            vulnerability
        for vulnerability
        in vulnerability_objects
    }

    serialized[
        "vulnerabilities"
    ] = [
        _enrich_vulnerability_with_kisa(
            vulnerability_payload,
            vulnerability_by_id.get(
                vulnerability_payload.get(
                    "id"
                )
            ),
        )
        for vulnerability_payload
        in serialized_vulnerabilities
    ]

    return serialized


# ========================================
# 일반 사용자용 완료 분석 응답
#
# 기존 API 계약을 그대로 유지한다.
# 내부 운영정보와 기술 Rule ID 등은 제외한다.
# ========================================

def serialize_user_completed_analysis(
    analysis_run,
):

    serialized = (
        _serialize_analysis_with_kisa(
            analysis_run
        )
    )

    vulnerabilities = [
        {
            field:
                vulnerability.get(
                    field
                )
            for field
            in USER_VULNERABILITY_FIELDS
        }
        |
        {
            "security_weakness_identifier":
                vulnerability.get(
                    "security_weakness_identifier"
                ),

            "security_weakness_item_number":
                vulnerability.get(
                    "security_weakness_item_number"
                ),
        }
        for vulnerability
        in serialized.get(
            "vulnerabilities",
            [],
        )
    ]

    return {
        "id":
            serialized.get(
                "id"
            ),

        "source_version_id":
            serialized.get(
                "source_version_id"
            ),

        "sequence":
            serialized.get(
                "sequence"
            ),

        "status":
            AnalysisRun.Status.COMPLETED,

        "analysis_languages":
            serialized.get(
                "analysis_languages"
            )
            or [],

        "completed_at":
            serialized.get(
                "completed_at"
            ),

        "vulnerabilities":
            vulnerabilities,
    }


# ========================================
# 관리자용 분석 응답
#
# 기존 AnalysisRunSerializer 응답을 유지하고
# KISA Catalog 연결 필드만 보장한다.
# ========================================

def serialize_admin_analysis_with_kisa(
    analysis_run,
):

    return _serialize_analysis_with_kisa(
        analysis_run
    )
