from rest_framework import serializers

from .models import (
    AnalysisRun,
    Vulnerability,
)


# ========================================
# Vulnerability Serializer
# ========================================

class VulnerabilitySerializer(
    serializers.ModelSerializer
):

    class Meta:

        model = Vulnerability

        fields = [
            "id",

            # --------------------------------
            # 탐지 언어
            #
            # 다중 언어 프로젝트에서도
            # 개별 취약점이 어떤 언어에서
            # 탐지되었는지 구분
            # --------------------------------
            "analysis_language",

            "rule_id",
            "name",
            "severity",
            "confidence",
            "file_path",
            "line",
            "message",
            "evidence",
            "recommendation",
            "created_at",
        ]

        read_only_fields = fields


# ========================================
# AnalysisRun Serializer
#
# 조회용
# ========================================

class AnalysisRunSerializer(
    serializers.ModelSerializer
):

    # ------------------------------------
    # Foreign Key ID
    # ------------------------------------

    project_id = serializers.IntegerField(
        read_only=True
    )

    source_version_id = serializers.IntegerField(
        read_only=True
    )

    executed_by_id = serializers.IntegerField(
        read_only=True
    )


    # ------------------------------------
    # 실행자 username
    # ------------------------------------

    executed_by_username = serializers.CharField(
        source="executed_by.username",
        read_only=True
    )


    # ------------------------------------
    # Vulnerability
    # ------------------------------------

    vulnerabilities = VulnerabilitySerializer(
        many=True,
        read_only=True
    )


    # ------------------------------------
    # 분석 결과 요약
    # ------------------------------------

    summary = serializers.SerializerMethodField()


    def get_summary(
        self,
        obj
    ):

        vulnerabilities = list(
            obj.vulnerabilities.all()
        )

        return {
            "total": len(
                vulnerabilities
            ),

            "critical": sum(
                1
                for vulnerability
                in vulnerabilities
                if vulnerability.severity ==
                Vulnerability.Severity.CRITICAL
            ),

            "high": sum(
                1
                for vulnerability
                in vulnerabilities
                if vulnerability.severity ==
                Vulnerability.Severity.HIGH
            ),

            "medium": sum(
                1
                for vulnerability
                in vulnerabilities
                if vulnerability.severity ==
                Vulnerability.Severity.MEDIUM
            ),

            "low": sum(
                1
                for vulnerability
                in vulnerabilities
                if vulnerability.severity ==
                Vulnerability.Severity.LOW
            ),
        }


    class Meta:

        model = AnalysisRun

        fields = [
            "id",
            "project_id",
            "source_version_id",
            "sequence",
            "status",
            "engine",
            "pipeline_version",
            "snapshot_digest",
            "finding_fingerprint_version",

            # --------------------------------
            # 기존 단일 언어 Snapshot
            #
            # 기존 데이터 / 코드 호환을 위해
            # 전환 기간 동안 유지
            # --------------------------------
            "analysis_language",

            # --------------------------------
            # 신규 다중 언어 Snapshot
            #
            # 예:
            # [
            #     "java",
            #     "javascript",
            #     "python",
            # ]
            # --------------------------------
            "analysis_languages",

            "executed_by_id",
            "executed_by_username",
            "started_at",
            "completed_at",
            "failure_reason",
            "logs",
            "summary",
            "vulnerabilities",
            "created_at",
            "updated_at",
        ]

        read_only_fields = fields


# ========================================
# AnalysisRun Create Serializer
#
# POST 요청용
#
# 실제 AnalysisRun 생성은
# View에서 수행한다.
#
# 분석 언어는 요청으로 받지 않는다.
# Backend가 실제 소스를 준비한 뒤
# 자동으로 감지한다.
# ========================================

class AnalysisRunCreateSerializer(
    serializers.Serializer
):

    source_version_id = serializers.IntegerField(
        min_value=1
    )
