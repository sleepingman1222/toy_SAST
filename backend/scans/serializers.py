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
            "analysis_language",
            "executed_by_id",
            "executed_by_username",
            "started_at",
            "completed_at",
            "failure_reason",
            "logs",
            "raw_result",
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
# ========================================

class AnalysisRunCreateSerializer(
    serializers.Serializer
):

    source_version_id = serializers.IntegerField(
        min_value=1
    )