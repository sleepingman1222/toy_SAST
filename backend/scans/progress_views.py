from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from projects.models import Project

from .models import AnalysisRun
from .services.analysis_progress import (
    build_analysis_progress,
)


# ========================================
# Analysis Chunk Progress
#
# GET
# /api/projects/{project_id}/analyses/{analysis_id}/progress/
#
# 관리자 전용 Read-only API
# ========================================

class ProjectAnalysisProgressView(
    APIView
):

    permission_classes = [
        IsAuthenticated
    ]


    def get(
        self,
        request,
        project_id,
        analysis_id,
    ):

        # --------------------------------
        # Chunk / Retry / Worker 상태는
        # 내부 운영 정보이므로 관리자만 조회.
        # --------------------------------

        if not request.user.is_staff:

            return Response(
                {
                    "detail":
                        "분석 Chunk 진행 정보는 관리자만 조회할 수 있습니다."
                },
                status=
                    status.HTTP_403_FORBIDDEN,
            )


        project = get_object_or_404(
            Project,
            pk=project_id,
        )


        # --------------------------------
        # AnalysisRun과 Chunk를 한 번에 준비.
        # Service는 DB 상태를 변경하지 않는다.
        # --------------------------------

        analysis_run = get_object_or_404(
            AnalysisRun.objects
            .prefetch_related(
                "analysis_chunks"
            ),
            pk=analysis_id,
            project=project,
        )


        progress = (
            build_analysis_progress(
                analysis_run
            )
        )


        return Response(
            progress,
            status=status.HTTP_200_OK,
        )
