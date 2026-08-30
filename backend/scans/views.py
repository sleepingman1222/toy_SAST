from django.db import transaction
from django.db.models import Max
from django.shortcuts import get_object_or_404

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from projects.models import (
    Project,
    ProjectAccess,
    SourceVersion,
)

from .models import AnalysisRun

from .serializers import (
    AnalysisRunCreateSerializer,
    AnalysisRunSerializer,
)


# ========================================
# Project 접근 권한 확인
#
# 관리자
# → 모든 프로젝트 조회 가능
#
# 일반 사용자
# → ProjectAccess가 있어야 조회 가능
# ========================================

def can_view_project(
    user,
    project
):

    if user.is_staff:
        return True

    return ProjectAccess.objects.filter(
        project=project,
        user=user
    ).exists()


# ========================================
# AnalysisRun 목록 / 생성
#
# GET
# /api/projects/{project_id}/analyses/
#
# POST
# /api/projects/{project_id}/analyses/
# ========================================

class ProjectAnalysisRunListCreateView(
    APIView
):

    permission_classes = [
        IsAuthenticated
    ]


    # ====================================
    # AnalysisRun 목록 조회
    # ====================================

    def get(
        self,
        request,
        project_id
    ):

        project = get_object_or_404(
            Project,
            pk=project_id
        )


        # --------------------------------
        # 프로젝트 접근 권한 확인
        # --------------------------------

        if not can_view_project(
            request.user,
            project
        ):

            return Response(
                {
                    "detail":
                        "이 프로젝트의 분석 결과를 조회할 권한이 없습니다."
                },
                status=status.HTTP_403_FORBIDDEN
            )


        # --------------------------------
        # 프로젝트 AnalysisRun 조회
        # --------------------------------

        analysis_runs = (
            AnalysisRun.objects
            .filter(
                project=project
            )
            .select_related(
                "project",
                "source_version",
                "executed_by"
            )
            .prefetch_related(
                "vulnerabilities"
            )
            .order_by(
                "sequence"
            )
        )


        # --------------------------------
        # 일반 사용자
        #
        # completed만 조회 가능
        # --------------------------------

        if not request.user.is_staff:

            analysis_runs = (
                analysis_runs.filter(
                    status=
                        AnalysisRun.Status.COMPLETED
                )
            )


        serializer = AnalysisRunSerializer(
            analysis_runs,
            many=True
        )


        return Response(
            serializer.data,
            status=status.HTTP_200_OK
        )


    # ====================================
    # AnalysisRun 생성
    # ====================================

    def post(
        self,
        request,
        project_id
    ):

        # --------------------------------
        # 관리자만 분석 실행 가능
        # --------------------------------

        if not request.user.is_staff:

            return Response(
                {
                    "detail":
                        "분석 실행은 관리자만 할 수 있습니다."
                },
                status=status.HTTP_403_FORBIDDEN
            )


        # --------------------------------
        # 요청 데이터 검증
        # --------------------------------

        input_serializer = (
            AnalysisRunCreateSerializer(
                data=request.data
            )
        )

        input_serializer.is_valid(
            raise_exception=True
        )


        source_version_id = (
            input_serializer
            .validated_data[
                "source_version_id"
            ]
        )


        # --------------------------------
        # Project 존재 확인
        #
        # 여기서는 아직 lock하지 않음
        # --------------------------------

        project = get_object_or_404(
            Project,
            pk=project_id
        )


        # =================================
        # Transaction
        #
        # 같은 Project에서 동시에
        # AnalysisRun을 만드는 것을 방지
        # =================================

        with transaction.atomic():

            # -----------------------------
            # Project row lock
            # -----------------------------

            locked_project = (
                Project.objects
                .select_for_update()
                .get(
                    pk=project.pk
                )
            )


            # -----------------------------
            # 현재 분석 대상 존재 확인
            # -----------------------------

            if (
                locked_project
                .current_source_version_id
                is None
            ):

                return Response(
                    {
                        "detail":
                            "등록된 분석 대상이 없습니다."
                    },
                    status=
                        status.HTTP_400_BAD_REQUEST
                )


            # -----------------------------
            # 요청한 SourceVersion 조회
            #
            # 반드시 해당 Project 소속이어야 함
            # -----------------------------

            source_version = (
                SourceVersion.objects
                .select_for_update()
                .filter(
                    pk=source_version_id,
                    project=locked_project
                )
                .first()
            )


            if source_version is None:

                return Response(
                    {
                        "source_version_id": [
                            "이 프로젝트에 속한 SourceVersion을 찾을 수 없습니다."
                        ]
                    },
                    status=
                        status.HTTP_400_BAD_REQUEST
                )


            # -----------------------------
            # 현재 SourceVersion만
            # 분석 실행 가능
            # -----------------------------

            if (
                locked_project
                .current_source_version_id
                !=
                source_version.id
            ):

                return Response(
                    {
                        "detail":
                            "현재 분석 대상이 아닌 과거 SourceVersion은 분석할 수 없습니다."
                    },
                    status=
                        status.HTTP_409_CONFLICT
                )


            # -----------------------------
            # Project에 pending/running
            # AnalysisRun이 존재하면 차단
            # -----------------------------

            active_analysis_exists = (
                AnalysisRun.objects
                .filter(
                    project=
                        locked_project,

                    status__in=[
                        AnalysisRun.Status.PENDING,
                        AnalysisRun.Status.RUNNING,
                    ]
                )
                .exists()
            )


            if active_analysis_exists:

                return Response(
                    {
                        "detail":
                            "현재 대기 또는 진행 중인 분석이 있습니다."
                    },
                    status=
                        status.HTTP_409_CONFLICT
                )


            # -----------------------------
            # 한 SourceVersion은
            # 한 번만 분석
            #
            # AnalysisRun이 하나라도 생기면
            # 해당 SourceVersion은 동결
            # -----------------------------

            source_already_analyzed = (
                AnalysisRun.objects
                .filter(
                    source_version=
                        source_version
                )
                .exists()
            )


            if source_already_analyzed:

                return Response(
                    {
                        "detail":
                            "이미 분석이 실행된 SourceVersion입니다. 새 분석 대상을 등록해주세요."
                    },
                    status=
                        status.HTTP_409_CONFLICT
                )


            # -----------------------------
            # 다음 Analysis sequence 계산
            #
            # Project 단위
            #
            # Analysis #1
            # Analysis #2
            # ...
            # -----------------------------

            sequence_result = (
                AnalysisRun.objects
                .filter(
                    project=
                        locked_project
                )
                .aggregate(
                    max_sequence=
                        Max(
                            "sequence"
                        )
                )
            )


            max_sequence = (
                sequence_result[
                    "max_sequence"
                ]
                or 0
            )


            next_sequence = (
                max_sequence + 1
            )


            # -----------------------------
            # AnalysisRun 생성
            #
            # 실제 Semgrep은 아직 실행하지 않음
            #
            # Celery 연결 전이므로
            # status=pending까지만 생성
            # -----------------------------

            analysis_run = (
                AnalysisRun.objects.create(
                    project=
                        locked_project,

                    source_version=
                        source_version,

                    sequence=
                        next_sequence,

                    status=
                        AnalysisRun.Status.PENDING,

                    engine=
                        "Semgrep",

                    analysis_language=
                        source_version.language,

                    executed_by=
                        request.user,
                )
            )


        # --------------------------------
        # 생성 결과 반환
        # --------------------------------

        analysis_run = (
            AnalysisRun.objects
            .select_related(
                "project",
                "source_version",
                "executed_by"
            )
            .prefetch_related(
                "vulnerabilities"
            )
            .get(
                pk=analysis_run.pk
            )
        )


        output_serializer = (
            AnalysisRunSerializer(
                analysis_run
            )
        )


        return Response(
            output_serializer.data,
            status=status.HTTP_201_CREATED
        )


# ========================================
# AnalysisRun 상세 조회
#
# GET
# /api/projects/{project_id}/analyses/{analysis_id}/
# ========================================

class ProjectAnalysisRunDetailView(
    APIView
):

    permission_classes = [
        IsAuthenticated
    ]


    def get(
        self,
        request,
        project_id,
        analysis_id
    ):

        # --------------------------------
        # Project 조회
        # --------------------------------

        project = get_object_or_404(
            Project,
            pk=project_id
        )


        # --------------------------------
        # 프로젝트 접근 권한 확인
        # --------------------------------

        if not can_view_project(
            request.user,
            project
        ):

            return Response(
                {
                    "detail":
                        "이 프로젝트의 분석 결과를 조회할 권한이 없습니다."
                },
                status=status.HTTP_403_FORBIDDEN
            )


        # --------------------------------
        # AnalysisRun 조회
        #
        # project_id까지 함께 검사
        # --------------------------------

        analysis_run = get_object_or_404(
            AnalysisRun.objects
            .select_related(
                "project",
                "source_version",
                "executed_by"
            )
            .prefetch_related(
                "vulnerabilities"
            ),

            pk=analysis_id,
            project=project
        )


        # --------------------------------
        # 일반 사용자
        #
        # completed 분석만 조회 가능
        # --------------------------------

        if (
            not request.user.is_staff
            and
            analysis_run.status
            !=
            AnalysisRun.Status.COMPLETED
        ):

            return Response(
                {
                    "detail":
                        "완료되지 않은 분석은 조회할 수 없습니다."
                },
                status=status.HTTP_403_FORBIDDEN
            )


        serializer = AnalysisRunSerializer(
            analysis_run
        )


        return Response(
            serializer.data,
            status=status.HTTP_200_OK
        )