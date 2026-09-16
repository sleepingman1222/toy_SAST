from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import (
    Count,
    Max,
    OuterRef,
    Subquery,
)
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

from .models import (
    AnalysisRun,
)

from .serializers import (
    AnalysisRunCreateSerializer,
)

from .services.analysis_response import (
    prepare_analysis_response_queryset,
    serialize_admin_analysis_with_kisa,
    serialize_user_completed_analysis,
)
from .tasks import run_analysis


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
            prepare_analysis_response_queryset(
                AnalysisRun.objects
                .filter(
                    project=project
                )
            )
            .order_by(
                "sequence"
            )
        )


        # --------------------------------
        # 일반 사용자
        #
        # completed만 조회 가능
        # + 내부 AnalysisRun 정보 제거
        # + 취약점 상세 결과 중심으로 반환
        # --------------------------------

        if not request.user.is_staff:

            analysis_runs = (
                analysis_runs.filter(
                    status=
                        AnalysisRun.Status.COMPLETED
                )
            )


            user_results = [
                serialize_user_completed_analysis(
                    analysis_run
                )
                for analysis_run
                in analysis_runs
            ]


            return Response(
                user_results,
                status=status.HTTP_200_OK
            )


        # --------------------------------
        # 관리자
        #
        # 기존 전체 AnalysisRun 응답 유지
        # --------------------------------

        admin_results = [
            serialize_admin_analysis_with_kisa(
                analysis_run
            )
            for analysis_run
            in analysis_runs
        ]


        return Response(
            admin_results,
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
        # --------------------------------

        project = get_object_or_404(
            Project,
            pk=project_id
        )


        # =================================
        # Transaction
        #
        # 같은 Project에서 동시에
        # AnalysisRun 생성 요청이 들어와도
        # sequence가 충돌하지 않도록 한다.
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
            # Project에 pending / running
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
            # 최초 상태는 pending
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

                    # 분석 언어는 관리자가 입력하지 않는다.
                    #
                    # Celery Task가 실제 분석 대상을
                    # 준비한 뒤 자동으로 감지하여
                    # analysis_languages에 저장한다.
                    #
                    # 기존 단일 필드는 전환 기간 동안
                    # 호환용으로만 빈 값으로 생성한다.
                    analysis_language=
                        "",

                    analysis_languages=
                        [],

                    executed_by=
                        request.user,
                )
            )


            # =================================
            # Celery Task 등록
            #
            # AnalysisRun DB 저장이 실제로
            # commit된 뒤 Celery에 전달한다.
            #
            # pending
            #   ↓
            # Celery
            #   ↓
            # running
            #   ↓
            # completed / failed
            # =================================

            transaction.on_commit(
                lambda:
                    run_analysis.delay(
                        analysis_run.id
                    )
            )


        # --------------------------------
        # 생성 결과 반환
        # --------------------------------

        analysis_run = (
            prepare_analysis_response_queryset(
                AnalysisRun.objects
                .filter(
                    pk=analysis_run.pk
                )
            )
            .get()
        )


        return Response(
            serialize_admin_analysis_with_kisa(
                analysis_run
            ),
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
            prepare_analysis_response_queryset(
                AnalysisRun.objects.all()
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


        # --------------------------------
        # 일반 사용자
        #
        # completed 분석의 취약점 상세 결과와
        # 화면 연결에 필요한 최소 정보만 반환
        # --------------------------------

        if not request.user.is_staff:

            return Response(
                serialize_user_completed_analysis(
                    analysis_run
                ),
                status=status.HTTP_200_OK
            )


        # --------------------------------
        # 관리자
        #
        # 기존 전체 AnalysisRun 상세 응답 유지
        # --------------------------------

        return Response(
            serialize_admin_analysis_with_kisa(
                analysis_run
            ),
            status=status.HTTP_200_OK
        )


# ========================================
# 관리자 요약
#
# GET
# /api/admin/summary/
#
# 관리자 전용
#
# 반환 정보
# - 전체 사용자
# - 활성 사용자
# - 전체 프로젝트
# - 전체 AnalysisRun
# - 현재 프로젝트별 분석 상태
# - 최근 AnalysisRun 5건
# ========================================

class AdminSummaryView(
    APIView
):

    permission_classes = [
        IsAuthenticated
    ]


    def get(
        self,
        request
    ):

        # --------------------------------
        # 관리자 전용
        # --------------------------------

        if not request.user.is_staff:

            return Response(
                {
                    "detail":
                        "관리자만 조회할 수 있습니다."
                },
                status=
                    status.HTTP_403_FORBIDDEN
            )


        # =================================
        # 사용자 통계
        # =================================

        total_users = (
            User.objects.count()
        )


        active_users = (
            User.objects
            .filter(
                is_active=True
            )
            .count()
        )


        # =================================
        # 프로젝트 현재 분석 상태
        #
        # 각 Project의 current_source_version에
        # 연결된 AnalysisRun 상태를 조회한다.
        #
        # SourceVersion이 없거나 현재 SourceVersion에
        # AnalysisRun이 없으면 상태 통계에서 제외한다.
        # =================================

        latest_analysis_status_subquery = (
            AnalysisRun.objects
            .filter(
                project_id=
                    OuterRef(
                        "pk"
                    ),

                source_version_id=
                    OuterRef(
                        "current_source_version_id"
                    ),
            )
            .order_by(
                "-sequence"
            )
            .values(
                "status"
            )[:1]
        )


        projects_with_status = (
            Project.objects
            .annotate(
                latest_analysis_status=
                    Subquery(
                        latest_analysis_status_subquery
                    )
            )
        )


        total_projects = (
            projects_with_status.count()
        )


        analysis_status = {
            "pending": 0,
            "running": 0,
            "completed": 0,
            "failed": 0,
        }


        status_rows = (
            projects_with_status
            .exclude(
                latest_analysis_status__isnull=True
            )
            .values(
                "latest_analysis_status"
            )
            .annotate(
                total=Count(
                    "id"
                )
            )
        )


        for row in status_rows:

            current_status = (
                row[
                    "latest_analysis_status"
                ]
            )


            if current_status in analysis_status:

                analysis_status[
                    current_status
                ] = row[
                    "total"
                ]


        # =================================
        # 전체 AnalysisRun
        # =================================

        total_analysis_runs = (
            AnalysisRun.objects
            .count()
        )


        # =================================
        # 최근 분석 이력
        #
        # 최근 생성된 AnalysisRun 5건
        # =================================

        recent_analysis_runs = (
            AnalysisRun.objects
            .select_related(
                "project",
                "source_version",
                "executed_by"
            )
            .annotate(
                result_count=
                    Count(
                        "vulnerabilities"
                    )
            )
            .order_by(
                "-created_at"
            )[:5]
        )


        recent_analyses = []


        for analysis in recent_analysis_runs:

            recent_analyses.append(
                {
                    "id":
                        analysis.id,

                    "sequence":
                        analysis.sequence,

                    "project_id":
                        analysis.project_id,

                    "project_name":
                        analysis.project.name,

                    "source_version_id":
                        analysis.source_version_id,

                    "source_version":
                        analysis.source_version.version,

                    # 기존 단일 언어
                    # 전환 기간 동안 호환용 유지
                    "analysis_language":
                        analysis.analysis_language,

                    # 자동 감지된 다중 언어
                    "analysis_languages":
                        analysis.analysis_languages,

                    "status":
                        analysis.status,

                    "result_count":
                        analysis.result_count,

                    "executed_by_username":
                        analysis.executed_by.username,

                    "started_at":
                        analysis.started_at,

                    "completed_at":
                        analysis.completed_at,

                    "created_at":
                        analysis.created_at,
                }
            )


        # =================================
        # 응답
        # =================================

        return Response(
            {
                "total_users":
                    total_users,

                "active_users":
                    active_users,

                "total_projects":
                    total_projects,

                "total_analysis_runs":
                    total_analysis_runs,

                "analysis_status":
                    analysis_status,

                "recent_analyses":
                    recent_analyses,
            },
            status=
                status.HTTP_200_OK
        )