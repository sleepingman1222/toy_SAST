from django.urls import path

from .views import (
    ProjectAnalysisRunDetailView,
    ProjectAnalysisRunListCreateView,
)


urlpatterns = [

    # ========================================
    # AnalysisRun 목록 조회 / 생성
    #
    # GET
    # POST
    #
    # /api/projects/{project_id}/analyses/
    # ========================================

    path(
        "projects/<int:project_id>/analyses/",
        ProjectAnalysisRunListCreateView.as_view(),
        name="project-analysis-list-create",
    ),


    # ========================================
    # AnalysisRun 상세 조회
    #
    # GET
    #
    # /api/projects/{project_id}/analyses/{analysis_id}/
    # ========================================

    path(
        "projects/<int:project_id>/analyses/<int:analysis_id>/",
        ProjectAnalysisRunDetailView.as_view(),
        name="project-analysis-detail",
    ),
]