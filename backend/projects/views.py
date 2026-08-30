import logging

from django.db import (
    IntegrityError,
    transaction,
)

from django.db.models import (
    Max,
)

from django.shortcuts import (
    get_object_or_404,
)


from rest_framework import (
    mixins,
    status,
    viewsets,
)

from rest_framework.decorators import (
    action,
)

from rest_framework.parsers import (
    FormParser,
    JSONParser,
    MultiPartParser,
)

from rest_framework.response import (
    Response,
)


from accounts.permissions import (
    IsAdminRole,
)


from scans.models import (
    AnalysisRun,
)


from .models import (
    Project,
    ProjectAccess,
    SourceVersion,
)


from .serializers import (
    ProjectAccessCreateSerializer,
    ProjectAccessSerializer,
    ProjectSerializer,
    SourceVersionSerializer,
    SourceVersionWriteSerializer,
)


logger = logging.getLogger(
    __name__
)


class ProjectViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):

    serializer_class = (
        ProjectSerializer
    )

    permission_classes = [
        IsAdminRole,
    ]


    queryset = (
        Project.objects
        .select_related(
            "created_by",
            "current_source_version",
        )
        .prefetch_related(
            "source_versions",
        )
        .all()
    )


    # ====================================
    # 프로젝트 생성
    # ====================================

    def perform_create(
        self,
        serializer,
    ):

        serializer.save(
            created_by=self.request.user
        )


    # ====================================
    # 프로젝트 삭제
    #
    # DELETE
    # /api/projects/{id}/
    # ====================================

    def destroy(
        self,
        request,
        *args,
        **kwargs,
    ):

        project = (
            self.get_object()
        )


        # --------------------------------
        # 분석 대기 / 진행 중이면
        # 프로젝트 삭제 금지
        # --------------------------------

        has_active_analysis = (
            AnalysisRun.objects
            .filter(
                project=project,

                status__in=[
                    "pending",
                    "running",
                ],
            )
            .exists()
        )


        if has_active_analysis:

            return Response(
                {
                    "detail":
                        "분석 대기 또는 진행 중인 작업이 있어 프로젝트를 삭제할 수 없습니다."
                },
                status=(
                    status.HTTP_409_CONFLICT
                ),
            )


        # --------------------------------
        # 실제 업로드 파일 정보 저장
        # --------------------------------

        source_files = []


        source_versions = (
            SourceVersion.objects
            .filter(
                project=project
            )
        )


        for source_version in source_versions:

            if (
                source_version.source_file
                and
                source_version.source_file.name
            ):

                source_files.append(
                    (
                        source_version
                        .source_file
                        .storage,

                        source_version
                        .source_file
                        .name,
                    )
                )


        # --------------------------------
        # DB Commit 후 실제 파일 삭제
        # --------------------------------

        def delete_source_files():

            for (
                storage,
                file_name,
            ) in source_files:

                try:

                    storage.delete(
                        file_name
                    )

                except Exception:

                    logger.exception(
                        "프로젝트 삭제 후 소스 파일 삭제 실패: %s",
                        file_name,
                    )


        # --------------------------------
        # AnalysisRun.source_version은
        # PROTECT이므로 먼저 제거
        # --------------------------------

        with transaction.atomic():

            AnalysisRun.objects.filter(
                project=project
            ).delete()


            ProjectAccess.objects.filter(
                project=project
            ).delete()


            SourceVersion.objects.filter(
                project=project
            ).delete()


            project.delete()


            transaction.on_commit(
                delete_source_files
            )


        return Response(
            status=(
                status.HTTP_204_NO_CONTENT
            )
        )


    # ====================================
    # SourceVersion 목록 / 등록
    #
    # GET
    # /api/projects/{id}/sources/
    #
    # POST
    # /api/projects/{id}/sources/
    # ====================================

    @action(
        detail=True,

        methods=[
            "get",
            "post",
        ],

        url_path="sources",

        parser_classes=[
            MultiPartParser,
            FormParser,
            JSONParser,
        ],
    )
    def source_versions(
        self,
        request,
        pk=None,
    ):

        project = (
            self.get_object()
        )


        # ====================================
        # GET
        #
        # SourceVersion 목록
        # ====================================

        if (
            request.method ==
            "GET"
        ):

            source_versions = (
                SourceVersion.objects
                .filter(
                    project=project
                )
                .select_related(
                    "created_by"
                )
                .order_by(
                    "version"
                )
            )


            return Response(
                SourceVersionSerializer(
                    source_versions,
                    many=True,
                ).data
            )


        # ====================================
        # POST
        #
        # SourceVersion 등록
        # ====================================

        serializer = (
            SourceVersionWriteSerializer(
                data=request.data
            )
        )


        serializer.is_valid(
            raise_exception=True
        )


        with transaction.atomic():

            # --------------------------------
            # 같은 프로젝트에서 동시에
            # SourceVersion을 등록하는 상황 방지
            #
            # 중요:
            # current_source_version은 nullable FK이므로
            # select_for_update()와 select_related()를
            # 함께 사용하면 PostgreSQL에서
            # nullable OUTER JOIN 잠금 오류가 발생함.
            #
            # 따라서 Project 행만 먼저 잠근다.
            # --------------------------------

            locked_project = (
                Project.objects
                .select_for_update()
                .get(
                    pk=project.pk
                )
            )


            # --------------------------------
            # 현재 SourceVersion 조회
            #
            # Project 행을 잠근 뒤
            # FK ID를 기준으로 별도 조회
            # --------------------------------

            current_source_version = None


            if (
                locked_project
                .current_source_version_id
                is not None
            ):

                current_source_version = (
                    SourceVersion.objects
                    .get(
                        pk=(
                            locked_project
                            .current_source_version_id
                        )
                    )
                )


            # ====================================
            # 기존 SourceVersion이 있는 경우
            # ====================================

            if (
                current_source_version
                is not None
            ):

                # --------------------------------
                # 현재 SourceVersion에
                # AnalysisRun이 있는지 검사
                # --------------------------------

                has_analysis_run = (
                    AnalysisRun.objects
                    .filter(
                        source_version=
                            current_source_version
                    )
                    .exists()
                )


                # --------------------------------
                # 분석 전 Source는 수정해야 함
                #
                # v1 생성
                # ↓
                # 분석하지 않음
                # ↓
                # v2 생성 금지
                # --------------------------------

                if not has_analysis_run:

                    return Response(
                        {
                            "detail":
                                "현재 분석 대상은 아직 분석되지 않았습니다. 새 버전을 등록하지 말고 현재 분석 대상을 수정해주세요."
                        },
                        status=(
                            status.HTTP_409_CONFLICT
                        ),
                    )


                # --------------------------------
                # pending / running이면
                # 새 버전 생성 금지
                # --------------------------------

                has_active_analysis = (
                    AnalysisRun.objects
                    .filter(
                        source_version=
                            current_source_version,

                        status__in=[
                            "pending",
                            "running",
                        ],
                    )
                    .exists()
                )


                if has_active_analysis:

                    return Response(
                        {
                            "detail":
                                "현재 분석이 대기 또는 진행 중이므로 새 분석 대상을 등록할 수 없습니다."
                        },
                        status=(
                            status.HTTP_409_CONFLICT
                        ),
                    )


            # ====================================
            # 다음 Version 계산
            #
            # Frontend에서 계산하지 않음
            # ====================================

            max_version = (
                SourceVersion.objects
                .filter(
                    project=locked_project
                )
                .aggregate(
                    max_version=
                        Max(
                            "version"
                        )
                )[
                    "max_version"
                ]
                or 0
            )


            next_version = (
                max_version + 1
            )


            # ====================================
            # SourceVersion 저장
            # ====================================

            source_version = (
                serializer.save(
                    project=
                        locked_project,

                    version=
                        next_version,

                    created_by=
                        request.user,
                )
            )


            # ====================================
            # Project의 현재 SourceVersion 갱신
            # ====================================

            locked_project.current_source_version = (
                source_version
            )


            locked_project.save(
                update_fields=[
                    "current_source_version",
                    "updated_at",
                ]
            )


        return Response(
            SourceVersionSerializer(
                source_version
            ).data,

            status=(
                status.HTTP_201_CREATED
            ),
        )


    # ====================================
    # SourceVersion 조회 / 수정
    #
    # GET
    # /api/projects/{id}/sources/{source_id}/
    #
    # PATCH
    # /api/projects/{id}/sources/{source_id}/
    # ====================================

    @action(
        detail=True,

        methods=[
            "get",
            "patch",
        ],

        url_path=(
            r"sources/"
            r"(?P<source_id>\d+)"
        ),

        parser_classes=[
            MultiPartParser,
            FormParser,
            JSONParser,
        ],
    )
    def source_version_detail(
        self,
        request,
        pk=None,
        source_id=None,
    ):

        project = (
            self.get_object()
        )


        # ====================================
        # GET
        # ====================================

        if (
            request.method ==
            "GET"
        ):

            source_version = (
                get_object_or_404(
                    SourceVersion.objects
                    .select_related(
                        "created_by"
                    ),

                    pk=source_id,

                    project=project,
                )
            )


            return Response(
                SourceVersionSerializer(
                    source_version
                ).data
            )


        # ====================================
        # PATCH
        #
        # 아직 AnalysisRun이 없는
        # 현재 SourceVersion만 수정 가능
        # ====================================

        with transaction.atomic():

            # --------------------------------
            # Project 잠금
            # --------------------------------

            locked_project = (
                Project.objects
                .select_for_update()
                .get(
                    pk=project.pk
                )
            )


            # --------------------------------
            # SourceVersion 잠금
            # --------------------------------

            source_version = (
                get_object_or_404(
                    SourceVersion.objects
                    .select_for_update(),

                    pk=source_id,

                    project=locked_project,
                )
            )


            # --------------------------------
            # 현재 SourceVersion만 수정
            # --------------------------------

            if (
                locked_project
                .current_source_version_id
                !=
                source_version.id
            ):

                return Response(
                    {
                        "detail":
                            "과거 SourceVersion은 수정할 수 없습니다."
                    },
                    status=(
                        status.HTTP_409_CONFLICT
                    ),
                )


            # --------------------------------
            # AnalysisRun이 하나라도 존재하면
            # SourceVersion 동결
            # --------------------------------

            has_analysis_run = (
                AnalysisRun.objects
                .filter(
                    source_version=
                        source_version
                )
                .exists()
            )


            if has_analysis_run:

                return Response(
                    {
                        "detail":
                            "이미 분석이 실행된 SourceVersion은 수정할 수 없습니다."
                    },
                    status=(
                        status.HTTP_409_CONFLICT
                    ),
                )


            # --------------------------------
            # 기존 파일 저장
            #
            # upload → repository 등으로
            # 변경했을 때 정리하기 위함
            # --------------------------------

            old_file_storage = None
            old_file_name = None


            if (
                source_version.source_file
                and
                source_version.source_file.name
            ):

                old_file_storage = (
                    source_version
                    .source_file
                    .storage
                )

                old_file_name = (
                    source_version
                    .source_file
                    .name
                )


            # ====================================
            # 수정 Serializer
            # ====================================

            serializer = (
                SourceVersionWriteSerializer(
                    source_version,

                    data=request.data,

                    partial=True,
                )
            )


            serializer.is_valid(
                raise_exception=True
            )


            updated_source_version = (
                serializer.save()
            )


            # --------------------------------
            # 수정 후 파일 이름
            # --------------------------------

            new_file_name = None


            if (
                updated_source_version
                .source_file
                and
                updated_source_version
                .source_file
                .name
            ):

                new_file_name = (
                    updated_source_version
                    .source_file
                    .name
                )


            # --------------------------------
            # 기존 파일이 다른 파일로
            # 변경되었거나 제거됐다면
            # Commit 이후 storage에서 삭제
            # --------------------------------

            if (
                old_file_storage
                is not None
                and
                old_file_name
                and
                old_file_name
                !=
                new_file_name
            ):

                def delete_old_source_file():

                    try:

                        old_file_storage.delete(
                            old_file_name
                        )

                    except Exception:

                        logger.exception(
                            "SourceVersion 수정 후 기존 파일 삭제 실패: %s",
                            old_file_name,
                        )


                transaction.on_commit(
                    delete_old_source_file
                )


        return Response(
            SourceVersionSerializer(
                updated_source_version
            ).data,

            status=(
                status.HTTP_200_OK
            ),
        )


    # ====================================
    # 프로젝트 접근 권한
    #
    # GET
    # /api/projects/{id}/access/
    #
    # POST
    # /api/projects/{id}/access/
    # ====================================

    @action(
        detail=True,

        methods=[
            "get",
            "post",
        ],

        url_path="access",
    )
    def project_access(
        self,
        request,
        pk=None,
    ):

        project = (
            self.get_object()
        )


        # --------------------------------
        # 접근 권한 목록
        # --------------------------------

        if (
            request.method ==
            "GET"
        ):

            access_list = (
                ProjectAccess.objects
                .filter(
                    project=project
                )
                .select_related(
                    "user",
                    "granted_by",
                )
                .order_by(
                    "created_at"
                )
            )


            serializer = (
                ProjectAccessSerializer(
                    access_list,
                    many=True,
                )
            )


            return Response(
                serializer.data
            )


        # --------------------------------
        # 접근 권한 부여
        # --------------------------------

        serializer = (
            ProjectAccessCreateSerializer(
                data=request.data,

                context={
                    "project":
                        project,

                    "request":
                        request,
                },
            )
        )


        serializer.is_valid(
            raise_exception=True
        )


        try:

            with transaction.atomic():

                project_access = (
                    serializer.save()
                )

        except IntegrityError:

            return Response(
                {
                    "detail":
                        "이미 이 프로젝트에 접근 권한이 있는 사용자입니다."
                },

                status=(
                    status.HTTP_400_BAD_REQUEST
                ),
            )


        return Response(
            ProjectAccessSerializer(
                project_access
            ).data,

            status=(
                status.HTTP_201_CREATED
            ),
        )


    # ====================================
    # 프로젝트 접근 권한 해제
    #
    # DELETE
    # /api/projects/{id}/access/{user_id}/
    # ====================================

    @action(
        detail=True,

        methods=[
            "delete",
        ],

        url_path=(
            r"access/"
            r"(?P<user_id>\d+)"
        ),
    )
    def revoke_project_access(
        self,
        request,
        pk=None,
        user_id=None,
    ):

        project = (
            self.get_object()
        )


        project_access = (
            get_object_or_404(
                ProjectAccess,

                project=project,

                user_id=user_id,
            )
        )


        project_access.delete()


        return Response(
            status=(
                status.HTTP_204_NO_CONTENT
            )
        )
