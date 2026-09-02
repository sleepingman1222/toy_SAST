from django.contrib.auth import (
    get_user_model,
)

from rest_framework import serializers

from .models import (
    Project,
    ProjectAccess,
    SourceVersion,
)


User = get_user_model()


# ========================================
# SourceVersion 조회 Serializer
# ========================================

class SourceVersionSerializer(
    serializers.ModelSerializer
):

    # ====================================
    # 등록자
    # ====================================

    created_by_id = serializers.IntegerField(
        source="created_by.id",
        read_only=True,
    )

    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
    )


    # ====================================
    # 업로드 파일명
    #
    # 실제 storage 경로 전체를
    # Frontend에 노출하지 않고
    # 파일명만 전달
    # ====================================

    source_file_name = (
        serializers.SerializerMethodField()
    )


    class Meta:

        model = SourceVersion

        fields = [
            "id",

            "version",
            "language",
            "source_type",

            "source_file_name",
            "repository_url",
            "internal_path",

            "created_by_id",
            "created_by_username",

            "created_at",
        ]

        read_only_fields = [
            "id",

            "version",
            "language",
            "source_type",

            "source_file_name",
            "repository_url",
            "internal_path",

            "created_by_id",
            "created_by_username",

            "created_at",
        ]


    # ====================================
    # 파일명
    # ====================================

    def get_source_file_name(
        self,
        obj,
    ):

        if (
            not obj.source_file
            or
            not obj.source_file.name
        ):

            return ""


        return (
            obj.source_file.name
            .replace("\\", "/")
            .split("/")[-1]
        )


# ========================================
# 일반 사용자용 SourceVersion 조회 Serializer
#
# 일반 사용자에게는 완료된 분석 결과를
# 화면에 연결하는 데 필요한 최소 정보만 제공한다.
# ========================================

class UserSourceVersionSerializer(
    serializers.ModelSerializer
):

    class Meta:

        model = SourceVersion

        fields = [
            "id",
            "version",
            "language",
        ]

        read_only_fields = [
            "id",
            "version",
            "language",
        ]


# ========================================
# SourceVersion 등록 / 수정 Serializer
#
# POST /api/projects/{id}/sources/
#
# PATCH
# /api/projects/{id}/sources/{source_id}/
# ========================================

class SourceVersionWriteSerializer(
    serializers.ModelSerializer
):

    # ====================================
    # Language
    #
    # 사용자가 분석 언어를 직접 선택하지 않는다.
    # SourceVersion 생성 시에는 빈 문자열로 저장하고,
    # 실제 분석 실행 시 Snapshot / Planner가 감지한
    # 언어를 scans.tasks.save_detected_languages()에서
    # 자동으로 갱신한다.
    #
    # PATCH(partial=True)에서는 HiddenField default가
    # 적용되지 않으므로 기존 language 값도 임의로
    # 덮어쓰지 않는다.
    # ====================================

    language = serializers.HiddenField(
        default="",
    )


    source_file = serializers.FileField(
        required=False,
        allow_null=True,
    )


    class Meta:

        model = SourceVersion

        fields = [
            "language",
            "source_type",

            "source_file",
            "repository_url",
            "internal_path",
        ]


    # ====================================
    # Repository URL 정리
    # ====================================

    def validate_repository_url(
        self,
        value,
    ):

        return value.strip()


    # ====================================
    # Internal Path 정리
    # ====================================

    def validate_internal_path(
        self,
        value,
    ):

        return value.strip()


    # ====================================
    # Source Type별 검증
    #
    # 사용하지 않는 필드는
    # 자동으로 초기화
    # ====================================

    def validate(
        self,
        attrs,
    ):

        attrs = super().validate(
            attrs
        )


        instance = (
            self.instance
        )


        # --------------------------------
        # Source Type
        # --------------------------------

        source_type = (
            attrs.get(
                "source_type"
            )
        )


        if (
            source_type
            is None
            and
            instance
            is not None
        ):

            source_type = (
                instance.source_type
            )


        if not source_type:

            raise serializers.ValidationError({
                "source_type":
                    "소스 유형을 선택해주세요."
            })


        # --------------------------------
        # Source File
        # --------------------------------

        if (
            "source_file"
            in attrs
        ):

            source_file = (
                attrs[
                    "source_file"
                ]
            )

        elif (
            instance
            is not None
        ):

            source_file = (
                instance.source_file
            )

        else:

            source_file = None


        # --------------------------------
        # Repository URL
        # --------------------------------

        if (
            "repository_url"
            in attrs
        ):

            repository_url = (
                attrs[
                    "repository_url"
                ]
            )

        elif (
            instance
            is not None
        ):

            repository_url = (
                instance.repository_url
            )

        else:

            repository_url = ""


        # --------------------------------
        # Internal Path
        # --------------------------------

        if (
            "internal_path"
            in attrs
        ):

            internal_path = (
                attrs[
                    "internal_path"
                ]
            )

        elif (
            instance
            is not None
        ):

            internal_path = (
                instance.internal_path
            )

        else:

            internal_path = ""


        # ====================================
        # Upload
        # ====================================

        if (
            source_type ==
            SourceVersion
            .SourceType
            .UPLOAD
        ):

            if not source_file:

                raise serializers.ValidationError({
                    "source_file":
                        "업로드 방식은 소스 파일이 필요합니다."
                })


            # Upload에서는
            # 다른 유형 데이터 제거

            attrs[
                "repository_url"
            ] = ""

            attrs[
                "internal_path"
            ] = ""


        # ====================================
        # Repository
        # ====================================

        elif (
            source_type ==
            SourceVersion
            .SourceType
            .REPOSITORY
        ):

            repository_url = (
                repository_url.strip()
                if repository_url
                else ""
            )


            if not repository_url:

                raise serializers.ValidationError({
                    "repository_url":
                        "Repository 방식은 URL이 필요합니다."
                })


            attrs[
                "repository_url"
            ] = repository_url


            # Repository에서는
            # 파일 / 내부 경로 제거

            attrs[
                "source_file"
            ] = None

            attrs[
                "internal_path"
            ] = ""


        # ====================================
        # Internal Path
        # ====================================

        elif (
            source_type ==
            SourceVersion
            .SourceType
            .INTERNAL
        ):

            internal_path = (
                internal_path.strip()
                if internal_path
                else ""
            )


            if not internal_path:

                raise serializers.ValidationError({
                    "internal_path":
                        "내부 경로 방식은 경로가 필요합니다."
                })


            attrs[
                "internal_path"
            ] = internal_path


            # Internal에서는
            # 파일 / Repository 제거

            attrs[
                "source_file"
            ] = None

            attrs[
                "repository_url"
            ] = ""


        else:

            raise serializers.ValidationError({
                "source_type":
                    "지원하지 않는 소스 유형입니다."
            })


        return attrs


# ========================================
# Project Serializer
# ========================================

class ProjectSerializer(
    serializers.ModelSerializer
):

    # ====================================
    # 등록자 정보
    # ====================================

    created_by_id = serializers.IntegerField(
        source="created_by.id",
        read_only=True,
    )

    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
    )


    # ====================================
    # 현재 SourceVersion ID
    # ====================================

    current_source_version_id = (
        serializers.IntegerField(
            source="current_source_version.id",
            read_only=True,
            allow_null=True,
        )
    )


    # ====================================
    # SourceVersion 목록
    #
    # Frontend 새로고침 후에도
    # SourceVersion을 복원하기 위해
    # Project 응답에 함께 포함
    # ====================================

    source_versions = (
        SourceVersionSerializer(
            many=True,
            read_only=True,
        )
    )


    # ====================================
    # 프로젝트 접근 권한 사용자 ID
    #
    # ProjectAccess DB 기준
    # ====================================

    assigned_user_ids = (
        serializers.SerializerMethodField()
    )


    class Meta:

        model = Project

        fields = [
            "id",

            "name",
            "description",

            "created_by_id",
            "created_by_username",

            "current_source_version_id",

            "source_versions",

            "assigned_user_ids",

            "created_at",
            "updated_at",
        ]


        read_only_fields = [
            "id",

            "created_by_id",
            "created_by_username",

            "current_source_version_id",

            "source_versions",

            "assigned_user_ids",

            "created_at",
            "updated_at",
        ]


    # ====================================
    # 프로젝트명 검증
    # ====================================

    def validate_name(
        self,
        value,
    ):

        value = value.strip()


        if not value:

            raise serializers.ValidationError(
                "프로젝트명을 입력해주세요."
            )


        return value


    # ====================================
    # 설명 정리
    # ====================================

    def validate_description(
        self,
        value,
    ):

        return value.strip()


    # ====================================
    # 프로젝트 접근 사용자 ID 목록
    # ====================================

    def get_assigned_user_ids(
        self,
        obj,
    ):

        return list(
            ProjectAccess.objects
            .filter(
                project=obj
            )
            .order_by(
                "user_id"
            )
            .values_list(
                "user_id",
                flat=True,
            )
        )


    # ====================================
    # 역할별 Project 응답 분리
    #
    # 관리자
    # → 기존 ProjectSerializer 응답
    #
    # 일반 사용자
    # → UserProjectSerializer 응답
    # ====================================

    def to_representation(
        self,
        instance,
    ):

        request = self.context.get(
            "request"
        )


        if (
            request is not None
            and
            not request.user.is_staff
        ):

            return UserProjectSerializer(
                instance,
                context=self.context,
            ).data


        return super().to_representation(
            instance
        )


# ========================================
# 일반 사용자용 Project 조회 Serializer
#
# 일반 사용자는 완료된 분석 결과 조회에
# 필요한 프로젝트 정보만 받는다.
#
# 제외:
# - created_by_id
# - current_source_version_id
# - assigned_user_ids
# - Source 파일명 / Repository URL / 내부 경로
# - 분석되지 않았거나 완료되지 않은 SourceVersion
# ========================================

class UserProjectSerializer(
    serializers.ModelSerializer
):

    created_by_username = serializers.CharField(
        source="created_by.username",
        read_only=True,
    )


    source_versions = (
        serializers.SerializerMethodField()
    )


    class Meta:

        model = Project

        fields = [
            "id",
            "name",
            "description",
            "created_by_username",
            "source_versions",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "name",
            "description",
            "created_by_username",
            "source_versions",
            "created_at",
        ]


    # ====================================
    # 완료된 분석과 연결된 SourceVersion만
    # 일반 사용자에게 제공
    # ====================================

    def get_source_versions(
        self,
        obj,
    ):

        source_versions = (
            obj.source_versions
            .filter(
                analysis_runs__status=
                    "completed"
            )
            .distinct()
            .order_by(
                "version"
            )
        )


        return (
            UserSourceVersionSerializer(
                source_versions,
                many=True,
            ).data
        )


# ========================================
# ProjectAccess 조회 Serializer
#
# GET
# /api/projects/{id}/access/
# ========================================

class ProjectAccessSerializer(
    serializers.ModelSerializer
):

    project_id = serializers.IntegerField(
        source="project.id",
        read_only=True,
    )

    user_id = serializers.IntegerField(
        source="user.id",
        read_only=True,
    )

    username = serializers.CharField(
        source="user.username",
        read_only=True,
    )

    granted_by_id = serializers.IntegerField(
        source="granted_by.id",
        read_only=True,
    )

    granted_by_username = serializers.CharField(
        source="granted_by.username",
        read_only=True,
    )


    class Meta:

        model = ProjectAccess

        fields = [
            "id",
            "project_id",
            "user_id",
            "username",
            "granted_by_id",
            "granted_by_username",
            "created_at",
        ]

        read_only_fields = [
            "id",
            "project_id",
            "user_id",
            "username",
            "granted_by_id",
            "granted_by_username",
            "created_at",
        ]


# ========================================
# ProjectAccess 생성 Serializer
#
# POST
# /api/projects/{id}/access/
#
# 요청:
#
# {
#     "user_id": 2
# }
# ========================================

class ProjectAccessCreateSerializer(
    serializers.Serializer
):

    user_id = (
        serializers.PrimaryKeyRelatedField(
            source="user",
            queryset=User.objects.all(),
            required=True,
        )
    )


    # ====================================
    # 사용자 검증
    # ====================================

    def validate_user_id(
        self,
        user,
    ):

        # --------------------------------
        # 관리자 계정 제외
        # --------------------------------

        if user.is_staff:

            raise serializers.ValidationError(
                "관리자 계정에는 프로젝트 접근 권한을 부여할 수 없습니다."
            )


        # --------------------------------
        # 비활성 사용자 제외
        # --------------------------------

        if not user.is_active:

            raise serializers.ValidationError(
                "비활성 사용자에게는 프로젝트 접근 권한을 부여할 수 없습니다."
            )


        return user


    # ====================================
    # 중복 검증
    # ====================================

    def validate(
        self,
        attrs,
    ):

        attrs = super().validate(
            attrs
        )


        project = self.context[
            "project"
        ]

        user = attrs[
            "user"
        ]


        if (
            ProjectAccess.objects
            .filter(
                project=project,
                user=user,
            )
            .exists()
        ):

            raise serializers.ValidationError({
                "user_id":
                    "이미 이 프로젝트에 접근 권한이 있는 사용자입니다."
            })


        return attrs


    # ====================================
    # ProjectAccess 생성
    # ====================================

    def create(
        self,
        validated_data,
    ):

        project = self.context[
            "project"
        ]

        request = self.context[
            "request"
        ]


        return (
            ProjectAccess.objects.create(
                project=project,

                user=validated_data[
                    "user"
                ],

                granted_by=request.user,
            )
        )


    # ====================================
    # 생성 응답
    # ====================================

    def to_representation(
        self,
        instance,
    ):

        return ProjectAccessSerializer(
            instance
        ).data