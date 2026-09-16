from django.conf import settings

from django.contrib.auth import (
    get_user_model,
)

from django.contrib.auth.password_validation import (
    validate_password,
)

from django.core.exceptions import (
    ValidationError as DjangoValidationError,
)

from django.db import (
    IntegrityError,
    transaction,
)

from django.db.models.deletion import (
    ProtectedError,
)

from django.http import JsonResponse

from django.shortcuts import (
    get_object_or_404,
)

from django.utils.decorators import (
    method_decorator,
)

from django.views.decorators.csrf import (
    csrf_protect,
    ensure_csrf_cookie,
)

from rest_framework import (
    mixins,
    status,
    viewsets,
)

from rest_framework.decorators import (
    action,
    api_view,
    permission_classes,
)

from rest_framework.permissions import (
    IsAuthenticated,
)

from rest_framework.response import (
    Response,
)

from rest_framework_simplejwt.tokens import (
    RefreshToken,
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


from projects.models import (
    ProjectAccess,
)


from .permissions import (
    IsAdminRole,
)

from .serializers import (
    CustomTokenObtainPairSerializer,
    UserActiveStatusSerializer,
    UserCreateSerializer,
    UserSerializer,
)

from .throttles import (
    LoginIPThrottle,
    LoginUsernameThrottle,
    LoginIPUsernameThrottle,
)


User = get_user_model()


# ========================================
# 로그인
# ========================================

class CustomTokenObtainPairView(
    TokenObtainPairView
):

    serializer_class = (
        CustomTokenObtainPairSerializer
    )

    throttle_classes = [
        LoginIPThrottle,
        LoginUsernameThrottle,
        LoginIPUsernameThrottle,
    ]


    def post(
        self,
        request,
        *args,
        **kwargs,
    ):
        serializer = self.get_serializer(
            data=request.data
        )

        serializer.is_valid(
            raise_exception=True
        )

        data = serializer.validated_data


        # ------------------------------------
        # Refresh Token은 JSON에서 제거
        # ------------------------------------

        refresh_token = data.pop(
            "refresh"
        )


        response = Response(
            data
        )


        # ------------------------------------
        # Refresh Token을
        # HttpOnly Cookie에 저장
        # ------------------------------------

        response.set_cookie(
            key="refresh_token",

            value=refresh_token,

            httponly=True,

            secure=(
                settings
                .REFRESH_COOKIE_SECURE
            ),

            samesite=(
                settings
                .REFRESH_COOKIE_SAMESITE
            ),

            max_age=(
                7 *
                24 *
                60 *
                60
            ),
        )

        return response


# ========================================
# Access Token 재발급
# ========================================

@method_decorator(
    csrf_protect,
    name="dispatch",
)
class CookieTokenRefreshView(
    TokenRefreshView
):

    def post(
        self,
        request,
        *args,
        **kwargs,
    ):

        refresh_token = (
            request.COOKIES.get(
                "refresh_token"
            )
        )


        if not refresh_token:
            return Response(
                {
                    "detail":
                        "Refresh Token이 없습니다."
                },
                status=(
                    status.HTTP_401_UNAUTHORIZED
                ),
            )


        serializer = self.get_serializer(
            data={
                "refresh":
                    refresh_token
            }
        )


        serializer.is_valid(
            raise_exception=True
        )


        data = (
            serializer.validated_data
        )


        new_refresh_token = (
            data.pop(
                "refresh",
                None,
            )
        )


        response = Response(
            data
        )


        if new_refresh_token:
            response.set_cookie(
                key="refresh_token",

                value=new_refresh_token,

                httponly=True,

                secure=(
                    settings
                    .REFRESH_COOKIE_SECURE
                ),

                samesite=(
                    settings
                    .REFRESH_COOKIE_SAMESITE
                ),

                max_age=(
                    7 *
                    24 *
                    60 *
                    60
                ),
            )


        return response


# ========================================
# 로그아웃
# ========================================

@csrf_protect
@api_view([
    "POST",
])
def logout_view(
    request
):

    refresh_token = (
        request.COOKIES.get(
            "refresh_token"
        )
    )


    if refresh_token:

        try:
            token = RefreshToken(
                refresh_token
            )

            token.blacklist()

        except Exception:
            pass


    response = Response({
        "message":
            "로그아웃 되었습니다."
    })


    response.delete_cookie(
        "refresh_token"
    )


    return response


# ========================================
# 현재 사용자 조회
# ========================================

@api_view([
    "GET",
])
@permission_classes([
    IsAuthenticated,
])
def me_view(
    request
):

    user = request.user


    return Response({
        "id":
            user.id,

        "username":
            user.username,

        "role":
            "admin"
            if user.is_staff
            else "user",
    })


# ========================================
# CSRF Token 발급
# ========================================

@ensure_csrf_cookie
def csrf_view(
    request
):

    return JsonResponse({
        "message":
            "CSRF Cookie 생성 완료"
    })


# ========================================
# 사용자 관리
#
# GET
# /api/users/
#
# POST
# /api/users/
#
# GET
# /api/users/{id}/
#
# PATCH
# /api/users/{id}/
#
# DELETE
# /api/users/{id}/
# ========================================

class UserViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):

    permission_classes = [
        IsAdminRole,
    ]


    queryset = (
        User.objects
        .all()
        .order_by(
            "-date_joined"
        )
    )


    # ====================================
    # Action별 Serializer
    # ====================================

    def get_serializer_class(
        self
    ):

        if (
            self.action ==
            "create"
        ):
            return (
                UserCreateSerializer
            )


        if (
            self.action ==
            "partial_update"
        ):
            return (
                UserActiveStatusSerializer
            )


        return (
            UserSerializer
        )


    # ====================================
    # 활성 / 비활성 변경
    #
    # PATCH /api/users/{id}/
    # ====================================

    def partial_update(
        self,
        request,
        *args,
        **kwargs,
    ):

        # --------------------------------
        # PATCH지만 우리가 허용하는
        # 값은 isActive 하나뿐
        # --------------------------------

        if (
            "isActive"
            not in request.data
        ):
            return Response(
                {
                    "detail":
                        "isActive 값이 필요합니다."
                },
                status=(
                    status.HTTP_400_BAD_REQUEST
                ),
            )


        with transaction.atomic():

            target_user = (
                get_object_or_404(
                    User.objects
                    .select_for_update(),

                    pk=kwargs.get(
                        "pk"
                    ),
                )
            )


            serializer = (
                UserActiveStatusSerializer(
                    target_user,
                    data=request.data,
                )
            )


            serializer.is_valid(
                raise_exception=True
            )


            next_is_active = (
                serializer
                .validated_data[
                    "is_active"
                ]
            )


            # --------------------------------
            # 관리자 자기 자신 비활성화 금지
            # --------------------------------

            if (
                target_user.id ==
                request.user.id
                and
                not next_is_active
            ):

                return Response(
                    {
                        "detail":
                            "현재 로그인 중인 계정은 비활성화할 수 없습니다."
                    },
                    status=(
                        status.HTTP_400_BAD_REQUEST
                    ),
                )


            updated_user = (
                serializer.save()
            )


            # --------------------------------
            # 비활성화
            #
            # 모든 프로젝트 접근 권한
            # 즉시 제거
            # --------------------------------

            if (
                not updated_user.is_active
            ):

                ProjectAccess.objects.filter(
                    user=updated_user
                ).delete()


        return Response(
            UserSerializer(
                updated_user
            ).data
        )



    # ====================================
    # 내 비밀번호 변경
    #
    # POST
    # /api/users/change-password/
    #
    # 관리자 / 일반 사용자 공통
    #
    # 정책
    #
    # 1. 로그인한 사용자만 허용
    # 2. 현재 비밀번호 재확인
    # 3. 현재 비밀번호와 동일한 새 비밀번호 금지
    # 4. 새 비밀번호 확인값 일치
    # 5. Django AUTH_PASSWORD_VALIDATORS 적용
    # 6. 성공 후 현재 Refresh Token blacklist
    # 7. Refresh Cookie 제거
    # 8. Frontend는 Access Token도 제거하고 재로그인
    # ====================================

    @action(
        detail=False,
        methods=[
            "post",
        ],
        url_path=
            "change-password",
        permission_classes=[
            IsAuthenticated,
        ],
    )
    def change_password(
        self,
        request,
    ):

        current_password = str(
            request.data.get(
                "current_password",
                "",
            )
            or ""
        )

        new_password = str(
            request.data.get(
                "new_password",
                "",
            )
            or ""
        )

        new_password_confirm = str(
            request.data.get(
                "new_password_confirm",
                "",
            )
            or ""
        )


        # --------------------------------
        # 필수값 검증
        # --------------------------------

        field_errors = {}

        if not current_password:

            field_errors[
                "current_password"
            ] = [
                "현재 비밀번호를 입력해주세요."
            ]


        if not new_password:

            field_errors[
                "new_password"
            ] = [
                "새 비밀번호를 입력해주세요."
            ]


        if not new_password_confirm:

            field_errors[
                "new_password_confirm"
            ] = [
                "새 비밀번호 확인을 입력해주세요."
            ]


        if field_errors:

            return Response(
                field_errors,
                status=(
                    status
                    .HTTP_400_BAD_REQUEST
                ),
            )


        # --------------------------------
        # 확인 비밀번호 일치
        # --------------------------------

        if (
            new_password
            !=
            new_password_confirm
        ):

            return Response(
                {
                    "new_password_confirm": [
                        "새 비밀번호와 확인 비밀번호가 일치하지 않습니다."
                    ]
                },
                status=(
                    status
                    .HTTP_400_BAD_REQUEST
                ),
            )


        # --------------------------------
        # 비밀번호 변경
        #
        # select_for_update로 같은 계정에 대한
        # 동시 변경 요청을 직렬화한다.
        # --------------------------------

        with transaction.atomic():

            target_user = (
                User.objects
                .select_for_update()
                .get(
                    pk=request.user.pk
                )
            )


            # ----------------------------
            # 현재 비밀번호 확인
            # ----------------------------

            if not (
                target_user
                .check_password(
                    current_password
                )
            ):

                return Response(
                    {
                        "current_password": [
                            "현재 비밀번호가 올바르지 않습니다."
                        ]
                    },
                    status=(
                        status
                        .HTTP_400_BAD_REQUEST
                    ),
                )


            # ----------------------------
            # 동일 비밀번호 재사용 방지
            #
            # 별도 Password History 테이블은
            # MVP 범위에 없으므로 최소한
            # 현재 비밀번호와 동일한 값은 금지한다.
            # ----------------------------

            if (
                target_user
                .check_password(
                    new_password
                )
            ):

                return Response(
                    {
                        "new_password": [
                            "현재 비밀번호와 다른 새 비밀번호를 입력해주세요."
                        ]
                    },
                    status=(
                        status
                        .HTTP_400_BAD_REQUEST
                    ),
                )


            # ----------------------------
            # Django Password Validators
            # ----------------------------

            try:

                validate_password(
                    new_password,
                    user=target_user,
                )

            except DjangoValidationError as exc:

                return Response(
                    {
                        "new_password":
                            list(
                                exc.messages
                            )
                    },
                    status=(
                        status
                        .HTTP_400_BAD_REQUEST
                    ),
                )


            # ----------------------------
            # Django set_password()
            #
            # 원문 비밀번호를 저장하지 않고
            # PASSWORD_HASHERS 정책으로 해시 저장
            # ----------------------------

            target_user.set_password(
                new_password
            )

            target_user.save(
                update_fields=[
                    "password",
                ]
            )


        # --------------------------------
        # 현재 Refresh Token 폐기
        #
        # Access Token은 Stateless JWT이므로
        # 서버에서 즉시 직접 삭제할 수 없다.
        # Frontend에서 성공 즉시 메모리의
        # Access Token을 제거하고 로그아웃한다.
        # --------------------------------

        refresh_token = (
            request.COOKIES.get(
                "refresh_token"
            )
        )

        if refresh_token:

            try:

                token = RefreshToken(
                    refresh_token
                )

                token.blacklist()

            except Exception:

                # 이미 만료 / 폐기된 Refresh Token이어도
                # 비밀번호 변경 자체는 성공으로 유지
                pass


        response = Response(
            {
                "message":
                    "비밀번호가 변경되었습니다. 새 비밀번호로 다시 로그인해주세요."
            },
            status=(
                status.HTTP_200_OK
            ),
        )


        response.delete_cookie(
            "refresh_token"
        )


        return response


    # ====================================
    # 사용자 삭제
    #
    # DELETE /api/users/{id}/
    #
    # 정책
    #
    # 1. 현재 로그인 중인 자기 계정 삭제 금지
    #
    # 2. 삭제 대상 사용자의 ProjectAccess는 제거
    #
    # 3. Project.created_by,
    #    SourceVersion.created_by,
    #    AnalysisRun.executed_by,
    #    ProjectAccess.granted_by 등
    #    PROTECT 관계가 남아 있으면 삭제 금지
    #
    # 4. 삭제 실패 시 ProjectAccess 삭제도
    #    transaction rollback
    # ====================================

    def destroy(
        self,
        request,
        *args,
        **kwargs,
    ):

        try:

            with transaction.atomic():

                target_user = (
                    get_object_or_404(
                        User.objects
                        .select_for_update(),

                        pk=kwargs.get(
                            "pk"
                        ),
                    )
                )


                # --------------------------------
                # 자기 계정 삭제 금지
                # --------------------------------

                if (
                    target_user.id ==
                    request.user.id
                ):

                    return Response(
                        {
                            "detail":
                                "현재 로그인 중인 계정은 삭제할 수 없습니다."
                        },
                        status=(
                            status.HTTP_400_BAD_REQUEST
                        ),
                    )


                # --------------------------------
                # 삭제 대상 사용자의
                # 프로젝트 접근 권한 제거
                #
                # granted_by 기록은 삭제하지 않음
                # → 감사 이력 보존
                # --------------------------------

                ProjectAccess.objects.filter(
                    user=target_user
                ).delete()


                # --------------------------------
                # 다른 보존 이력이 PROTECT로
                # 연결되어 있으면 여기서
                # ProtectedError 발생
                # --------------------------------

                target_user.delete()


        except ProtectedError:

            return Response(
                {
                    "detail":
                        "프로젝트 생성 또는 분석 이력 등 보존해야 할 기록이 연결된 계정은 삭제할 수 없습니다. 계정 비활성화를 이용해주세요."
                },
                status=(
                    status.HTTP_409_CONFLICT
                ),
            )


        except IntegrityError:

            return Response(
                {
                    "detail":
                        "관련 데이터가 존재하여 계정을 삭제할 수 없습니다. 계정 비활성화를 이용해주세요."
                },
                status=(
                    status.HTTP_409_CONFLICT
                ),
            )


        return Response(
            status=(
                status.HTTP_204_NO_CONTENT
            )
        )
