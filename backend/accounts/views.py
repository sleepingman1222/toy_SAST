from rest_framework.decorators import (
    api_view,
    permission_classes,
)
from rest_framework.permissions import (
    IsAuthenticated,
)
from rest_framework.response import Response

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from .serializers import (
    CustomTokenObtainPairSerializer,
)

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework_simplejwt.tokens import RefreshToken
from .throttles import (
    LoginIPThrottle,
    LoginUsernameThrottle,
    LoginIPUsernameThrottle,
)
from django.conf import settings

# -------------------------
# 로그인
# -------------------------

class CustomTokenObtainPairView(
    TokenObtainPairView
):
    serializer_class = (
        CustomTokenObtainPairSerializer
    )

    throttle_classes = [
        LoginIPThrottle,
        LoginUsernameThrottle,
        LoginIPUsernameThrottle
    ]

    def post(
        self,
        request,
        *args,
        **kwargs
    ):
        serializer = self.get_serializer(
            data=request.data
        )

        serializer.is_valid(
            raise_exception=True
        )

        data = serializer.validated_data

        # refresh는 JSON에서 제거
        refresh_token = data.pop(
            "refresh"
        )

        response = Response(data)

        # refresh token은
        # HttpOnly Cookie에 저장
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,

            # 개발환경 HTTP이므로 False
            # 운영 HTTPS에서는 True
            secure=settings.REFRESH_COOKIE_SECURE,
            samesite=settings.REFRESH_COOKIE_SAMESITE,

            max_age=7 * 24 * 60 * 60,
        )

        return response


# -------------------------
# Access Token 재발급
# -------------------------
@method_decorator(csrf_protect, name="dispatch")
class CookieTokenRefreshView(TokenRefreshView):

    def post(self, request, *args, **kwargs):

        refresh_token = request.COOKIES.get(
            "refresh_token"
        )

        if not refresh_token:
            return Response(
                {
                    "detail": "Refresh Token이 없습니다."
                },
                status=401,
            )

        serializer = self.get_serializer(
            data={
                "refresh": refresh_token
            }
        )

        serializer.is_valid(
            raise_exception=True
        )

        data = serializer.validated_data

        new_refresh_token = data.pop(
            "refresh",
            None
        )

        response = Response(data)

        if new_refresh_token:
            response.set_cookie(
                key="refresh_token",
                value=new_refresh_token,
                httponly=True,
                secure=settings.REFRESH_COOKIE_SECURE,
                samesite=settings.REFRESH_COOKIE_SAMESITE,
                max_age=7 * 24 * 60 * 60,
            )

        return response


# -------------------------
# 로그아웃
# -------------------------
@csrf_protect
@api_view(["POST"])
def logout_view(request):

    refresh_token = request.COOKIES.get(
        "refresh_token"
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
        "message": "로그아웃 되었습니다."
    })

    response.delete_cookie(
        "refresh_token"
    )

    return response

# -------------------------
# 현재 사용자 조회
# -------------------------

@api_view(["GET"])
@permission_classes([
    IsAuthenticated
])
def me_view(request):

    user = request.user

    return Response({
        "username":
            user.username,

        "role":
            "admin"
            if user.is_staff
            else "user",
    })


# -------------------------
# CSRF Token 발급
# -------------------------

@ensure_csrf_cookie
def csrf_view(request):
    return JsonResponse({
        "message": "CSRF Cookie 생성 완료"
    })