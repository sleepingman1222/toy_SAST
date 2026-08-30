from django.urls import (
    include,
    path,
)

from rest_framework.routers import (
    DefaultRouter,
)


from .views import (
    CookieTokenRefreshView,
    CustomTokenObtainPairView,
    UserViewSet,
    csrf_view,
    logout_view,
    me_view,
)


# ========================================
# Router
# ========================================

router = DefaultRouter()


router.register(
    "users",
    UserViewSet,
    basename="user",
)


# ========================================
# URL
# ========================================

urlpatterns = [

    # ------------------------------------
    # 로그인
    # ------------------------------------

    path(
        "login/",
        CustomTokenObtainPairView.as_view(),
        name="login",
    ),


    # ------------------------------------
    # Access Token 재발급
    # ------------------------------------

    path(
        "token/refresh/",
        CookieTokenRefreshView.as_view(),
        name="token_refresh",
    ),


    # ------------------------------------
    # 로그아웃
    # ------------------------------------

    path(
        "logout/",
        logout_view,
        name="logout",
    ),


    # ------------------------------------
    # 현재 사용자
    # ------------------------------------

    path(
        "me/",
        me_view,
        name="me",
    ),


    # ------------------------------------
    # CSRF
    # ------------------------------------

    path(
        "csrf/",
        csrf_view,
        name="csrf",
    ),


    # ------------------------------------
    # User API
    #
    # /api/users/
    # /api/users/{id}/
    # ------------------------------------

    path(
        "",
        include(
            router.urls
        ),
    ),
]