from django.urls import path

from .views import (
    CustomTokenObtainPairView,
    CookieTokenRefreshView,
    logout_view,
    me_view,
    csrf_view,
)


urlpatterns = [
    path(
        "login/",
        CustomTokenObtainPairView.as_view(),
        name="login",
    ),

    path(
        "token/refresh/",
        CookieTokenRefreshView.as_view(),
        name="token_refresh",
    ),

    path(
        "logout/",
        logout_view,
        name="logout",
    ),

    path(
        "me/",
        me_view,
        name="me",
    ),

    path(
        "csrf/",
        csrf_view,
        name="csrf",
    ),
]