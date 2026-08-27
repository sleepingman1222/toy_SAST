from rest_framework.permissions import (
    BasePermission,
)


class IsAdminRole(BasePermission):
    message = "관리자 권한이 필요합니다."

    def has_permission(
        self,
        request,
        view,
    ):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.is_staff
        )