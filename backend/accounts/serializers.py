from django.contrib.auth import (
    get_user_model,
)

from django.contrib.auth.password_validation import (
    validate_password,
)

from rest_framework import serializers

from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
)


User = get_user_model()


# ========================================
# 로그인
# ========================================

class CustomTokenObtainPairSerializer(
    TokenObtainPairSerializer
):

    def validate(
        self,
        attrs,
    ):
        data = super().validate(
            attrs
        )

        user = self.user

        data["id"] = user.id

        data["username"] = (
            user.username
        )

        data["role"] = (
            "admin"
            if user.is_staff
            else "user"
        )

        return data


# ========================================
# 사용자 조회
#
# GET /api/users/
# GET /api/users/{id}/
# ========================================

class UserSerializer(
    serializers.ModelSerializer
):

    role = serializers.SerializerMethodField()

    isActive = serializers.BooleanField(
        source="is_active",
        read_only=True,
    )

    createdAt = serializers.DateTimeField(
        source="date_joined",
        read_only=True,
    )

    lastLogin = serializers.DateTimeField(
        source="last_login",
        read_only=True,
        allow_null=True,
    )


    class Meta:
        model = User

        fields = [
            "id",
            "username",
            "role",
            "isActive",
            "createdAt",
            "lastLogin",
        ]

        read_only_fields = [
            "id",
            "username",
            "role",
            "isActive",
            "createdAt",
            "lastLogin",
        ]


    def get_role(
        self,
        obj,
    ):
        return (
            "admin"
            if obj.is_staff
            else "user"
        )


# ========================================
# 사용자 생성
#
# POST /api/users/
# ========================================

class UserCreateSerializer(
    serializers.ModelSerializer
):

    password = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=False,
    )

    role = serializers.ChoiceField(
        choices=[
            "admin",
            "user",
        ],
        write_only=True,
        required=True,
    )


    class Meta:
        model = User

        fields = [
            "id",
            "username",
            "password",
            "role",
        ]

        read_only_fields = [
            "id",
        ]


    # ====================================
    # username 검증
    # ====================================

    def validate_username(
        self,
        value,
    ):
        value = value.strip()

        if not value:
            raise serializers.ValidationError(
                "아이디를 입력해주세요."
            )

        if User.objects.filter(
            username__iexact=value
        ).exists():
            raise serializers.ValidationError(
                "이미 사용 중인 아이디입니다."
            )

        return value


    # ====================================
    # 전체 입력 검증
    #
    # username을 포함해서
    # Django Password Validator 적용
    # ====================================

    def validate(
        self,
        attrs,
    ):
        attrs = super().validate(
            attrs
        )

        temporary_user = User(
            username=attrs.get(
                "username",
                "",
            )
        )

        validate_password(
            attrs.get(
                "password"
            ),
            user=temporary_user,
        )

        return attrs


    # ====================================
    # 사용자 생성
    # ====================================

    def create(
        self,
        validated_data,
    ):
        role = validated_data.pop(
            "role"
        )

        password = validated_data.pop(
            "password"
        )

        user = User.objects.create_user(
            password=password,

            is_staff=(
                role == "admin"
            ),

            is_active=True,

            **validated_data,
        )

        return user


    # ====================================
    # 생성 응답
    #
    # password 제외
    # ====================================

    def to_representation(
        self,
        instance,
    ):
        return UserSerializer(
            instance
        ).data


# ========================================
# 사용자 활성 상태 변경
#
# PATCH /api/users/{id}/
# ========================================

class UserActiveStatusSerializer(
    serializers.ModelSerializer
):

    isActive = serializers.BooleanField(
        source="is_active",
        required=True,
    )


    class Meta:
        model = User

        fields = [
            "isActive",
        ]


    def to_representation(
        self,
        instance,
    ):
        return UserSerializer(
            instance
        ).data