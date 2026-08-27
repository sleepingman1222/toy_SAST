from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user
        data["username"] = user.username
        data["role"] = "admin" if user.is_staff else "user"
        return data


'''
username/ pw 검증
JWT 생성
추가로 username, role 넣어서 data 반환
'''