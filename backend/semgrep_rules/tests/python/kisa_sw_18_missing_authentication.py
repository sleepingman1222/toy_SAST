from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.decorators import permission_classes

# ruleid: kisa.sw18.python.public-sensitive-endpoint-review
@permission_classes([AllowAny])
def unsafe(request):
    return "sensitive action"

# ok: kisa.sw18.python.public-sensitive-endpoint-review
@permission_classes([IsAuthenticated])
def safe(request):
    return "protected"
