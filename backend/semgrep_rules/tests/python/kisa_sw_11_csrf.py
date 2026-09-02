from django.views.decorators.csrf import csrf_exempt

# ruleid: kisa.sw11.python.csrf-protection-disabled
@csrf_exempt
def unsafe(request):
    return "changed"

def safe(request):
    # ok: kisa.sw11.python.csrf-protection-disabled
    return "protected"
