from django.http import HttpResponse
def unsafe():
    try:
        1 / 0
    except Exception as e:
        # ruleid: kisa.sw36.python.exception-detail-to-response
        return HttpResponse(str(e))
def safe():
    try:
        1 / 0
    except Exception:
        # ok: kisa.sw36.python.exception-detail-to-response
        return HttpResponse("internal error", status=500)
