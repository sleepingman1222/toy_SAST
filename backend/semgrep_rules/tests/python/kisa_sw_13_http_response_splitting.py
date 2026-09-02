def unsafe(request, response):
    value = request.GET.get("value")
    # ruleid: kisa.sw13.python.external-input-to-response-header
    response["X-User"] = value
    return response

def safe(response):
    # ok: kisa.sw13.python.external-input-to-response-header
    response["X-User"] = "fixed"
    return response
