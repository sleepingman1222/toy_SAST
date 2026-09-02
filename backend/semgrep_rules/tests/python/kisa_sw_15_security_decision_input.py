def unsafe(request):
    # ruleid: kisa.sw15.python.external-input-controls-security-decision
    if request.GET.get("role") == "admin":
        return "secret"
    return "denied"

def safe(request):
    # ok: kisa.sw15.python.external-input-controls-security-decision
    if request.user.is_staff:
        return "secret"
    return "denied"
