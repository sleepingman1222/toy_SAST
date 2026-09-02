current_user_data = None
def unsafe(request):
    global current_user_data
    # ruleid: kisa.sw44.python.request-data-to-global-state-review
    current_user_data = request.GET.get("profile")
    return current_user_data
def safe(request):
    # ok: kisa.sw44.python.request-data-to-global-state-review
    return {"profile": request.GET.get("profile")}
