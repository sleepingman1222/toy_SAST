def login(request):
    # ruleid: kisa.sw33.python.login-handler-rate-limit-review
    user = authenticate(username=request.POST.get("username"), password=request.POST.get("password"))
    return user

def health(request):
    # ok: kisa.sw33.python.login-handler-rate-limit-review
    return "ok"
