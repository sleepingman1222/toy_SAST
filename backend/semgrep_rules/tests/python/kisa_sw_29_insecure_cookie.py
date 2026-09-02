def unsafe(response):
    # ruleid: kisa.sw29.python.insecure-cookie-flags
    response.set_cookie("session", "value", secure=False)
def safe(response):
    # ok: kisa.sw29.python.insecure-cookie-flags
    response.set_cookie("session", "value", secure=True, httponly=True, samesite="Lax")
