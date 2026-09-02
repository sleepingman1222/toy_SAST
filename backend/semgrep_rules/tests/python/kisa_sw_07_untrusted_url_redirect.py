from django.shortcuts import redirect

def unsafe(request):
    url = request.GET.get("next")
    # ruleid: kisa.sw07.python.external-input-to-redirect
    return redirect(url)

def safe(request):
    # ok: kisa.sw07.python.external-input-to-redirect
    return redirect("/home")
