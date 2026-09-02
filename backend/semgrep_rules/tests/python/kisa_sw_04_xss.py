from django.http import HttpResponse
from django.utils.html import escape

def unsafe(request):
    value = request.GET.get("q")
    # ruleid: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(value)

def safe(request):
    value = escape(request.GET.get("q"))
    # ok: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(value)
