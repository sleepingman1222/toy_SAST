def unsafe(request):
    fmt = request.GET.get("fmt")
    # ruleid: kisa.sw17.python.external-input-as-format-string
    return fmt % ("value",)
def safe(request):
    value = request.GET.get("value")
    # ok: kisa.sw17.python.external-input-as-format-string
    return "value=%s" % value
