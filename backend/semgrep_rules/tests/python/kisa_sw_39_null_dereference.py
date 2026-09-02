def unsafe(request):
    # ruleid: kisa.sw39.python.nullable-get-result-dereference
    return request.GET.get("name").strip()
def safe(request):
    value = request.GET.get("name")
    # ok: kisa.sw39.python.nullable-get-result-dereference
    return value.strip() if value is not None else ""
