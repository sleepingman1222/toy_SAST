import ctypes
def unsafe(request):
    value = request.GET.get("value")
    # ruleid: kisa.sw14.python.external-input-to-fixed-width-integer
    return ctypes.c_int(int(value))
def safe(request):
    value = int(request.GET.get("value"))
    if value < -2147483648 or value > 2147483647:
        raise ValueError("out of range")
    # ok: kisa.sw14.python.external-input-to-fixed-width-integer
    return value
