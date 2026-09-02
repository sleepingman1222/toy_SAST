import ctypes
def unsafe(lib, ptr):
    lib.free(ptr)
    # ruleid: kisa.sw41.python.native-use-after-free-review
    return ctypes.string_at(ptr, 8)
def safe(lib, ptr):
    data = ctypes.string_at(ptr, 8)
    lib.free(ptr)
    # ok: kisa.sw41.python.native-use-after-free-review
    return data
