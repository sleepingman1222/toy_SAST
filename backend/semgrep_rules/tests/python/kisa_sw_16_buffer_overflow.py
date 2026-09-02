import ctypes
def unsafe(dst, src, size):
    # ruleid: kisa.sw16.python.native-memory-operation-review
    ctypes.memmove(dst, src, size)
def safe(data):
    # ok: kisa.sw16.python.native-memory-operation-review
    return bytes(data)
