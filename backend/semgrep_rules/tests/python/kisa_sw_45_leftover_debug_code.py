def unsafe():
    # ruleid: kisa.sw45.python.debug-code-leftover
    breakpoint()
def safe():
    # ok: kisa.sw45.python.debug-code-leftover
    return "ok"
