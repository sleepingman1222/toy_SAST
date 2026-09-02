def unsafe():
    try:
        risky()
    except Exception:
        # ruleid: kisa.sw37.python.swallowed-exception
        pass

def safe():
    try:
        risky()
    except Exception:
        # ok: kisa.sw37.python.swallowed-exception
        raise

def risky():
    return 1
