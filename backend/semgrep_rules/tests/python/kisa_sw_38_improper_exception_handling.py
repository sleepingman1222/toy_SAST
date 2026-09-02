def unsafe():
    try:
        return risky()
    except Exception:
        # ruleid: kisa.sw38.python.overbroad-exception-default-return
        return None
def safe():
    try:
        return risky()
    except ValueError:
        # ok: kisa.sw38.python.overbroad-exception-default-return
        raise
def risky():
    raise ValueError()
