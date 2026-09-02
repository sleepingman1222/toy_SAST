def unsafe():
    value: int
    # ruleid: kisa.sw42.python.annotation-without-value-use-review
    return value

def safe():
    value: int = 0
    # ok: kisa.sw42.python.annotation-without-value-use-review
    return value
