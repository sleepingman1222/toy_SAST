def unsafe(password):
    # ruleid: kisa.sw26.python.weak-minimum-password-length
    return len(password) >= 6
def safe(password):
    # ok: kisa.sw26.python.weak-minimum-password-length
    return len(password) >= 12
