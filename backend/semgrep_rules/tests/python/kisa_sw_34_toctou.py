import os
def unsafe(path):
    if os.path.exists(path):
        # ruleid: kisa.sw34.python.check-then-use-file
        return open(path, "r")
def safe(path):
    # ok: kisa.sw34.python.check-then-use-file
    try:
        return open(path, "x")
    except FileExistsError:
        return None
