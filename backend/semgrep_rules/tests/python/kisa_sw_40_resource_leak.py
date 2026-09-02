def unsafe(path):
    # ruleid: kisa.sw40.python.file-handle-without-context-review
    f = open(path, "r")
    return f.read()

def safe(path):
    # ok: kisa.sw40.python.file-handle-without-context-review
    with open(path, "r") as f:
        return f.read()
