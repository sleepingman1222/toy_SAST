import tempfile
def unsafe():
    # ruleid: kisa.sw49.python.dangerous-api-use
    return tempfile.mktemp()
def safe():
    # ok: kisa.sw49.python.dangerous-api-use
    return tempfile.NamedTemporaryFile()
