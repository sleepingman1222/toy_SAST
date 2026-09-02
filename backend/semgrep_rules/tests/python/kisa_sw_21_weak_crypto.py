import hashlib
def unsafe(data):
    # ruleid: kisa.sw21.python.weak-cryptographic-algorithm
    return hashlib.md5(data).hexdigest()
def safe(data):
    # ok: kisa.sw21.python.weak-cryptographic-algorithm
    return hashlib.sha256(data).hexdigest()
