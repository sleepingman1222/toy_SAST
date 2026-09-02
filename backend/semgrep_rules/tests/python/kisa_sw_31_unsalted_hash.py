import hashlib
def unsafe(password):
    # ruleid: kisa.sw31.python.password-hash-without-salt
    return hashlib.sha256(password.encode()).hexdigest()
def safe(password, salt):
    # ok: kisa.sw31.python.password-hash-without-salt
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
