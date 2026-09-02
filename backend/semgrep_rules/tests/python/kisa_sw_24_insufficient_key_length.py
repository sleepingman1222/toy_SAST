from Crypto.PublicKey import RSA
def unsafe():
    # ruleid: kisa.sw24.python.insufficient-rsa-key-length
    return RSA.generate(1024)
def safe():
    # ok: kisa.sw24.python.insufficient-rsa-key-length
    return RSA.generate(3072)
