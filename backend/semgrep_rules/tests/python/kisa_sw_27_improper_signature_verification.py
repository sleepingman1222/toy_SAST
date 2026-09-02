import jwt
def unsafe(token):
    # ruleid: kisa.sw27.python.signature-verification-disabled
    return jwt.decode(token, options={"verify_signature": False})
def safe(token, key):
    # ok: kisa.sw27.python.signature-verification-disabled
    return jwt.decode(token, key, algorithms=["RS256"])
