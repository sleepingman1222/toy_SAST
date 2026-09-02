import random
import secrets
def unsafe():
    # ruleid: kisa.sw25.python.insecure-random-for-security
    return random.randint(100000, 999999)
def safe():
    # ok: kisa.sw25.python.insecure-random-for-security
    return secrets.randbelow(900000) + 100000
