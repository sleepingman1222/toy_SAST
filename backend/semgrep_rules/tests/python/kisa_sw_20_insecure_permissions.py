import os
def unsafe(path):
    # ruleid: kisa.sw20.python.world-writable-permission
    os.chmod(path, 0o777)
def safe(path):
    # ok: kisa.sw20.python.world-writable-permission
    os.chmod(path, 0o600)
