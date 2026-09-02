import socket
def unsafe(host, trusted):
    ip = socket.gethostbyname(host)
    # ruleid: kisa.sw48.python.dns-result-used-for-security-decision-review
    if ip == trusted:
        return True
    return False
def safe(cert_ok):
    # ok: kisa.sw48.python.dns-result-used-for-security-decision-review
    return cert_ok
