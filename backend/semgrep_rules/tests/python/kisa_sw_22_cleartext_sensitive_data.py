import requests
def unsafe(payload):
    # ruleid: kisa.sw22.python.cleartext-http-transport-review
    return requests.post("http://api.example.com/login", data=payload)
def safe(payload):
    # ok: kisa.sw22.python.cleartext-http-transport-review
    return requests.post("https://api.example.com/login", data=payload)
