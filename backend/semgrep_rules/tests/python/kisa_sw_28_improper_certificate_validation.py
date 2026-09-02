import requests
def unsafe():
    # ruleid: kisa.sw28.python.certificate-validation-disabled
    return requests.get("https://example.com", verify=False)
def safe():
    # ok: kisa.sw28.python.certificate-validation-disabled
    return requests.get("https://example.com", verify=True)
