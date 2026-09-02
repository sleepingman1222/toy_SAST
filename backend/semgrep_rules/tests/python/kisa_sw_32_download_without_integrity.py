import requests
def unsafe(url):
    # ruleid: kisa.sw32.python.downloaded-code-executed-review
    exec(requests.get(url).text)
def safe(url):
    code = requests.get(url).content
    # hash/signature verification omitted in this fixture
    # ok: kisa.sw32.python.downloaded-code-executed-review
    return code
