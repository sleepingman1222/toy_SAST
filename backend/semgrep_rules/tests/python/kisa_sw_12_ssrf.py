import requests
def unsafe(request):
    url = request.GET.get("url")
    # ruleid: kisa.sw12.python.external-input-to-http-client
    return requests.get(url)
def safe():
    # ok: kisa.sw12.python.external-input-to-http-client
    return requests.get("https://api.example.com/status")
