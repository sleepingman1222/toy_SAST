import httpx
import requests
import urllib.request


def unsafe_requests_get(request):
    url = request.GET.get("url")

    # ruleid: kisa.sw12.python.external-input-to-http-client
    return requests.get(url)


def unsafe_requests_method(request):
    url = request.POST["callback_url"]
    method = request.POST.get("method")

    # ruleid: kisa.sw12.python.external-input-to-http-client
    return requests.request(method, url, timeout=5)


def unsafe_httpx_multistep(request):
    target = request.headers.get("X-Target-URL")
    copied_target = target

    # ruleid: kisa.sw12.python.external-input-to-http-client
    return httpx.post(copied_target, json={"status": "ready"})


def unsafe_urllib(request):
    target = request.args["url"]

    # ruleid: kisa.sw12.python.external-input-to-http-client
    return urllib.request.urlopen(target, timeout=5)


def safe_hardcoded_requests():
    # ok: kisa.sw12.python.external-input-to-http-client
    return requests.get("https://api.example.com/status")


def safe_hardcoded_httpx():
    # ok: kisa.sw12.python.external-input-to-http-client
    return httpx.get("https://api.example.com/status")
