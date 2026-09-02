import os
import subprocess

def unsafe(request):
    host = request.GET.get("host")
    # ruleid: kisa.sw05.python.external-input-to-command
    os.system("ping -c 1 " + host)

def safe(request):
    host = request.GET.get("host")
    # ok: kisa.sw05.python.external-input-to-command
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
