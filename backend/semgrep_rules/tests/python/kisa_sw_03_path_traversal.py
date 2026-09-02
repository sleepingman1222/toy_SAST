import os
from pathlib import Path

def unsafe(request):
    path = request.GET.get("path")
    # ruleid: kisa.sw03.python.external-input-to-file-path
    return open(path, "r")

def safe(request, base):
    raw = request.GET.get("path")
    name = os.path.basename(raw)
    # ok: kisa.sw03.python.external-input-to-file-path
    return open(Path(base) / name, "r")
