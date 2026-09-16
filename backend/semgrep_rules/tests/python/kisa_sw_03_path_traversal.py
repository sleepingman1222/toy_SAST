import os
from pathlib import Path
import shutil

from flask import send_file
from werkzeug.utils import secure_filename


def unsafe_open(request):
    path = request.GET.get("path")

    # ruleid: kisa.sw03.python.external-input-to-file-path
    return open(path, "r")


def unsafe_resolve_only(request, base):
    raw = request.GET.get("path")

    candidate = (
        Path(base) / raw
    ).resolve()

    # resolve만으로는 base containment가 보장되지 않는다.
    # ruleid: kisa.sw03.python.external-input-to-file-path
    return open(candidate, "r")


def unsafe_multi_step(request):
    raw = request.args.get("path")

    first = raw
    second = first

    # ruleid: kisa.sw03.python.external-input-to-file-path
    return open(second, "rb")


def unsafe_remove(request):
    target = request.POST.get("target")

    # ruleid: kisa.sw03.python.external-input-to-file-path
    os.remove(target)


def unsafe_send_file(request):
    target = request.args.get("file")

    # ruleid: kisa.sw03.python.external-input-to-file-path
    return send_file(target)


def unsafe_copy_destination(request):
    target = request.form.get("output")

    # ruleid: kisa.sw03.python.external-input-to-file-path
    return shutil.copyfile("/srv/app/template.txt", target)


def safe_basename(request, base):
    raw = request.GET.get("path")

    name = os.path.basename(raw)
    target = Path(base) / name

    # ok: kisa.sw03.python.external-input-to-file-path
    return open(target, "r")


def safe_path_name(request, base):
    raw = request.GET.get("path")

    name = Path(raw).name
    target = Path(base) / name

    # ok: kisa.sw03.python.external-input-to-file-path
    return target.read_text()


def safe_secure_filename(request, base):
    raw = request.args.get("file")

    name = secure_filename(raw)
    target = Path(base) / name

    # ok: kisa.sw03.python.external-input-to-file-path
    return open(target, "rb")


def safe_hardcoded():
    # ok: kisa.sw03.python.external-input-to-file-path
    return open(
        "/srv/app/public/help.txt",
        "r",
    )
