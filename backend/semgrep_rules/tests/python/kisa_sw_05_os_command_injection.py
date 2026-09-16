import os
import subprocess

from subprocess import (
    check_output,
)


def unsafe_os_system(request):
    host = request.GET.get("host")

    # ruleid: kisa.sw05.python.external-input-to-command
    os.system("ping -c 1 " + host)


def unsafe_shell_true(request):
    host = request.POST.get("host")

    command = (
        f"nslookup {host}"
    )

    # ruleid: kisa.sw05.python.external-input-to-command
    subprocess.run(command, check=False, shell=True)


def unsafe_multi_step(request):
    command = request.GET.get(
        "command"
    )

    copied_command = command

    second_copy = (
        copied_command
    )

    # ruleid: kisa.sw05.python.external-input-to-command
    subprocess.Popen(second_copy, text=True, shell=True)


def unsafe_os_popen(request):
    host = request.args.get("host")

    # ruleid: kisa.sw05.python.external-input-to-command
    return os.popen("dig " + host)


def unsafe_getoutput(request):
    host = request.form.get("host")

    command = (
        "ping -c 1 " + host
    )

    # ruleid: kisa.sw05.python.external-input-to-command
    return subprocess.getoutput(command)


def unsafe_imported_check_output(request):
    host = request.GET["host"]

    command = (
        "ping -c 1 " + host
    )

    # ruleid: kisa.sw05.python.external-input-to-command
    return check_output(command, shell=True)


def unsafe_cli_input():
    command = input(
        "command: "
    )

    # ruleid: kisa.sw05.python.external-input-to-command
    return os.system(command)


def safe_argument_array(request):
    host = request.GET.get("host")

    # ok: kisa.sw05.python.external-input-to-command
    return subprocess.run(
        [
            "ping",
            "-c",
            "1",
            host,
        ],
        shell=False,
        check=False,
    )


def safe_default_shell_false(request):
    host = request.GET.get("host")

    # ok: kisa.sw05.python.external-input-to-command
    return subprocess.run(
        [
            "ping",
            "-c",
            "1",
            host,
        ],
        check=False,
    )


def safe_hardcoded_shell():
    # ok: kisa.sw05.python.external-input-to-command
    return subprocess.run(
        "uptime",
        shell=True,
        check=False,
    )


def safe_unrelated_function(request):
    command = request.GET.get(
        "command"
    )

    def run(value, shell=False):
        return (
            value,
            shell,
        )

    # ok: kisa.sw05.python.external-input-to-command
    return run(
        command,
        shell=True,
    )
