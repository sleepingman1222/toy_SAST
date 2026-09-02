def unsafe_eval():
    code = input(
        "code: "
    )

    # ruleid: kisa.sw02.python.external-input-to-eval-exec
    return eval(
        code
    )


def unsafe_exec():
    script = input(
        "script: "
    )

    # ruleid: kisa.sw02.python.external-input-to-eval-exec
    exec(
        script
    )


def unsafe_compile():
    source = input(
        "source: "
    )

    # ruleid: kisa.sw02.python.external-input-to-eval-exec
    compiled = compile(
        source,
        "<user-input>",
        "exec",
    )

    return compiled


def unsafe_django_get(
    request
):
    expression = (
        request.GET.get(
            "expression"
        )
    )

    # ruleid: kisa.sw02.python.external-input-to-eval-exec
    return eval(
        expression
    )


def unsafe_django_post(
    request
):
    script = (
        request.POST.get(
            "script"
        )
    )

    # ruleid: kisa.sw02.python.external-input-to-eval-exec
    exec(
        script
    )


def safe_value():
    value = input(
        "value: "
    )

    # ok: kisa.sw02.python.external-input-to-eval-exec
    return {
        "value":
            value
    }


def safe_mapping():
    action = input(
        "action: "
    )

    handlers = {
        "list":
            lambda: "list",

        "detail":
            lambda: "detail",
    }

    # ok: kisa.sw02.python.external-input-to-eval-exec
    handler = (
        handlers.get(
            action
        )
    )

    if handler is None:
        return None

    return handler()