from flask import request


def get_status():

    return "OK"


def get_version():

    return "1.0"


def execute():

    action = request.args.get(
        "action"
    )

    allowed_actions = {
        "status": get_status,
        "version": get_version,
    }

    handler = allowed_actions.get(
        action
    )

    if handler is None:

        raise ValueError(
            "허용되지 않은 요청입니다."
        )

    return handler()
