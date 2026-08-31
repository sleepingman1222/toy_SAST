from flask import request


def execute():

    code = request.args.get(
        "code"
    )

    return eval(
        code
    )
