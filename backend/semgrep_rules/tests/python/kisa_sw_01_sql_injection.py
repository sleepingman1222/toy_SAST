def unsafe_concat(cursor, user_id):
    # ruleid: kisa.sw01.python.dbapi-string-built-query
    cursor.execute(
        "SELECT * FROM users WHERE id = "
        + user_id
    )


def unsafe_percent(cursor, username):
    # ruleid: kisa.sw01.python.dbapi-string-built-query
    cursor.execute(
        "SELECT * FROM users WHERE username = '%s'"
        % username
    )


def safe_parameter(cursor, user_id):
    # ok: kisa.sw01.python.dbapi-string-built-query
    cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        [user_id],
    )
