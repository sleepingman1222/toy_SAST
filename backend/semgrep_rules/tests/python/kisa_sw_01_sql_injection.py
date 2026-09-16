def unsafe_concat(cursor, request):
    user_id = request.GET.get("id")

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute("SELECT * FROM users WHERE id = " + user_id)


def unsafe_percent(cursor, request):
    username = request.POST.get("username")

    sql = (
        "SELECT * FROM users WHERE username = '%s'"
        % username
    )

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(sql)


def unsafe_format(cursor, request):
    status = request.args.get("status")

    sql = "SELECT * FROM users WHERE status = '{}'".format(
        status
    )

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(sql)


def unsafe_fstring(cursor, request):
    role = request.form.get("role")

    sql = f"SELECT * FROM users WHERE role = '{role}'"

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(sql)


def unsafe_multi_step(cursor, request):
    order_by = request.GET.get("sort")

    sql = (
        "SELECT * FROM users ORDER BY "
        + order_by
    )

    copied_sql = sql
    second_copy = copied_sql

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(second_copy)


def unsafe_direct_sql(cursor, request):
    sql = request.POST.get("sql")

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(sql)


def unsafe_django_raw(User, request):
    name = request.GET.get("name")

    sql = (
        "SELECT * FROM auth_user WHERE username = '"
        + name
        + "'"
    )

    # ruleid: kisa.sw01.python.dbapi-string-built-query
    return User.objects.raw(sql)


def safe_parameter_binding(cursor, request):
    user_id = request.GET.get("id")

    # ok: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        [user_id],
    )


def safe_named_binding(cursor, request):
    username = request.GET.get("username")

    # ok: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(
        "SELECT * FROM users WHERE username = %(username)s",
        {
            "username": username,
        },
    )


def safe_hardcoded(cursor):
    # ok: kisa.sw01.python.dbapi-string-built-query
    return cursor.execute(
        "SELECT id, username FROM users"
    )


def safe_django_orm(User, request):
    user_id = request.GET.get("id")

    # ok: kisa.sw01.python.dbapi-string-built-query
    return User.objects.filter(
        id=user_id
    )
