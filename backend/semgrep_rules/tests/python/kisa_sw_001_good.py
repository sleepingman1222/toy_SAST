import sqlite3

from django.http import HttpRequest


def find_user(
    request: HttpRequest
):

    user_id = (
        request.GET.get(
            "id"
        )
    )


    connection = (
        sqlite3.connect(
            "test.db"
        )
    )


    cursor = (
        connection.cursor()
    )


    query = (
        "SELECT * "
        "FROM users "
        "WHERE id = ?"
    )


    cursor.execute(
        query,
        (
            user_id,
        )
    )


    result = (
        cursor.fetchall()
    )


    connection.close()


    return result