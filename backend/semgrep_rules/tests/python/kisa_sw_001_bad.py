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
        "WHERE id = '"
        + user_id
        + "'"
    )


    cursor.execute(
        query
    )


    result = (
        cursor.fetchall()
    )


    connection.close()


    return result