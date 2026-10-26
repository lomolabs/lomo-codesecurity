import sqlite3


def lookup_user(user_id: int) -> list[tuple[object, ...]]:
    connection = sqlite3.connect("users.db")
    return connection.execute(
        "select id, email from users where id = ?",
        (user_id,),
    ).fetchall()
