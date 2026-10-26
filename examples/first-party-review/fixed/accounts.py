def find_account(connection, email):
    # SQLite receives the email as data, separate from SQL syntax.
    query = "SELECT id, email FROM accounts WHERE email = ?"
    return connection.execute(query, (email,)).fetchone()
