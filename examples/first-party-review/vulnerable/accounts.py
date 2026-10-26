def find_account(connection, email):
    # A caller's email becomes SQL syntax.
    query = f"SELECT id, email FROM accounts WHERE email = '{email}'"
    return connection.execute(query).fetchone()
