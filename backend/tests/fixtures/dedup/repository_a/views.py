from flask import request


def fetch_user():
    query = f"SELECT * FROM users WHERE id = {request.args.get('user_id')}"
    cursor.execute(query)