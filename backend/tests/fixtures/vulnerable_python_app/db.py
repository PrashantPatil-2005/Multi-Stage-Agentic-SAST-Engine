"""Database access helpers (fixture)."""

import sqlite3


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self.connection = None

    def connect(self) -> None:
        self.connection = sqlite3.connect(self.path)

    def execute(self, sql: str):
        if self.connection is None:
            raise RuntimeError("not connected")
        return self.connection.execute(sql)

    def query_users(self, user_id: str):
        return self.execute(f"SELECT * FROM users WHERE id = {user_id}")
