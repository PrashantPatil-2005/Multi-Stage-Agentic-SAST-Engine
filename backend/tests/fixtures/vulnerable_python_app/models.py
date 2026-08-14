"""Data models (fixture)."""


class User:
    def __init__(self, user_id: int, name: str) -> None:
        self.id = user_id
        self.name = name

    def display_name(self) -> str:
        return self.name.title()

    @staticmethod
    def from_row(row) -> "User":
        return User(row[0], row[1])
