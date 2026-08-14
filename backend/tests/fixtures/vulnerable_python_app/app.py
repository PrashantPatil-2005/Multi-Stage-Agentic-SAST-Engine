"""Demo web application fixture for the SAST engine.

Contains intentionally vulnerable patterns (SQLi, command injection, SSRF)
for later SCAN-stage testing. NEVER execute this file.
"""

import os
import sqlite3
import subprocess


def get_user(user_id: str) -> dict:
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return {}
    return {"id": row[0], "name": row[1]}


def get_user_safe(user_id: int) -> dict:
    conn = sqlite3.connect("app.db")
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return {}
    return {"id": row[0], "name": row[1]}


def run_command(cmd: str) -> None:
    subprocess.run(cmd, shell=True)


def fetch_url(url: str) -> str:
    import requests

    response = requests.get(url, timeout=5)
    return response.text


def fetch_safe() -> str:
    import requests

    return requests.get("https://example.com").text


def run_command_safe() -> None:
    subprocess.run("ls -la", shell=True)
