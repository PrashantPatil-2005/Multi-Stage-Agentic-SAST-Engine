"""Fixture with concatenated SQL patterns for remediation testing.

Patterns covered:
1. Simple concatenation: sql = "..." + variable
2. Chained concatenation: sql = "..." + var1 + "..." + var2
3. Conditional clause: sql += "..." + variable (augmented assignment)
4. Mixed = and +=: initial query + conditional WHERE clause
"""

import sqlite3


def query_by_name(customer_name: str):
    """Simple string concatenation (the sast-multiservice pattern)."""
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM orders WHERE customer = '" + customer_name + "'"
    conn.execute(sql)
    conn.close()


def query_with_status(customer_name: str, status: str):
    """Chained concatenation with two variables."""
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM orders WHERE customer = '" + customer_name + "' AND status = '" + status + "'"
    conn.execute(sql)
    conn.close()


def query_conditional(customer_name: str, status: str):
    """Base query + conditional clause via +=."""
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM orders"
    sql += " WHERE customer = '" + customer_name + "'"
    if status:
        sql += " AND status = '" + status + "'"
    conn.execute(sql)
    conn.close()


def query_mixed(customer_name: str, active_only: bool):
    """Mixed = and += with a boolean conditional."""
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE name = '" + customer_name + "'"
    if active_only:
        sql += " AND active = 1"
    conn.execute(sql)
    conn.close()
