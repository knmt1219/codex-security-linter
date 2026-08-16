# Sample demonstration file for codex-security-linter
import os
import sqlite3

def get_user(username):
    # Safe parameterized query implementation
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

if __name__ == "__main__":
    user = get_user("admin")
    print(f"Found user: {user}")
