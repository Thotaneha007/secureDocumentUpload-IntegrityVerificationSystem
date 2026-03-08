import sqlite3
import os
import sys

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
        print("Column mfa_secret added")
    except sqlite3.OperationalError:
        print("Column mfa_secret already exists")

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        print("Column role added")
    except sqlite3.OperationalError:
        print("Column role already exists")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
