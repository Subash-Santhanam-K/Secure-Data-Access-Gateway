import sqlite3
import os

def cleanup():
    if os.path.exists('database.db'):
        conn = sqlite3.connect('database.db')
        conn.execute('DELETE FROM access_requests')
        conn.execute('DELETE FROM privileges')
        # Also clean users to ensure we create fresh ones for testing
        conn.execute("DELETE FROM users WHERE email LIKE '%@example.com' OR email LIKE '%@lab.com'")
        conn.commit()
        conn.close()
        print("Cleanup done.")
    else:
        print("No database found.")

if __name__ == "__main__":
    cleanup()
