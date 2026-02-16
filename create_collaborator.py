import sqlite3
from app import get_db_connection
import hashlib
import os

def create_collaborator():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email='collab@lab.com'").fetchone()
    
    if not user:
        print("Creating Collaborator user...")
        salt = os.urandom(32).hex()
        # Password: Password123!
        password = "Password123!"
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            bytes.fromhex(salt),
            100000
        )
        password_hash = key.hex()
        
        conn.execute("INSERT INTO users (fullname, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                     ("Dr. Collab", "collab@lab.com", password_hash, salt, "Collaborator"))
        conn.commit()
        print("Collaborator 'collab@lab.com' created.")
    else:
        print("Collaborator 'collab@lab.com' already exists.")
        
    conn.close()

if __name__ == "__main__":
    create_collaborator()
