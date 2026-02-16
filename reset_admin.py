import sqlite3
import hashlib
import os

def reset_admin():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # 1. Check for existing Admins
    cursor.execute("SELECT id FROM users WHERE role = 'Admin'")
    admins = cursor.fetchall()
    
    # 2. Prepare new credentials
    password = 'admin123'
    salt = os.urandom(16).hex()
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    
    fullname = 'System Administrator'
    email = 'admin@lab.com'
    role = 'Admin'
    
    if not admins:
        # Create new admin
        print("No Admin found. Creating new Admin.")
        cursor.execute("INSERT INTO users (fullname, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                       (fullname, email, password_hash, salt, role))
    else:
        # Update first admin, delete others
        print(f"Found {len(admins)} Admin(s). Updating the first one and removing others if any.")
        admin_id = admins[0][0]
        
        # Update the main admin
        cursor.execute("""
            UPDATE users 
            SET fullname = ?, email = ?, password_hash = ?, salt = ?
            WHERE id = ?
        """, (fullname, email, password_hash, salt, admin_id))
        
        # Remove duplicates if any
        if len(admins) > 1:
            other_ids = [str(a[0]) for a in admins[1:]]
            cursor.execute(f"DELETE FROM users WHERE id IN ({','.join(other_ids)})")
            print(f"Removed {len(other_ids)} duplicate Admin(s).")

    conn.commit()
    
    # 3. Verify
    print("\nVerifying Admin Account:")
    cursor.execute("SELECT id, fullname, email, role FROM users WHERE role = 'Admin'")
    row = cursor.fetchone()
    if row:
        print(f"ID: {row[0]}, Name: {row[1]}, Email: {row[2]}, Role: {row[3]}")
    else:
        print("Error: Admin verification failed.")
        
    conn.close()

if __name__ == "__main__":
    reset_admin()
