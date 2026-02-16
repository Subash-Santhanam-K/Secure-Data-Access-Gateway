import sqlite3

def update_schema():
    db_path = 'database.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("Checking 'privileges' table schema...")
        cursor.execute("PRAGMA table_info(privileges)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'granted_by' not in columns:
            print("Adding 'granted_by' column to 'privileges' table...")
            cursor.execute("ALTER TABLE privileges ADD COLUMN granted_by TEXT")
            conn.commit()
            print("Schema updated successfully.")
        else:
            print("'granted_by' column already exists.")
            
    except Exception as e:
        print(f"Error updating schema: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    update_schema()
