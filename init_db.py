import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS datasets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            description TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            dataset_id INTEGER,
            purpose TEXT,
            duration INTEGER,
            status TEXT DEFAULT 'Pending'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS privileges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            dataset_id INTEGER,
            expiry_time TEXT,
            status TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            timestamp TEXT
        )
    ''')


    # Check if datasets exist, if not insert samples
    cursor.execute('SELECT count(*) FROM datasets')
    if cursor.fetchone()[0] == 0:
        sample_datasets = [
            ('Genomics Research Data', 'High', 'Human genome sequencing datasets'),
            ('AI Model Training Data', 'Medium', 'Large-scale AI training datasets'),
            ('Climate Research Dataset', 'Low', 'Climate and weather historical data')
        ]
        cursor.executemany('INSERT INTO datasets (name, sensitivity, description) VALUES (?, ?, ?)', sample_datasets)
        print("Sample datasets inserted.")
        
    conn.commit()
    conn.close()
    
    # Encrypt datasets
    import crypto_utils
    import os
    
    cipher = crypto_utils.get_cipher()
    
    # Get all dataset IDs (re-connect since we closed it)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    datasets = cursor.execute('SELECT id, name FROM datasets').fetchall()
    
    for row in datasets:
        dataset_id = row[0]
        name = row[1]
        file_path = f"secure_data/dataset_{dataset_id}.enc"
        
        if not os.path.exists(file_path):
            plaintext = f"This is confidential research data for {name}.\nOnly authorized researchers can read this."
            encrypted_data = cipher.encrypt(plaintext.encode())
            
            with open(file_path, "wb") as f:
                f.write(encrypted_data)
            print(f"Encrypted data created for Dataset {dataset_id}")
            
    conn.close()

    print("Database initialized successfully.")

    # Ensure Admin exists
    from reset_admin import reset_admin
    reset_admin()

if __name__ == "__main__":
    init_db()
