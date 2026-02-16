import unittest
import os
import tempfile
import sqlite3
from flask import session
from app import app, get_db_connection

class AuthTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Ensure tables exist
        conn = get_db_connection()
        conn.execute('''CREATE TABLE IF NOT EXISTS datasets 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, sensitivity TEXT, description TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS access_requests 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, dataset_id INTEGER, purpose TEXT, duration INTEGER, status TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS privileges 
            (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, dataset_id INTEGER, expiry_time TEXT, status TEXT)''')
            
        # Insert test dataset
        conn.execute("INSERT OR IGNORE INTO datasets (id, name, sensitivity, description) VALUES (999, 'Test Dataset', 'Low', 'Test Desc')")
        conn.commit()
        conn.close()

    def tearDown(self):
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE email LIKE '%@example.com'")
        conn.execute("DELETE FROM datasets WHERE id = 999")
        conn.execute("DELETE FROM access_requests")
        conn.execute("DELETE FROM privileges")
        conn.commit()
        conn.close()

    def register_and_login(self, email, role, fullname="Test User"):
        # Register
        self.client.post('/register', data={
            'fullname': fullname,
            'email': email,
            'password': 'password123',
            'role': role
        }, follow_redirects=True)

        # Login
        self.client.post('/login', data={
            'email': email,
            'password': 'password123'
        }, follow_redirects=True)

        # Get OTP
        with self.client.session_transaction() as sess:
            if 'otp' in sess:
                otp = sess['otp']
                self.client.post('/otp', data={'otp': otp}, follow_redirects=True)

    def test_workflow(self):
        # 1. Researcher registers and logins
        self.register_and_login('res@example.com', 'Researcher', 'Researcher Alice')
        
        # 2. Researcher requests access
        response = self.client.post('/request-access', data={
            'dataset': '999',
            'purpose': 'Testing',
            'duration': '1h'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify Pending Request in DB
        conn = get_db_connection()
        req = conn.execute("SELECT * FROM access_requests WHERE status='Pending'").fetchone()
        self.assertIsNotNone(req)
        req_id = req['id']
        conn.close()
        
        # 3. Researcher tries to access dataset (Should be denied)
        response = self.client.get('/access-dataset?id=999')
        self.assertEqual(response.status_code, 403)
        self.assertIn(b'Access Denied', response.data) # No valid privilege
        
        # 4. Admin registers/logins (Manually insert admin first)
        conn = get_db_connection()
        import hashlib
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256(('password123' + salt).encode()).hexdigest()
        conn.execute('INSERT INTO users (fullname, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)',
                     ('Admin', 'admin@example.com', password_hash, salt, 'Admin'))
        conn.commit()
        conn.close()
        
        self.client.get('/logout') # Logout researcher
        self.client.post('/login', data={'email': 'admin@example.com', 'password': 'password123'})
        with self.client.session_transaction() as sess:
            otp = sess['otp']
        self.client.post('/otp', data={'otp': otp}, follow_redirects=True)
        
        # 5. Admin approves request
        response = self.client.post('/admin-approvals', data={
            'req_id': req_id,
            'action': 'approve'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # 6. Researcher logs in again
        self.client.get('/logout')
        self.client.post('/login', data={'email': 'res@example.com', 'password': 'password123'})
        with self.client.session_transaction() as sess:
            otp = sess['otp']
        self.client.post('/otp', data={'otp': otp}, follow_redirects=True)
        
        # 7. Researcher accesses dataset (Should be granted)
        response = self.client.get('/access-dataset?id=999')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Access Granted', response.data)

if __name__ == '__main__':
    unittest.main()
