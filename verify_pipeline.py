import unittest
import os
import sqlite3
from app import app, get_db_connection

class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Initialize DB with fresh tables
        conn = get_db_connection()
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM access_requests")
        conn.execute("DELETE FROM privileges")
        conn.execute("DELETE FROM datasets")
        
        # Create dataset
        conn.execute("INSERT INTO datasets (id, name, sensitivity, description) VALUES (1, 'Pipeline Data', 'High', 'Test Pipeline')")
        
        # Create Researcher
        import hashlib
        salt = os.urandom(16).hex()
        pw_hash = hashlib.sha256(('password' + salt).encode()).hexdigest()
        conn.execute("INSERT INTO users (fullname, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                     ("Res", "res@pipeline.com", pw_hash, salt, 'Researcher'))
                     
        # Create Admin
        salt_admin = os.urandom(16).hex()
        pw_hash_admin = hashlib.sha256(('password' + salt_admin).encode()).hexdigest()
        conn.execute("INSERT INTO users (fullname, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)",
                     ("Adm", "adm@pipeline.com", pw_hash_admin, salt_admin, 'Admin'))
                     
        conn.commit()
        conn.close()

    def login(self, email):
        resp = self.client.post('/login', data={'email': email, 'password': 'password'}, follow_redirects=True)
        if b'OTP' not in resp.data:
            print("Login failed, no OTP page")
            print(resp.data)
        with self.client.session_transaction() as sess:
            otp = sess['otp']
        self.client.post('/otp', data={'otp': otp}, follow_redirects=True)

    def test_full_pipeline(self):
        try:
            # 1. Login as Researcher
            self.login('res@pipeline.com')
            
            # 2. View Datasets (Should NOT be denied)
            resp = self.client.get('/datasets')
            if resp.status_code != 200:
                print("View Datasets Failed:", resp.status_code)
                print(resp.data)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'Pipeline Data', resp.data)
            self.assertIn(b'Not Authorized', resp.data)
            
            # 3. Request Access
            resp = self.client.post('/request-access', data={'dataset': '1', 'purpose': 'Test', 'duration': '1h'}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            print("STEP 3 PASS: Request Access")
            
            # 4. View Datasets again (Status should be Pending)
            resp = self.client.get('/datasets')
            if b'Requested' not in resp.data:
                 print("Requested button not found in datasets")
                 # Print first 500 chars of body to check what's there
                 print(resp.data[:1000])
            self.assertIn(b'Requested', resp.data)
            print("STEP 4 PASS: Pending Status")
            
            # Logout
            self.client.get('/logout')
            
            # 5. Login as Admin
            self.login('adm@pipeline.com')
            print("STEP 5 PASS: Admin Login")
            
            # 6. Approve Request
            conn = get_db_connection()
            req = conn.execute("SELECT id FROM access_requests WHERE status='Pending'").fetchone()
            conn.close()
            
            if not req:
                print("No pending request found for Admin to approve")
            req_id = req['id']
            
            resp = self.client.post('/approve-request', data={'request_id': req_id}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            print("STEP 6 PASS: Admin Approve")
            
            # Logout
            self.client.get('/logout')
            
            # 7. Login as Researcher again
            self.login('res@pipeline.com')
            print("STEP 7 PASS: Researcher Re-login")
            
            # 8. View Datasets (Status should be Authorized)
            # 8. View Datasets (Should NOT be authorized here, but in My Privileges)
            # The requirement is that /datasets only shows datasets WITHOUT active access.
            # So checking /my-privileges instead.
            resp = self.client.get('/my-privileges')
            if b'Active' not in resp.data:
                print("Active status not found in my-privileges page")
                print(resp.data)
                
            self.assertIn(b'Active', resp.data)
            self.assertIn(b'Access', resp.data)
            print("STEP 8 PASS: Authorized Status in My Privileges")
            
            # 9. Access Dataset
            resp = self.client.get('/access-dataset/1')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b'Access Granted', resp.data)
            print("STEP 9 PASS: Access Granted")
        except Exception as e:
            print(f"Test failed at step matching last PASS + 1")
            raise

if __name__ == '__main__':
    unittest.main()
