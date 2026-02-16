from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
import random
from datetime import datetime, timedelta
from datetime import datetime, timedelta
import crypto_utils
import encoding_utils


app = Flask(__name__)
app.secret_key = "secure_gateway_secret"

# Configure logging
import logging
logging.basicConfig(level=logging.INFO, format='%(message)s') # Simplified format for console clarity as requested



logger = app.logger

# NIST SP 800-63B Compliance
# This password system follows NIST guidelines by:
# • Enforcing minimum length (8 characters)
# • Blocking known weak passwords (common_passwords.txt)
# • Allowing passphrases (no complexity rules forced)
# • Using salted hashing for storage (SHA-256)
# • Applying rate limiting to prevent brute-force attacks (5 attempts / 5 mins)
# • Avoiding outdated complexity rules (no forced special chars/numbers)

# Load common passwords
try:
    with open("common_passwords.txt", "r") as f:
        COMMON_PASSWORDS = set(line.strip().lower() for line in f)
except FileNotFoundError:
    print("Warning: common_passwords.txt not found. Weak password checks disabled.")
    COMMON_PASSWORDS = set()

# Rate limiting storage (In-memory for simplicity)
# Format: {email: {"count": int, "blocked_until": datetime}}
login_attempts = {}

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if password.lower() in COMMON_PASSWORDS:
        return False, "This password is too common and insecure. Please choose a stronger one."

    return True, ""

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_action(user_id, action):
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO audit_logs (user_id, action, timestamp)
            VALUES (?, ?, ?)
        """, (user_id, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging action: {e}")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return "Missing form data", 400
            
        # Rate Limiting Check
        if email in login_attempts:
            attempt_data = login_attempts[email]
            if attempt_data["blocked_until"] and datetime.now() < attempt_data["blocked_until"]:
                flash("Account locked due to too many failed attempts.", "error")
                return render_template("login.html", 
                                       lockout_end_time=attempt_data["blocked_until"].timestamp(),
                                       attempts_remaining=0)
            
            # Reset if block expired
            if attempt_data["blocked_until"] and datetime.now() > attempt_data["blocked_until"]:
                 login_attempts.pop(email)
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user:
            salt = user['salt']
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            
            if password_hash == user['password_hash']:
                # Success - Reset rate limit
                if email in login_attempts:
                    login_attempts.pop(email)
                    
                session['user_id'] = user['id']
                session['role'] = user['role']
                session['email'] = user['email']
                session['fullname'] = user['fullname']
                
                # generate OTP
                try:
                    otp = str(random.randint(100000, 999999))
                    session["otp"] = otp
                    session["otp_verified"] = False
                    session["otp_email"] = user['email']
                    
                    # OTP Logging
                    app.logger.warning(f"[OTP] Generated for {user['email']} : {otp}")
                    app.logger.info(f"[AUTH] User logged in: {user['email']}")
                    
                except Exception as e:
                    app.logger.error(f"[ERROR] OTP Generation failed: {e}")
                    return "Internal Server Error: OTP Failed", 500
                
                log_action(user['id'], "User logged in (Password verified)")
                
                return redirect(url_for('otp'))
        
                        
        # Failed Login
        if email not in login_attempts:
            login_attempts[email] = {"count": 0, "blocked_until": None}
        
        login_attempts[email]["count"] += 1
        
        if login_attempts[email]["count"] >= 5:
            login_attempts[email]["blocked_until"] = datetime.now() + timedelta(minutes=5)
            flash("Account locked due to too many failed attempts.", "error")
            return render_template("login.html", 
                                   lockout_end_time=login_attempts[email]["blocked_until"].timestamp(),
                                   attempts_remaining=0)

        attempts_remaining = 5 - login_attempts[email]["count"]
        flash(f"Invalid credentials. {attempts_remaining} attempts remaining.", "error")
        return render_template("login.html", attempts_remaining=attempts_remaining)
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if not fullname or not email or not password or not role:
            return "Missing form data", 400
        
        is_valid, msg = validate_password(password)
        if not is_valid:
            return msg, 400
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            conn.close()
            return "Email already exists", 400
        
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        conn.execute('INSERT INTO users (fullname, email, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)',
                     (fullname, email, password_hash, salt, role))
        conn.commit()
        conn.close()
        
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
        
    import json
    return render_template("register.html", common_passwords_json=json.dumps(list(COMMON_PASSWORDS)))

@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "User logged out")
        app.logger.info(f"[AUTH] User logged out: {session.get('email', 'unknown')}")
    session.clear()
    return redirect(url_for("login"))

@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        user_otp = request.form.get("otp")
        stored_otp = session.get("otp")
        
        if user_otp == stored_otp:
            session["otp_verified"] = True
            log_action(session["user_id"], "OTP verified successfully")
            app.logger.info(f"[OTP] Verified successfully for {session.get('otp_email', 'unknown')}")
            flash('Identity verified. Access granted.', 'success')
            return redirect(url_for("dashboard"))
        else:
            log_action(session["user_id"], "OTP verification failed")
            app.logger.warning(f"[OTP] Verification failed for {session.get('otp_email', 'unknown')}")
            flash('Invalid OTP. Please try again.', 'error')
            
    return render_template("otp.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    return render_template("dashboard.html",
                           role=session.get("role"),
                           fullname=session.get("fullname"))

@app.route("/admin/grant-access", methods=["GET", "POST"])
def grant_access():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    if session.get("role") != "Admin":
        return "Access Denied", 403
        
    conn = get_db_connection()
    
    if request.method == "POST":
        user_id = request.form.get("user_id")
        dataset_id = request.form.get("dataset_id")
        duration = int(request.form.get("duration"))
        
        # Calculate expiry
        expiry_time = datetime.now() + timedelta(hours=duration)
        
        # Check existing privilege
        existing = conn.execute("SELECT id FROM privileges WHERE user_id=? AND dataset_id=?", (user_id, dataset_id)).fetchone()
        
        if existing:
            conn.execute("""
                UPDATE privileges 
                SET status='Active', expiry_time=?, granted_by='Admin'
                WHERE id=?
            """, (expiry_time.strftime("%Y-%m-%d %H:%M:%S"), existing['id']))
        else:
            conn.execute("""
                INSERT INTO privileges (user_id, dataset_id, expiry_time, status, granted_by)
                VALUES (?, ?, ?, 'Active', 'Admin')
            """, (user_id, dataset_id, expiry_time.strftime("%Y-%m-%d %H:%M:%S")))
            
        conn.commit()
        
        # Get user email for logging
        user = conn.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
        
        log_action(session['user_id'], f"Admin granted dataset {dataset_id} to user {user['email']}")
        app.logger.info(f"[ADMIN] Granted dataset {dataset_id} to {user['email']} for {duration} hours")
        
        flash("Access granted successfully.", "success")
        return redirect("/admin/grant-access")
        
    # GET: fetch users and datasets
    users = conn.execute("SELECT id, fullname, email, role FROM users WHERE role IN ('Collaborator', 'Researcher')").fetchall()
    datasets = conn.execute("SELECT id, name, sensitivity FROM datasets").fetchall()
    conn.close()
    
    return render_template("grant_access.html", users=users, datasets=datasets)

@app.route("/datasets")
def datasets():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    if session.get("role") not in ["Researcher", "Collaborator", "researcher", "collaborator"]:
        return "Access Denied", 403
        
    conn = get_db_connection()
    
    # Collaborator Restriction: ONLY see datasets they have access to (Active or Expired)
    if session.get("role") == "Collaborator":
        datasets_rows = conn.execute('''
            SELECT * FROM datasets 
            WHERE id IN (
                SELECT dataset_id FROM privileges 
                WHERE user_id = ?
            )
        ''', (session['user_id'],)).fetchall()
         
    else:
        # Researchers: Fetch datasets that user does NOT have active access to (to show Request button)
        datasets_rows = conn.execute('''
            SELECT * FROM datasets 
            WHERE id NOT IN (
                SELECT dataset_id FROM privileges 
                WHERE user_id = ? AND status = 'Active'
            )
        ''', (session['user_id'],)).fetchall()

    datasets = [dict(row) for row in datasets_rows]

    
    # User privileges (Active) - actually we don't need them for the list logic anymore if we filter in SQL,
    # but we might need pending status.
    # User said: "View Datasets page... properties: Status = Not Authorized... Button = Request Access"
    # But usually we show Pending. I'll keep pending check to be nice, but filter out Active.
    
    # Also fetch pending requests to show Pending status if applicable
    pending_requests = conn.execute('SELECT dataset_id FROM access_requests WHERE user_id = ? AND status = "Pending"', (session['user_id'],)).fetchall()
    pending_dataset_ids = [int(row['dataset_id']) for row in pending_requests]
    
    conn.close()
    
    return render_template("datasets.html", datasets=datasets, pending_ids=pending_dataset_ids)

@app.route("/request-access", methods=["GET", "POST"])
def request_access():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
        
    # RBAC: Collaborators cannot request access
    if session.get("role") == "Collaborator":
        log_action(session['user_id'], "Access Denied: Attempted to access Request Page")
        app.logger.warning(f"[ACCESS] Collaborator {session.get('email')} denied access to Request Page")
        return "Access Denied: Collaborators cannot request access.", 403

    if session.get("role") != "Researcher":
        return "Only Researchers can request dataset access", 403
        
    conn = get_db_connection()
    if request.method == "POST":
        dataset_id = int(request.form.get("dataset"))
        purpose = request.form.get("purpose")
        duration = request.form.get("duration")
        
        # Simple duration mapping
        duration_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}
        hours = duration_map.get(duration, 24) # Default 24
        
        # Handle Renew: if expired privilege exists, mark it as Renew Requested
        conn.execute("""
            UPDATE privileges 
            SET status = 'Renew Requested' 
            WHERE user_id = ? AND dataset_id = ? AND status = 'Expired'
        """, (session['user_id'], dataset_id))
        
        conn.execute('INSERT INTO access_requests (user_id, dataset_id, purpose, duration, status) VALUES (?, ?, ?, ?, ?)',
                     (session['user_id'], dataset_id, purpose, hours, 'Pending'))
        conn.commit()
        conn.close()
        
        log_action(session['user_id'], f"Requested access to dataset {dataset_id}")
        
        flash('Access request submitted successfully.', 'success')
        return redirect(url_for("my_privileges"))
        
    datasets_rows = conn.execute('SELECT * FROM datasets').fetchall()
    datasets = [dict(row) for row in datasets_rows]
    
    selected_dataset = request.args.get("dataset_id")
    
    conn.close()
    return render_template("request_access.html", datasets=datasets, selected_dataset=selected_dataset)

@app.route("/my-privileges")
def my_privileges():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    if session.get("role") not in ["Researcher", "Collaborator"]:
        return "Access Denied", 403
        
    conn = get_db_connection()
    privileges = conn.execute('''
        SELECT p.*, d.name as dataset_name 
        FROM privileges p 
        JOIN datasets d ON p.dataset_id = d.id 
        WHERE p.user_id = ?
    ''', (session['user_id'],)).fetchall()
    
    # Process privileges to mark expired
    active_privileges = []
    current_time = datetime.now()
    
    for row in privileges:
        # Convert row to dict to modify or just use logic in template?
        # Better to update status logic here or in template.
        # Let's verify status vs time.
        expiry = datetime.strptime(row['expiry_time'], '%Y-%m-%d %H:%M:%S')
        status = row['status']
        if current_time > expiry:
            status = 'Expired'
        
        active_privileges.append({
            'dataset_name': row['dataset_name'],
            'expiry_time': row['expiry_time'],
            'status': status,
            'dataset_id': row['dataset_id'],
            'encoded_dataset_id': encoding_utils.encode_base64(str(row['dataset_id']))
        })
        
    conn.close()
    return render_template("my_privileges.html", privileges=active_privileges)

@app.route("/access-dataset/<encoded_dataset_id>")
def access_dataset(encoded_dataset_id):
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    if session.get("role") not in ["Researcher", "Collaborator"]:
        return "Access Denied", 403
        
    try:
        dataset_id = int(encoding_utils.decode_base64(encoded_dataset_id))
    except Exception as e:
         return f"Invalid Encoded ID: {e}", 400

    conn = get_db_connection()
    privilege = conn.execute('''
        SELECT * FROM privileges 
        WHERE user_id = ? AND dataset_id = ? AND status = 'Active'
    ''', (session['user_id'], dataset_id)).fetchone()
    conn.close()
    
    if privilege:
        expiry = datetime.strptime(privilege['expiry_time'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() < expiry:
            # Decrypt data
            try:
                cipher = crypto_utils.get_cipher()
                file_path = f"secure_data/dataset_{dataset_id}.enc"
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()
                    decrypted_data = cipher.decrypt(encrypted_data).decode()
                    
                    # Verify Signature
                    sig_path = f"secure_data/dataset_{dataset_id}.sig"
                    integrity_verified = False
                    if os.path.exists(sig_path):
                        with open(sig_path, "rb") as f:
                            signature = f.read()
                        
                        hash_val = crypto_utils.hash_data(decrypted_data.encode())
                        if crypto_utils.verify_signature(hash_val, signature):
                            integrity_verified = True
                        else:
                            return "Data Integrity Compromised – Signature Invalid", 500
                    else:
                        # Should we fail if signature missing? Yes per requirements "If signature file deleted... FAIL"
                        return "Data Integrity Compromised – Signature Missing", 500

                    log_action(session['user_id'], f"Accessed dataset {dataset_id}")
                    app.logger.info(f"[ACCESS] Dataset {dataset_id} accessed by {session.get('email', 'unknown')}")
                    
                    # Log specifically if Collaborator
                    if session.get('role') == 'Collaborator':
                         app.logger.info(f"[COLLABORATOR] {session.get('email', 'unknown')} accessed dataset {dataset_id}")
                         
                    return render_template("access_dataset.html", data=decrypted_data, dataset_id=dataset_id, integrity=integrity_verified)
                else:
                    return "Dataset file not found.", 404
            except Exception as e:
                return f"Error decrypting data: {str(e)}", 500
    
    return "Access Denied – No valid privilege", 403

@app.route("/admin-approvals")
def admin_approvals():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    if session.get("role") != "Admin":
        return "Access Denied", 403
        
    conn = get_db_connection()
    requests = conn.execute('''
        SELECT ar.id, u.email, d.name as dataset_name, ar.purpose, ar.duration, ar.status
        FROM access_requests ar
        JOIN users u ON ar.user_id = u.id
        JOIN datasets d ON ar.dataset_id = d.id
        WHERE ar.status = 'Pending'
    ''').fetchall()
    conn.close()
    
    return render_template("admin_approvals.html", requests=requests)

@app.route("/approve-request", methods=["POST"])
def approve_request():
    if session.get("role") != "Admin":
        return "Access Denied", 403

    request_id = int(request.form.get("request_id"))

    conn = get_db_connection()
    
    # Fetch request details
    req = conn.execute("""
        SELECT user_id, dataset_id, duration
        FROM access_requests
        WHERE id = ? AND status = 'Pending'
    """, (request_id,)).fetchone()

    if not req:
        conn.close()
        return "Invalid or already processed request"

    user_id = req['user_id']
    dataset_id = req['dataset_id']
    duration = req['duration']

    # Update request status to Approved
    conn.execute("""
        UPDATE access_requests
        SET status = 'Approved'
        WHERE id = ?
    """, (request_id,))

    # Create privilege entry
    expiry_time = datetime.now() + timedelta(hours=duration)
    conn.execute("""
        INSERT INTO privileges (user_id, dataset_id, expiry_time, status)
        VALUES (?, ?, ?, 'Active')
    """, (user_id, dataset_id, expiry_time.strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()

    log_action(session.get('user_id'), f"Approved access request {request_id}")
    app.logger.info(f"[ADMIN] Approved access request #{request_id}")

    flash('Access request approved.', 'success')
    return redirect("/admin-approvals")

@app.route("/reject-request", methods=["POST"])
def reject_request():
    if session.get("role") != "Admin":
        return "Access Denied", 403

    request_id = int(request.form.get("request_id"))

    conn = get_db_connection()
    conn.execute("""
        UPDATE access_requests
        SET status = 'Rejected'
        WHERE id = ?
    """, (request_id,))

    conn.commit()
    conn.close()

    log_action(session.get('user_id'), f"Rejected access request {request_id}")
    app.logger.info(f"[ADMIN] Rejected access request #{request_id}")

    flash('Access request rejected.', 'warning')
    return redirect("/admin-approvals")

@app.route("/audit-logs")
def audit_logs():
    if "user_id" not in session or not session.get("otp_verified"):
        return redirect("/login")
    if session.get("role") != "Admin":
        return "Access Denied", 403
        
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT al.timestamp, u.email, al.action
        FROM audit_logs al
        JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC
    ''').fetchall()
    conn.close()
    
    return render_template("audit_logs.html", logs=logs)

if __name__ == "__main__":
    print("\n" + "-"*60)
    print("   SECURE DATA GATEWAY SERVER STARTING")
    print("-" * 60 + "\n")
    app.run(debug=True, use_reloader=False)
