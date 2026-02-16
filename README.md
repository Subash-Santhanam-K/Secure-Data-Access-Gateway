# Secure Data Access Gateway for R&D Labs

A secure, role-based data access control system implementing authentication, encryption, integrity protection, and audit logging.

## Project Overview

This project addresses the critical need for secure data access in R&D and Research labs. In such environments, protecting sensitive intellectual property and research data from unauthorized access while facilitating collaboration is paramount.

This system provides:
*   **Authentication**: Verifying user identity.
*   **Role-based access control (RBAC)**: Restricting access based on user roles.
*   **Encryption at rest**: Securing stored data using AES.
*   **Integrity**: ensuring data has not been tampered with.
*   **Audit logging**: Recording access and actions for accountability.

## Features Implemented

*   Login + Registration
*   OTP 2FA
*   Researcher access requests
*   Admin approvals
*   Collaborator role
*   AES encryption
*   RSA key protection
*   Digital signatures
*   Base64 encoding
*   Audit logs
*   Secure password policy (NIST)
*   Rate limiting
*   Secure UI

## Technology Stack

| Layer | Technology |
| :--- | :--- |
| Backend | Flask (Python) |
| Database | SQLite |
| Frontend | HTML + CSS |
| Crypto | cryptography (AES + RSA) |
| Security | Hashing + 2FA + RBAC |

## Project Folder Structure

*   `app.py` → Main backend server
*   `templates/` → HTML pages
*   `static/` → CSS styles
*   `keys/` → RSA keys
*   `secure_data/` → Encrypted datasets
*   `crypto_utils.py` → Encryption utilities
*   `encoding_utils.py` → Base64 encoding
*   `init_db.py` → Database initialization
*   `migrate_keys.py` → RSA key generation
*   `sign_datasets.py` → Digital signatures
*   `database.db` → Application database

## Setup & Run Instructions

**1. Installation**
```bash
pip install -r requirements.txt 
```
          (or)
```bash
pip install Flask cryptography
```

**2. Initialize DB (if needed)**
```bash
python init_db.py
```

**3. Run server**
```bash
python app.py
```

**4. Access**
[http://127.0.0.1:5000](http://127.0.0.1:5000)

*   Default port 5000
*   Works on localhost
*   HTTPS can be enabled optionally

## Default Test Accounts

**Researcher:**
*   email: `researcher@lab.com`
*   password: `pass1234`

**Admin:**
*   email: `admin@lab.com`
*   password: `admin123`

**Collaborator:**
*   email: `collab@lab.com`
*   password: `collab123`

## Security Architecture

**Authentication**
Uses secure password hashing to protect credentials and implements OTP (One-Time Password) for robust Two-Factor Authentication.

**Authorization**
Enforces strict Role-Based Access Control (RBAC) to ensure users can only perform actions permitted by their specific roles.

**Encryption**
Utilizes AES (Advanced Encryption Standard) to encrypt sensitive datasets at rest, ensuring data confidentiality.

**Key protection**
RSA asymmetric encryption protects the AES keys, ensuring keys are stored securely and separate from the data.

**Integrity**
Digital signatures verify the authenticity and integrity of datasets, detecting any unauthorized modifications.

**Logging**
Detailed audit logs capture all critical system activities, providing transparency and valid non-repudiation.

**Encoding**
Base64 encoding is used to safely represent and transport binary data within the system.

**Rate limiting**
Implements login attempt limits to protect against brute-force password guessing attacks.

## Rubric Mapping Table

| Rubric Requirement | Where Implemented |
| :--- | :--- |
| Authentication | `app.py` (login, register) |
| 2FA OTP | `app.py` (/otp route) |
| RBAC | `app.py` (role checks) |
| Encryption | `crypto_utils.py` |
| Hybrid Encryption | `migrate_keys.py` |
| Integrity | `sign_datasets.py` |
| Encoding | `encoding_utils.py` |
| Audit Logs | `audit_logs` route |
| Password Policy | `validate_password()` |
| Rate Limiting | `login_attempts` logic |
| UI | `templates` + `styles.css` |

## User Roles Explained

**Researcher:**
*   Request access to datasets.
*   View datasets they have been granted access to.

**Collaborator:**
*   Only use granted datasets.
*   Cannot request new access.

**Admin:**
*   Approve access requests.
*   Grant access to users.
*   View system audit logs.

## How the System Works

Login → OTP → Dashboard → Request → Admin Approve → Privilege → Access → Logs

## Key Management Explanation

RSA keys are securely stored in the `keys/` directory. The master AES key used for data encryption is encrypted with these RSA keys. This setup uses persistent keys to ensure data availability across restarts, avoiding runtime key exchange in favor of a stable, secure hybrid encryption model.

## Future Improvements

*   HTTPS (TLS) implementation
*   Email-based OTP
*   Docker containerization
*   Cloud deployment
*   Automated key rotation
*   Hardware Security Module (HSM) integration

## Conclusion

This Secure Data Access Gateway delivers a professional-grade security solution for R&D labs. By effectively implementing industry-standard security measures such as RBAC, hybrid encryption, and comprehensive auditing, it meets the rigorous demands of securing sensitive research environments.
