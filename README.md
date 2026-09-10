# Digital Evidence Vault

A secure Flask-based Digital Evidence Management System designed to store, manage, verify, and download digital evidence securely.

## Features

- Secure user registration and login
- Password hashing
- Secure session management
- Encrypted evidence file storage using Fernet encryption
- SHA-256 file integrity verification
- Evidence verification system
- Secure evidence download
- Audit logging for important user activities
- Evidence dashboard with verification statistics
- File type validation
- Maximum file upload limit of 20 MB
- CSRF protection
- User-based evidence access control

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- Flask-WTF / CSRF Protection
- Cryptography (Fernet)
- HTML5
- CSS3
- JavaScript
- Werkzeug Security
- python-dotenv
- PyTZ

## Project Structure

```text
DigitalEvidenceVault/
│
├── app.py
├── requirements.txt
├── start_app.bat
├── .gitignore
├── README.md
│
├── templates/
│   ├── dashboard.html
│   ├── evidence.html
│   ├── evidence_details.html
│   ├── login.html
│   ├── logs.html
│   ├── register.html
│   ├── upload.html
│   └── verify.html
│
├── database/
├── evidence/
├── logs/
├── static/
├── venv/
├── .env
└── secret.key