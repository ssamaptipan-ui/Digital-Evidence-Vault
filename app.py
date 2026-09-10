import os
import hashlib

from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    send_file
)

from flask_sqlalchemy import SQLAlchemy

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet

from dotenv import load_dotenv

import pytz


load_dotenv()


app = Flask(__name__)


# ==============================
# APPLICATION SECURITY
# ==============================

app.secret_key = os.getenv(
    "SECRET_KEY",
    "digital-evidence-vault-development-key"
)


app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = False

app.permanent_session_lifetime = timedelta(
    days=30
)


# Maximum request size: 10 MB
app.config["MAX_CONTENT_LENGTH"] = (
    20 * 1024 * 1024
)


# ==============================
# BASE DIRECTORY
# ==============================

BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


# ==============================
# DATABASE
# ==============================

DATABASE_DIR = os.path.join(
    BASE_DIR,
    "database"
)

os.makedirs(
    DATABASE_DIR,
    exist_ok=True
)


app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///"
    + os.path.join(
        DATABASE_DIR,
        "vault.db"
    )
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)


# ==============================
# CSRF PROTECTION
# ==============================

csrf = CSRFProtect(app)


# ==============================
# FOLDERS
# ==============================

EVIDENCE_FOLDER = os.path.join(
    BASE_DIR,
    "evidence"
)

LOG_FOLDER = os.path.join(
    BASE_DIR,
    "logs"
)


os.makedirs(
    EVIDENCE_FOLDER,
    exist_ok=True
)

os.makedirs(
    LOG_FOLDER,
    exist_ok=True
)


# ==============================
# ENCRYPTION KEY
# ==============================

SECRET_KEY_FILE = os.path.join(
    BASE_DIR,
    "secret.key"
)


def load_encryption_key():

    if not os.path.exists(
        SECRET_KEY_FILE
    ):

        key = Fernet.generate_key()

        with open(
            SECRET_KEY_FILE,
            "wb"
        ) as key_file:

            key_file.write(
                key
            )

    with open(
        SECRET_KEY_FILE,
        "rb"
    ) as key_file:

        return key_file.read()


encryption_key = load_encryption_key()


fernet = Fernet(
    encryption_key
)


# ==============================
# INDIA TIMEZONE
# ==============================

INDIA_TZ = pytz.timezone(
    "Asia/Kolkata"
)


def current_india_time():

    return datetime.now(
        INDIA_TZ
    ).replace(
        tzinfo=None
    )


# ==============================
# FILE UPLOAD SECURITY
# ==============================

ALLOWED_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "txt",
    "jpg",
    "jpeg",
    "png"
}


MAX_FILE_SIZE = 20 * 1024 * 1024


def allowed_file(filename):

    if not filename:

        return False

    if "." not in filename:

        return False

    extension = filename.rsplit(
        ".",
        1
    )[1].lower()

    return extension in ALLOWED_EXTENSIONS


# ==============================
# DATABASE MODELS
# ==============================

class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


class Evidence(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        nullable=False
    )

    uploaded_by = db.Column(
        db.String(100),
        nullable=False
    )

    upload_time = db.Column(
        db.DateTime,
        default=current_india_time
    )

    file_hash = db.Column(
        db.String(64),
        nullable=False
    )

    verified = db.Column(
        db.Boolean,
        default=False
    )


class AuditLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        nullable=False
    )

    action = db.Column(
        db.String(255),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=current_india_time
    )


# ==============================
# AUDIT LOG FUNCTION
# ==============================

def create_log(
    username,
    action
):

    log = AuditLog(
        username=username,
        action=action,
        timestamp=current_india_time()
    )

    db.session.add(
        log
    )

    db.session.commit()


# ==============================
# LOGIN
# ==============================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        remember_me = request.form.get(
            "remember_me"
        )

        if not email or not password:

            return "Please enter email and password!"

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session["user_id"] = user.id

            session["username"] = user.username

            print(
                "LOGIN USERNAME:",
                repr(user.username)
            )

            if remember_me:

                session.permanent = True

            else:

                session.permanent = False

            create_log(
                user.username,
                "User Logged In"
            )

            return redirect(
                "/dashboard"
            )

        return "Invalid email or password!"

    return render_template(
        "login.html"
    )


# ==============================
# REGISTER
# ==============================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not email or not password:

            return "Please fill all fields!"

        existing_user = User.query.filter(
            (
                (User.username == username)
                |
                (User.email == email)
            )
        ).first()

        if existing_user:

            return "Username or email already exists!"

        hashed_password = generate_password_hash(
            password
        )

        user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(
            user
        )

        db.session.commit()

        return redirect(
            "/login"
        )

    return render_template(
        "register.html"
    )


# ==============================
# DASHBOARD
# ==============================

@app.route(
    "/dashboard"
)
def dashboard():

    if "user_id" not in session:

        return redirect(
            "/login"
        )

    username = session.get(
        "username",
        ""
    ).strip()

    print(
        "CURRENT DASHBOARD USERNAME:",
        repr(username)
    )


    evidence_list = Evidence.query.filter(
        db.func.lower(
            db.func.trim(
                Evidence.uploaded_by
            )
        )
        ==
        db.func.lower(
            db.func.trim(
                username
            )
        )
    ).order_by(
        Evidence.id.desc()
    ).all()


    print(
        "EVIDENCE FOUND FOR USER:",
        len(evidence_list)
    )

    print(
        "TOTAL EVIDENCE IN DATABASE:",
        Evidence.query.count()
    )

    print(
        "ALL EVIDENCE USERS:",
        [item.uploaded_by for item in Evidence.query.all()]
    )

    print(
        "DATABASE FILE:",
        app.config["SQLALCHEMY_DATABASE_URI"]
    )


    total_evidence = len(
        evidence_list
    )


    verified_evidence = sum(
        1
        for evidence_item in evidence_list
        if evidence_item.verified
    )


    pending_evidence = (
        total_evidence
        -
        verified_evidence
    )


    if total_evidence > 0:

        verification_percentage = round(
            (
                verified_evidence
                /
                total_evidence
            )
            *
            100
        )

    else:

        verification_percentage = 0


    security_score = verification_percentage


    recent_evidence = evidence_list[:5]


    recent_logs = AuditLog.query.filter(
        db.func.lower(
            db.func.trim(
                AuditLog.username
            )
        )
        ==
        db.func.lower(
            db.func.trim(
                username
            )
        )
    ).order_by(
        AuditLog.id.desc()
    ).limit(
        5
    ).all()


    total_logs = AuditLog.query.filter(
        db.func.lower(
            db.func.trim(
                AuditLog.username
            )
        )
        ==
        db.func.lower(
            db.func.trim(
                username
            )
        )
    ).count()


    return render_template(
        "dashboard.html",

        username=username,

        total_evidence=total_evidence,

        verified_evidence=verified_evidence,

        pending_evidence=pending_evidence,

        verification_percentage=verification_percentage,

        security_score=security_score,

        recent_evidence=recent_evidence,

        recent_logs=recent_logs,

        total_logs=total_logs
    )


# ==============================
# UPLOAD EVIDENCE
# ==============================

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
def upload_evidence():

    if "user_id" not in session:

        return redirect(
            "/login"
        )

    if request.method == "POST":

        file = request.files.get(
            "evidence_file"
        )

        if not file or not file.filename:

            return "Please select a file!"


        # Check file extension
        if not allowed_file(
            file.filename
        ):

            return (
                "File type not allowed! "
                "Allowed types: PDF, DOC, DOCX, "
                "TXT, JPG, JPEG, PNG."
            )


        # Secure the original filename
        safe_filename = secure_filename(
            file.filename
        )


        if not safe_filename:

            return "Invalid file name!"


        # Read file
        file_data = file.read()


        # Empty file check
        if not file_data:

            return "The selected file is empty!"


        # File size check
        if len(file_data) > MAX_FILE_SIZE:

            return "File size exceeds the 20 MB limit!"


        # SHA-256 hash
        file_hash = hashlib.sha256(
            file_data
        ).hexdigest()


        # Encrypt evidence
        encrypted_data = fernet.encrypt(
            file_data
        )


        # Generate unique storage name
        timestamp = datetime.now().strftime(
            "%Y%m%d%H%M%S%f"
        )


        stored_filename = (
            timestamp
            + "_"
            + safe_filename
            + ".encrypted"
        )


        stored_path = os.path.join(
            EVIDENCE_FOLDER,
            stored_filename
        )


        # Save encrypted evidence
        with open(
            stored_path,
            "wb"
        ) as encrypted_file:

            encrypted_file.write(
                encrypted_data
            )


        # Save database record
        evidence = Evidence(

            filename=safe_filename,

            stored_filename=stored_filename,

            uploaded_by=session.get(
                "username"
            ),

            upload_time=current_india_time(),

            file_hash=file_hash,

            verified=False
        )


        db.session.add(
            evidence
        )

        db.session.commit()


        # Audit log
        create_log(
            session.get(
                "username"
            ),
            "Evidence Uploaded: "
            + safe_filename
        )


        return redirect(
            "/evidence"
        )


    return render_template(
        "upload.html"
    )


# ==============================
# EVIDENCE LIST
# ==============================

@app.route(
    "/evidence"
)
def evidence():

    if "user_id" not in session:

        return redirect(
            "/login"
        )


    username = session.get(
        "username",
        ""
    ).strip()


    print(
        "CURRENT EVIDENCE USERNAME:",
        repr(username)
    )


    evidence_list = Evidence.query.filter(
        db.func.lower(
            db.func.trim(
                Evidence.uploaded_by
            )
        )
        ==
        db.func.lower(
            db.func.trim(
                username
            )
        )
    ).order_by(
        Evidence.id.desc()
    ).all()


    print(
        "EVIDENCE RECORDS FOUND:",
        len(evidence_list)
    )


    return render_template(
        "evidence.html",
        evidence_list=evidence_list
    )


# ==============================
# EVIDENCE DETAILS
# ==============================

@app.route(
    "/evidence/<int:evidence_id>"
)
def evidence_details(
    evidence_id
):

    if "user_id" not in session:

        return redirect(
            "/login"
        )


    evidence = Evidence.query.get_or_404(
        evidence_id
    )


    if evidence.uploaded_by.lower().strip() != session.get(
        "username",
        ""
    ).lower().strip():

        return "Access denied!", 403


    return render_template(
        "evidence_details.html",
        evidence=evidence
    )


# ==============================
# VERIFY EVIDENCE
# ==============================

@app.route(
    "/verify/<int:evidence_id>",
    methods=["GET", "POST"]
)
def verify_evidence(
    evidence_id
):

    if "user_id" not in session:

        return redirect(
            "/login"
        )


    evidence = Evidence.query.get_or_404(
        evidence_id
    )


    if evidence.uploaded_by.lower().strip() != session.get(
        "username",
        ""
    ).lower().strip():

        return "Access denied!", 403


    stored_path = os.path.join(
        EVIDENCE_FOLDER,
        evidence.stored_filename
    )


    if not os.path.exists(
        stored_path
    ):

        return "Encrypted evidence file not found!"


    with open(
        stored_path,
        "rb"
    ) as encrypted_file:

        encrypted_data = encrypted_file.read()


    try:

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

    except Exception:

        return "Evidence decryption failed!"


    current_hash = hashlib.sha256(
        decrypted_data
    ).hexdigest()


    if current_hash == evidence.file_hash:

        evidence.verified = True

        db.session.commit()


        create_log(
            session.get(
                "username"
            ),
            "Evidence Verified: "
            + evidence.filename
        )


        return redirect(
            "/evidence"
        )


    evidence.verified = False

    db.session.commit()


    create_log(
        session.get(
            "username"
        ),
        "Evidence Verification Failed: "
        + evidence.filename
    )


    return "Evidence verification failed!"


# ==============================
# DOWNLOAD EVIDENCE
# ==============================

@app.route(
    "/download/<int:evidence_id>"
)
def download_evidence(
    evidence_id
):

    if "user_id" not in session:

        return redirect(
            "/login"
        )


    evidence = Evidence.query.get_or_404(
        evidence_id
    )


    if evidence.uploaded_by.lower().strip() != session.get(
        "username",
        ""
    ).lower().strip():

        return "Access denied!", 403


    stored_path = os.path.join(
        EVIDENCE_FOLDER,
        evidence.stored_filename
    )


    if not os.path.exists(
        stored_path
    ):

        return "Evidence file not found!"


    with open(
        stored_path,
        "rb"
    ) as encrypted_file:

        encrypted_data = encrypted_file.read()


    try:

        decrypted_data = fernet.decrypt(
            encrypted_data
        )

    except Exception:

        return "Unable to decrypt evidence!"


    download_path = os.path.join(
        EVIDENCE_FOLDER,
        "download_" + evidence.filename
    )


    with open(
        download_path,
        "wb"
    ) as output_file:

        output_file.write(
            decrypted_data
        )


    create_log(
        session.get(
            "username"
        ),
        "Evidence Downloaded: "
        + evidence.filename
    )


    return send_file(
        download_path,
        as_attachment=True,
        download_name=evidence.filename
    )


# ==============================
# AUDIT LOGS
# ==============================

@app.route(
    "/logs"
)
def logs():

    if "user_id" not in session:

        return redirect(
            "/login"
        )


    username = session.get(
        "username",
        ""
    ).strip()


    logs_list = AuditLog.query.filter(
        db.func.lower(
            db.func.trim(
                AuditLog.username
            )
        )
        ==
        db.func.lower(
            db.func.trim(
                username
            )
        )
    ).order_by(
        AuditLog.id.desc()
    ).all()


    return render_template(
        "logs.html",
        logs=logs_list
    )


# ==============================
# LOGOUT
# ==============================

@app.route(
    "/logout"
)
def logout():

    username = session.get(
        "username"
    )


    if username:

        create_log(
            username,
            "User Logged Out"
        )


    session.clear()


    return redirect(
        "/login"
    )


# ==============================
# HOME
# ==============================

@app.route(
    "/"
)
def home():

    if "user_id" in session:

        return redirect(
            "/dashboard"
        )

    return redirect(
        "/login"
    )


# ==============================
# DATABASE INITIALIZATION
# ==============================

with app.app_context():

    db.create_all()

    old_evidence = Evidence.query.filter(
        Evidence.uploaded_by.is_(None)
    ).all()

    for item in old_evidence:

        item.uploaded_by = "samapti"

    if old_evidence:

        db.session.commit()

    print(
        "OLD EVIDENCE UPDATED:",
        len(old_evidence)
    )


# ==============================
# RUN APPLICATION
# ==============================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )