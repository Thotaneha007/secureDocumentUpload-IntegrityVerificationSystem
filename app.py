from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from datetime import datetime
from cryptography.fernet import InvalidToken

from auth.auth import hash_password, check_password
from auth.mfa import generate_totp_secret, verify_totp, get_totp_uri
from crypto_utils.hashing import generate_hash
import urllib.parse
from crypto_utils.encryption import generate_key, encrypt_data, decrypt_data
from crypto_utils.signature import generate_keys, sign_hash

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads", "encrypted_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed file types
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL,
            mfa_secret TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            file_hash TEXT,
            signature BLOB,
            enc_key BLOB,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return redirect("/login")

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = hash_password(request.form["password"])
        mfa_secret = generate_totp_secret()
        role = request.form.get("role", "user")

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, mfa_secret, role) VALUES (?, ?, ?, ?)",
                (username, password, mfa_secret, role)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        conn.close()

        totp_uri = get_totp_uri(mfa_secret, "SecureDocumentSystem", username)
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?data={urllib.parse.quote(totp_uri)}&size=200x200"

        return render_template("mfa_setup.html", secret=mfa_secret, qr_url=qr_url)

    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        mfa_token = request.form.get("mfa_token", "")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password, mfa_secret, role FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password(password, user[1]):
            mfa_secret = user[2]
            
            # Allow skipping MFA if not set (for old accounts before migration)
            if mfa_secret and not verify_totp(mfa_secret, mfa_token):
                 return "Invalid MFA token"
                 
            session["user_id"] = user[0]
            session["role"] = user[3]
            
            if session["role"] == 'admin':
                return redirect("/admin")
            elif session["role"] == 'auditor':
                return redirect("/auditor")
            
            return redirect("/upload")

        return "Invalid credentials"

    return render_template("login.html")

# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------- ADMIN DASHBOARD --------
@app.route("/admin")
def admin():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.id, d.filename, u.username 
        FROM documents d
        JOIN users u ON d.user_id = u.id
    """)
    documents = cursor.fetchall()
    conn.close()

    return render_template("admin.html", documents=documents)

@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect("/login")
        
    doc_id = request.form["doc_id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT filename FROM documents WHERE id = ?", (doc_id,))
    record = cursor.fetchone()
    if record:
        filepath = os.path.join(UPLOAD_FOLDER, record[0])
        if os.path.exists(filepath):
            os.remove(filepath)
        cursor.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        conn.commit()
    conn.close()
    
    return redirect("/admin")

# -------- AUDITOR DASHBOARD --------
@app.route("/auditor", methods=["GET", "POST"])
def auditor():
    if "user_id" not in session or session.get("role") != "auditor":
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.id, d.filename, u.username 
        FROM documents d
        JOIN users u ON d.user_id = u.id
    """)
    documents = cursor.fetchall()
    conn.close()

    result = None
    message = None

    if request.method == "POST":
        doc_id = request.form["doc_id"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT filename, file_hash, enc_key FROM documents WHERE id = ?", (doc_id,))
        record = cursor.fetchone()
        conn.close()

        if record:
            filename, stored_hash, key = record
            filepath = os.path.join(UPLOAD_FOLDER, filename)

            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = decrypt_data(encrypted_data, key)
                new_hash = generate_hash(decrypted_data)

                if new_hash == stored_hash:
                    result = "VALID"
                    message = f"File '{filename}' is authentic and has not been tampered with."
                else:
                    result = "INVALID"
                    message = "File integrity check failed (hash mismatch)."
            except InvalidToken:
                result = "INVALID"
                message = "File integrity check failed (file was tampered)."
            except FileNotFoundError:
                result = "INVALID"
                message = "File missing from disk."

    return render_template("auditor.html", documents=documents, result=result, message=message)

# -------- SECURE UPLOAD --------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect("/login")

    message = None

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            return render_template("upload.html", message="No file selected")

        if not allowed_file(file.filename):
            return render_template("upload.html", message="Invalid file type")

        data = file.read()

        # 1️ Hash (Integrity)
        file_hash = generate_hash(data)

        # 2️ Encrypt (Confidentiality)
        key = generate_key()
        encrypted_data = encrypt_data(data, key)

        # 3️ Digital Signature (Authenticity)
        private_key, _ = generate_keys()
        signature = sign_hash(private_key, file_hash.encode())

        # 4️ Save encrypted file
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        secure_filename = f"{session['user_id']}_{timestamp}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, secure_filename)

        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        # 5️ Store metadata
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO documents (user_id, filename, file_hash, signature, enc_key)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            secure_filename,
            file_hash,
            signature,
            key
        ))
        conn.commit()
        conn.close()

        message = "File securely uploaded, encrypted, and signed"

    return render_template("upload.html", message=message)

# -------- VERIFY DOCUMENT --------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, filename FROM documents WHERE user_id = ?",
        (session["user_id"],)
    )
    documents = cursor.fetchall()
    conn.close()

    result = None
    message = None

    if request.method == "POST":
        doc_id = request.form["doc_id"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT filename, file_hash, enc_key
            FROM documents WHERE id = ?
        """, (doc_id,))
        record = cursor.fetchone()
        conn.close()

        if record:
            filename, stored_hash, key = record
            filepath = os.path.join(UPLOAD_FOLDER, filename)

            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()

                #  Try decrypting
                decrypted_data = decrypt_data(encrypted_data, key)

                #  Recompute hash
                new_hash = generate_hash(decrypted_data)

                if new_hash == stored_hash:
                    result = "VALID"
                    message = "File is authentic and has not been tampered"
                else:
                    result = "INVALID"
                    message = "File integrity check failed (hash mismatch)"

            except InvalidToken:
                # TAMPERING HANDLING
                result = "INVALID"
                message = "File integrity check failed (file was tampered)"

    return render_template(
        "verify.html",
        documents=documents,
        result=result,
        message=message
    )


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully")
    app.run(debug=True)
