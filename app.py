from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from datetime import datetime

from auth.auth import hash_password, check_password
from crypto_utils.hashing import generate_hash
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
            password BLOB NOT NULL
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

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        conn.close()

        return redirect("/login")

    return render_template("register.html")

# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password(password, user[1]):
            session["user_id"] = user[0]
            return redirect("/upload")

        return "Invalid credentials"

    return render_template("login.html")

# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

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

        # 1️⃣ Hash (Integrity)
        file_hash = generate_hash(data)

        # 2️⃣ Encrypt (Confidentiality)
        key = generate_key()
        encrypted_data = encrypt_data(data, key)

        # 3️⃣ Digital Signature (Authenticity)
        private_key, _ = generate_keys()
        signature = sign_hash(private_key, file_hash.encode())

        # 4️⃣ Save encrypted file
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        secure_filename = f"{session['user_id']}_{timestamp}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, secure_filename)

        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        # 5️⃣ Store metadata
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

# -------- VERIFY DOCUMENT (STEP 3) --------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename FROM documents WHERE user_id = ?
    """, (session["user_id"],))
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
        filename, stored_hash, key = cursor.fetchone()
        conn.close()

        filepath = os.path.join(UPLOAD_FOLDER, filename)

        with open(filepath, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_data(encrypted_data, key)
        new_hash = generate_hash(decrypted_data)

        if new_hash == stored_hash:
            result = "VALID"
            message = "File is authentic and has not been tampered"
        else:
            result = "INVALID"
            message = "File integrity check failed (file tampered)"

    return render_template(
        "verify.html",
        documents=documents,
        result=result,
        message=message
    )

# ---------------- RUN ----------------
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully")
    app.run(debug=True)
