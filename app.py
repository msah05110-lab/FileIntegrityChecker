from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = "super_secret_key"

UPLOAD_FOLDER = "uploads"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ==========================
# DATABASE
# ==========================

def init_db():

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        file_hash TEXT,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()


init_db()


# ==========================
# HASH FUNCTION
# ==========================

def generate_file_hash(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


# ==========================
# HOME
# ==========================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect("/dashboard")

    return redirect("/login")


# ==========================
# REGISTER
# ==========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:

            cursor.execute(
                "INSERT INTO users(username,password) VALUES (?,?)",
                (username, hashed_password)
            )

            conn.commit()

            flash("Registration Successful", "success")

            return redirect("/login")

        except:

            flash("Username Already Exists", "danger")

        conn.close()

    return render_template("register.html")


# ==========================
# LOGIN
# ==========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect("/dashboard")

        else:

            flash("Invalid Credentials", "danger")

    return render_template("login.html")


# ==========================
# LOGOUT
# ==========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==========================
# DASHBOARD
# ==========================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT filename,file_hash,upload_date
        FROM files
        WHERE user_id=?
        ORDER BY id DESC
        ''',
        (session["user_id"],)
    )

    files = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        files=files
    )


# ==========================
# FILE UPLOAD
# ==========================

@app.route("/upload", methods=["POST"])
def upload():

    if "user_id" not in session:
        return redirect("/login")

    file = request.files["file"]

    if file.filename == "":
        flash("No File Selected", "danger")
        return redirect("/dashboard")

    filepath = os.path.join(
        app.config['UPLOAD_FOLDER'],
        file.filename
    )

    file.save(filepath)

    file_hash = generate_file_hash(filepath)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        '''
        INSERT INTO files
        (user_id,filename,file_hash)
        VALUES (?,?,?)
        ''',
        (
            session["user_id"],
            file.filename,
            file_hash
        )
    )

    conn.commit()
    conn.close()

    flash("File Uploaded Successfully", "success")

    return redirect("/dashboard")


# ==========================
# VERIFY PAGE
# ==========================

@app.route("/verify")
def verify_page():

    if "user_id" not in session:
        return redirect("/login")

    return render_template("verify.html")


# ==========================
# VERIFY FILE
# ==========================

@app.route("/verify_file", methods=["POST"])
def verify_file():

    if "user_id" not in session:
        return redirect("/login")

    file = request.files["file"]

    filepath = os.path.join(
        app.config['UPLOAD_FOLDER'],
        file.filename
    )

    file.save(filepath)

    current_hash = generate_file_hash(filepath)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT file_hash
        FROM files
        WHERE filename=?
        ORDER BY id DESC
        LIMIT 1
        ''',
        (file.filename,)
    )

    result = cursor.fetchone()

    conn.close()

    if result:

        stored_hash = result[0]

        if stored_hash == current_hash:

            status = "SAFE"
            message = "File Integrity Verified"

        else:

            status = "TAMPERED"
            message = "WARNING! File Modified"

    else:

        status = "UNKNOWN"
        message = "File Not Found"

    return render_template(
        "verify.html",
        status=status,
        message=message
    )


# ==========================
# RUN
# ==========================

if __name__ == "__main__":
    app.run(debug=True)