from flask import Flask, request, render_template
import sqlite3
from datetime import datetime
import os
from ml_engine import run_ml_detection   # ✅ ADD THIS

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "honeypot.db")


# -------------------- INIT DB --------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            username TEXT,
            timestamp TEXT,
            suspicious INTEGER DEFAULT 0,
            threat_score INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

init_db()


# -------------------- LOGIN ROUTE --------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        ip = request.remote_addr
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ?", (ip,))
        count = cursor.fetchone()[0]

        threat_score = 20

        if count >= 3:
            threat_score += 50

        suspicious = 1 if threat_score >= 70 else 0

        cursor.execute("""
            INSERT INTO logs (ip, username, timestamp, suspicious, threat_score)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, username, timestamp, suspicious, threat_score))

        conn.commit()
        conn.close()

        run_ml_detection()   # ✅ ML runs after every login

        return "Invalid Credentials"

    return render_template("login.html")


# -------------------- ADMIN TRAP --------------------
@app.route("/admin")
def fake_admin():
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    threat_score = 80
    suspicious = 1

    cursor.execute("""
        INSERT INTO logs (ip, username, timestamp, suspicious, threat_score)
        VALUES (?, ?, ?, ?, ?)
    """, (ip, "ADMIN_PROBE", timestamp, suspicious, threat_score))

    conn.commit()
    conn.close()

    run_ml_detection()   # ✅ ML also runs for admin trap

    return "Access Denied"


# -------------------- DASHBOARD --------------------
@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logs WHERE suspicious = 1")
    suspicious_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",
        logs=logs,
        total_logs=total_logs,
        suspicious_count=suspicious_count
    )


if __name__ == "__main__":
    app.run(debug=True)