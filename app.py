from flask import Flask, request, render_template
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Create DB & Table (runs once)
def init_db():
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            username TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        ip = request.remote_addr
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect("honeypot.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO logs (ip, username, timestamp) VALUES (?, ?, ?)",
            (ip, username, timestamp)
        )
        conn.commit()
        conn.close()

        return "Invalid Credentials"

    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)