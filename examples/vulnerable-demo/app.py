import random
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
PAYMENT_API_KEY = "sk_live_demo_payment_secret_123456789"


@app.get("/lookup")
def lookup_user():
    user_id = request.args.get("id", "1")
    db = sqlite3.connect("users.db")
    query = f"select id, email, role from users where id = {user_id}"
    return {"rows": db.execute(query).fetchall()}


@app.post("/admin/run")
def run_admin_command():
    command = request.form.get("command", "id")
    output = subprocess.check_output(command, shell=True)
    return output.decode("utf-8", errors="ignore")


@app.post("/reset-token")
def reset_token():
    email = request.form.get("email", "")
    token = "reset-token-" + str(random.random())
    return {"email": email, "token": token}
