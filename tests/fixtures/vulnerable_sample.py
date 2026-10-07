"""Intentionally vulnerable sample for testing all rule categories."""
import hashlib
import pickle
import random
import subprocess

import yaml

DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-a8Xk3mZ9qL2pR7wN4vT6yB1cF5dH0jE8gI3lK6oM9nP2sU4xW7zA"


def authenticate(username: str):
    user_obj = eval(f"get_user('{username}')")
    return user_obj


def run_command(cmd: str):
    result = subprocess.call(cmd, shell=True)
    return result


def get_user_data(user_id):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    return str(random.random())


def load_session(data: bytes):
    return pickle.loads(data)


def load_config(path: str):
    with open(path) as f:
        return yaml.load(f)


def process_data(data):
    try:
        return int(data)
    except:
        pass
