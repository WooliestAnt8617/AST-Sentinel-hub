"""Sample insecure application — for demonstration scanning.

WARNING: This file is INTENTIONALLY vulnerable. Do NOT use in production.
"""
import hashlib
import os
import pickle
import random
import subprocess
import yaml


# SEC-001: Hardcoded secrets
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk-proj-a8Xk3mZ9qL2pR7wN4vT6yB1cF5dH0jE8gI3lK6oM9nP2sU4xW7zA"
AWS_SECRET_TOKEN = "AKIAIOSFODNN7EXAMPLE"


def authenticate(username: str):
    # SEC-002: Code injection — eval with user input
    user_obj = eval(f"get_user('{username}')")
    return user_obj


def run_command(cmd: str):
    # SEC-002: Subprocess with shell=True
    result = subprocess.call(cmd, shell=True)
    return result


def get_user_data(user_id):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SEC-003: SQL injection — f-string in execute
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def search_users(name: str):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SEC-003: SQL injection — string formatting
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(query)
    return cursor.fetchall()


def hash_password(password: str) -> str:
    # SEC-004: Weak hash
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token():
    # SEC-004: Non-cryptographic PRNG
    return str(random.random())


def load_user_session(data: bytes):
    # SEC-005: Unsafe deserialization
    return pickle.loads(data)


def load_config(path: str):
    # SEC-005: yaml.load without SafeLoader
    with open(path) as f:
        return yaml.load(f)


def process_data(data):
    # SEC-006: Bare except + empty body
    try:
        return int(data)
    except:
        pass

    # SEC-006: Broad except Exception
    try:
        return float(data)
    except Exception as e:
        pass
