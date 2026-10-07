"""Sample secure application — remediated counterpart of insecure_app.py.

This file should produce ZERO findings when scanned.
"""
import hashlib
import os
import json
import secrets
import subprocess

import yaml


# Secrets loaded from environment
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD", "")
API_KEY = os.environ.get("API_KEY", "")


def authenticate(username: str):
    """Safe lookup — no eval."""
    from users import get_user  # hypothetical import
    return get_user(username)


def run_command(args: list[str]):
    """Subprocess with shell=False and list args."""
    result = subprocess.run(args, shell=False, capture_output=True, text=True)
    return result.stdout


def get_user_data(user_id: int):
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def hash_password(password: str) -> str:
    """SHA-256 with salt."""
    salt = secrets.token_hex(16)
    return hashlib.sha256((salt + password).encode()).hexdigest()


def generate_session_token() -> str:
    """Cryptographically secure token."""
    return secrets.token_urlsafe(32)


def load_user_session(data: str):
    """Safe deserialization via JSON."""
    return json.loads(data)


def load_config(path: str):
    """yaml.safe_load is safe."""
    with open(path) as f:
        return yaml.safe_load(f)


def process_data(data):
    """Proper exception handling."""
    try:
        return int(data)
    except ValueError:
        return None
