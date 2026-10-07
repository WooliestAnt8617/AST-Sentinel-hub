"""Clean sample — should produce zero findings."""
import hashlib
import os
import secrets

import yaml

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def authenticate(username: str):
    return {"user": username}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return hashlib.sha256((salt + password).encode()).hexdigest()


def load_config(path: str):
    with open(path) as f:
        return yaml.safe_load(f)


def process_data(data):
    try:
        return int(data)
    except ValueError:
        return None
