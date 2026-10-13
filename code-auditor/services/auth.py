"""
Auth service — session signing/verifying using itsdangerous.
"""

import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-please-use-a-long-random-string")
_serializer = URLSafeTimedSerializer(SECRET_KEY)
SESSION_COOKIE = "session_token"
MAX_AGE = 60 * 60 * 24 * 30  # 30 days


def create_session_token(user_id: str) -> str:
    """Create a signed session token containing the user_id."""
    return _serializer.dumps(user_id, salt="session")


def decode_session_token(token: str) -> str | None:
    """Decode and verify a session token. Returns user_id or None."""
    try:
        return _serializer.loads(token, salt="session", max_age=MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
