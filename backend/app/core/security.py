"""Password hashing and JWT issuance.

bcrypt is used directly rather than through passlib: one less abstraction, and
passlib's bcrypt backend detection has been a recurring source of breakage.
The work factor is configurable so tests can drop it without weakening the
production default.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import bcrypt
import jwt

from app.core.config import settings
from app.core.errors import AuthenticationError

# bcrypt silently truncates at 72 bytes; rejecting longer input is clearer than
# accepting a password whose tail is ignored.
MAX_PASSWORD_BYTES = 72
DEFAULT_ROUNDS = 12


def hash_password(password: str, *, rounds: int = DEFAULT_ROUNDS) -> str:
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes.")
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:MAX_PASSWORD_BYTES], password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    *,
    subject: str,
    role: str,
    expires_minutes: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, dt.datetime]:
    now = dt.datetime.now(dt.UTC)
    expires_at = now + dt.timedelta(minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    claims: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.APP_NAME,
    }
    if extra_claims:
        claims.update(extra_claims)
    token = jwt.encode(claims, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],  # pinned: no 'alg: none' downgrade
            issuer=settings.APP_NAME,
            options={"require": ["exp", "sub", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Session expired. Please sign in again.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Invalid authentication token.") from exc
