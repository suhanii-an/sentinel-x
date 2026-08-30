"""Authentication and account management.

Two behaviours worth naming.

*Uniform failure.* A failed login returns the same error whether the username
does not exist or the password is wrong. Distinguishing them turns the login
endpoint into an account enumeration oracle.

*Lockout with a constant-time-ish path.* Repeated failures lock the account for a
cooldown. The verification is still performed against a dummy hash when the user
does not exist, so response time does not leak account existence either.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AuthenticationError, ConflictError, ValidationFailed
from app.core.logging import get_logger
from app.core.security import hash_password, verify_password
from app.core.timeutils import utcnow
from app.models.enums import Role
from app.models.platform import AppUser

logger = get_logger("sentinelx.auth")

MAX_FAILED_LOGINS = 8
LOCKOUT_MINUTES = 15

#: A real bcrypt hash of a value nobody knows, used to spend the same time
#: verifying a password for a user that does not exist as for one that does.
_DUMMY_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.6Jt6T0Q9m9MvQZ0aE3xO9m0m9Q0Q0Qe"


def get_user(db: Session, username: str) -> AppUser | None:
    return db.execute(
        select(AppUser).where(AppUser.username == username.strip().lower())
    ).scalar_one_or_none()


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role: str = Role.ANALYST,
    email: str | None = None,
    full_name: str | None = None,
) -> AppUser:
    username = username.strip().lower()
    if get_user(db, username) is not None:
        raise ConflictError(f"An account named '{username}' already exists.")
    if len(password) < 12:
        raise ValidationFailed("Password must be at least 12 characters.")

    user = AppUser(
        username=username,
        password_hash=hash_password(password),
        role=str(role),
        email=email,
        full_name=full_name,
        created_at=utcnow(),
    )
    db.add(user)
    db.flush()
    logger.info("app_user_created", extra={"username": username, "role": str(role)})
    return user


def authenticate(db: Session, username: str, password: str) -> AppUser:
    user = get_user(db, username)
    now = utcnow()

    if user is None:
        # Spend comparable time so timing does not reveal account existence.
        verify_password(password, _DUMMY_HASH)
        raise AuthenticationError("Invalid username or password.")

    if user.locked_until and user.locked_until > now:
        # Deliberately indistinguishable from a wrong password, and deliberately
        # still paying the bcrypt cost.
        #
        # A distinct "account locked" message is an enumeration oracle: eight
        # attempts against a candidate username separate real accounts from
        # non-existent ones by message text alone, and returning early would do
        # the same by timing. The lockout still applies — the caller is refused
        # — they simply cannot tell *why* from the outside. The account owner
        # learns about it from the audit trail, which is where it belongs.
        verify_password(password, _DUMMY_HASH)
        logger.info("login_refused_locked", extra={"username": user.username})
        raise AuthenticationError("Invalid username or password.")

    if not user.is_active:
        verify_password(password, _DUMMY_HASH)
        raise AuthenticationError("Invalid username or password.")

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = now + dt.timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
            logger.warning("account_locked", extra={"username": user.username})
        db.flush()
        raise AuthenticationError("Invalid username or password.")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.flush()
    return user


def change_password(db: Session, user: AppUser, current: str, new: str) -> None:
    if not verify_password(current, user.password_hash):
        raise AuthenticationError("Current password is incorrect.")
    if len(new) < 12:
        raise ValidationFailed("New password must be at least 12 characters.")
    user.password_hash = hash_password(new)
    db.flush()
    logger.info("password_changed", extra={"username": user.username})
