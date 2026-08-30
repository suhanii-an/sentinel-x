"""Request dependencies: authentication, authorization, rate limiting.

Authorization is a dependency factory rather than a check inside each handler.
A forgotten check inside a handler is invisible; a missing dependency is visible
in the route signature, and the test suite asserts the role requirement of every
mutating endpoint.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.errors import AuthenticationError, AuthorizationError, RateLimitError
from app.core.ratelimit import FixedWindowRateLimiter
from app.core.security import decode_access_token
from app.models.enums import Role
from app.models.platform import AppUser
from app.services import auth as auth_service

# auto_error=False so a missing header raises our structured error rather than
# FastAPI's default, keeping every failure shape identical.
bearer_scheme = HTTPBearer(auto_error=False, description="JWT bearer token from /auth/login")

general_limiter = FixedWindowRateLimiter(
    settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW_SECONDS
)
ai_limiter = FixedWindowRateLimiter(
    settings.AI_RATE_LIMIT_REQUESTS, settings.AI_RATE_LIMIT_WINDOW_SECONDS
)
#: Login gets its own tight budget: it is the endpoint an attacker brute-forces.
login_limiter = FixedWindowRateLimiter(10, 60)


@dataclass(slots=True)
class Principal:
    """The authenticated caller."""

    user: AppUser
    role: Role
    ip_address: str | None
    user_agent: str | None

    @property
    def username(self) -> str:
        return self.user.username

    def can(self, minimum: Role) -> bool:
        return self.role.level >= minimum.level


def client_ip(request: Request) -> str | None:
    """Best-effort client address.

    ``X-Forwarded-For`` is trusted only because this application is expected to
    run behind a proxy it controls; that assumption is stated in
    docs/threat-model.md rather than left implicit, because a spoofable client
    address feeding a rate limiter is a real weakness.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def get_current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> Principal:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("Authentication required.")

    claims = decode_access_token(credentials.credentials)
    username = claims.get("sub")
    if not username:
        raise AuthenticationError("Invalid authentication token.")

    user = auth_service.get_user(db, username)
    if user is None or not user.is_active:
        # The account was removed or disabled after the token was issued.
        raise AuthenticationError("This account is no longer active.")

    try:
        role = Role(user.role)
    except ValueError:
        raise AuthenticationError("This account has an invalid role assignment.") from None

    return Principal(
        user=user,
        role=role,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
DbSession = Annotated[Session, Depends(get_db)]


def require_role(minimum: Role) -> Callable[[Principal], Principal]:
    """Dependency factory enforcing a minimum role."""

    def dependency(principal: CurrentPrincipal) -> Principal:
        if not principal.can(minimum):
            raise AuthorizationError(
                f"This action requires the {minimum.value} role or higher; "
                f"your account has {principal.role.value}."
            )
        return principal

    return dependency


RequireViewer = Annotated[Principal, Depends(require_role(Role.VIEWER))]
RequireAnalyst = Annotated[Principal, Depends(require_role(Role.ANALYST))]
RequireAdmin = Annotated[Principal, Depends(require_role(Role.ADMIN))]


def rate_limit(limiter: FixedWindowRateLimiter, scope: str) -> Callable:
    def dependency(request: Request, principal: CurrentPrincipal) -> None:
        key = f"{scope}:{principal.username}"
        allowed, remaining, retry_after = limiter.check(key)
        if not allowed:
            raise RateLimitError(
                f"Rate limit exceeded for {scope}. Retry in {retry_after}s.",
                details={"retry_after_seconds": retry_after, "scope": scope},
            )
        request.state.rate_limit_remaining = remaining

    return dependency


AIRateLimited = Annotated[None, Depends(rate_limit(ai_limiter, "ai"))]


def anonymous_rate_limit(request: Request) -> None:
    """Rate limit for endpoints reached before authentication."""
    key = f"login:{client_ip(request) or 'unknown'}"
    allowed, _, retry_after = login_limiter.check(key)
    if not allowed:
        raise RateLimitError(
            f"Too many sign-in attempts. Retry in {retry_after}s.",
            details={"retry_after_seconds": retry_after},
        )


LoginRateLimited = Annotated[None, Depends(anonymous_rate_limit)]
