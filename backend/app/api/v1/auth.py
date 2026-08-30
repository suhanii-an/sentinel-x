"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request, status

from app.api.deps import (
    CurrentPrincipal,
    DbSession,
    LoginRateLimited,
    RequireAdmin,
    RequireViewer,
    client_ip,
)
from app.core.errors import AuthenticationError
from app.core.security import create_access_token
from app.models.enums import Role
from app.schemas.auth import (
    CurrentUser,
    LoginRequest,
    PasswordChange,
    TokenResponse,
    UserCreate,
)
from app.schemas.common import MessageResponse
from app.services import audit
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse, summary="Sign in and obtain a bearer token")
def login(
    payload: LoginRequest,
    request: Request,
    db: DbSession,
    _: LoginRateLimited,
) -> TokenResponse:
    """Exchange credentials for a JWT.

    Failures are recorded in the audit log: a burst of failed sign-ins is itself
    security telemetry, and a platform that only logs successes cannot show an
    attack against its own front door.
    """
    try:
        user = auth_service.authenticate(db, payload.username, payload.password)
    except AuthenticationError:
        audit.record(
            db,
            actor=payload.username[:128],
            action="login_failed",
            result="failure",
            ip_address=client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        db.commit()
        raise

    token, expires_at = create_access_token(subject=user.username, role=user.role)
    audit.record(
        db,
        actor=user.username,
        actor_role=user.role,
        action="login",
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()

    return TokenResponse(
        access_token=token,
        expires_at=expires_at,
        user=CurrentUser.model_validate(user),
    )


@router.post("/logout", response_model=MessageResponse, summary="Record a sign-out")
def logout(principal: CurrentPrincipal, db: DbSession) -> MessageResponse:
    """Record the sign-out.

    The token is not revoked server-side: these are stateless JWTs with a bounded
    lifetime, and pretending otherwise would be security theatre. A deployment
    needing immediate revocation must add a token denylist — noted in
    docs/threat-model.md rather than glossed over.
    """
    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="logout",
        ip_address=principal.ip_address,
    )
    db.commit()
    return MessageResponse(
        message="Signed out. The issued token remains valid until it expires; "
                "discard it client-side.",
    )


@router.get("/me", response_model=CurrentUser, summary="The authenticated account")
def me(principal: CurrentPrincipal) -> CurrentUser:
    return CurrentUser.model_validate(principal.user)


@router.post(
    "/users",
    response_model=CurrentUser,
    status_code=status.HTTP_201_CREATED,
    summary="Create an account (admin only)",
)
def create_user(payload: UserCreate, principal: RequireAdmin, db: DbSession) -> CurrentUser:
    user = auth_service.create_user(
        db,
        username=payload.username,
        password=payload.password,
        role=payload.role,
        email=payload.email,
        full_name=payload.full_name,
    )
    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="user_created",
        target_type="app_user",
        target_id=user.username,
        details={"role": user.role},
        ip_address=principal.ip_address,
    )
    db.commit()
    return CurrentUser.model_validate(user)


@router.post("/password", response_model=MessageResponse, summary="Change your own password")
def change_password(
    payload: PasswordChange,
    principal: CurrentPrincipal,
    db: DbSession,
) -> MessageResponse:
    auth_service.change_password(
        db, principal.user, payload.current_password, payload.new_password
    )
    audit.record(
        db,
        actor=principal.username,
        actor_role=principal.role.value,
        action="password_changed",
        target_type="app_user",
        target_id=principal.username,
        ip_address=principal.ip_address,
    )
    db.commit()
    return MessageResponse(message="Password changed.")


@router.get("/roles", summary="Role model")
def roles(_: RequireViewer) -> dict:
    """The authorization model, so the UI does not hard-code it.

    Authenticated even though the content is not secret: handing an anonymous
    caller a map of which role can do what is free reconnaissance, and the only
    consumer is the signed-in console.
    """
    return {
        "roles": [
            {
                "role": Role.VIEWER.value,
                "level": Role.VIEWER.level,
                "description": "Read-only access to alerts, incidents, evidence and dashboards.",
                "can": ["view all security data", "run threat hunts", "export reports"],
                "cannot": ["change alert or incident status", "run simulations",
                           "execute response actions", "modify detection rules"],
            },
            {
                "role": Role.ANALYST.value,
                "level": Role.ANALYST.level,
                "description": "Full investigation and response workflow.",
                "can": ["everything a viewer can", "triage alerts and incidents",
                        "run attack simulations", "execute simulated response actions",
                        "use the AI assistant", "generate reports"],
                "cannot": ["enable or disable detection rules", "create accounts",
                           "read the audit log"],
            },
            {
                "role": Role.ADMIN.value,
                "level": Role.ADMIN.level,
                "description": "Platform administration.",
                "can": ["everything an analyst can", "enable and disable detection rules",
                        "create accounts", "read the audit log", "run evaluations"],
                "cannot": [],
            },
        ]
    }
