"""Authentication API routes.

POST /api/auth/login   - authenticate and create session
POST /api/auth/logout  - revoke session and clear cookie
GET  /api/auth/me      - return current authenticated user
"""

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.auth.models import LoginRequest, LoginResponse, User, UserPublic
from app.auth.service import (
    SESSION_COOKIE_NAME,
    authenticate_user,
    create_session,
    revoke_session,
    to_public,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# Generic auth failure message (never reveal whether username or password
# was wrong — prevents username enumeration).
_GENERIC_AUTH_ERROR = "Invalid username or password"


class LogoutResponse(BaseModel):
    detail: str


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, response: Response, request: Request):
    """Authenticate with username + password.

    On success: creates a server-side session and sets an HttpOnly cookie.
    On failure: returns 401 with a generic message.
    """
    db = request.app.state.session_factory()
    try:
        user = authenticate_user(db, body.username, body.password)
        if user is None:
            raise HTTPException(status_code=401, detail=_GENERIC_AUTH_ERROR)

        raw_session_id, _session = create_session(db, user.id)

        # Set HttpOnly cookie (Secure=False for dev over HTTP)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=raw_session_id,
            httponly=True,
            secure=False,  # TODO: True in production with HTTPS
            samesite="lax",
            path="/",
            max_age=7 * 24 * 60 * 60,  # 7 days
        )
        return LoginResponse(user=to_public(user))
    finally:
        db.close()


@router.post("/logout", response_model=LogoutResponse)
def logout(
    response: Response,
    request: Request,
    sast_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    """Revoke the current session and clear the cookie.

    Idempotent: calling logout when not logged in is safe.
    """
    if sast_session:
        db = request.app.state.session_factory()
        try:
            revoke_session(db, sast_session)
        finally:
            db.close()

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
    )
    return LogoutResponse(detail="Logged out")


@router.get("/me", response_model=UserPublic)
def me(request: Request, user: User = Depends(get_current_user)):
    """Return the currently authenticated user."""
    return to_public(user)
