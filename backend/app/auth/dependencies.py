"""FastAPI dependencies for authentication.

``get_current_user`` reads the session cookie, validates the session
server-side, and returns the authenticated User.  Use it via::

    @router.get("/protected")
    def protected(user: User = Depends(get_current_user)):
        ...
"""
from collections.abc import Generator

from fastapi import Cookie, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from app.auth.models import User
from app.auth.service import SESSION_COOKIE_NAME, get_session, get_user_by_id


def _get_db(request: Request) -> Generator[DbSession, None, None]:
    """Extract the SQLAlchemy session factory from app state."""
    factory = request.app.state.session_factory
    session = factory()
    try:
        yield session
    finally:
        session.close()


def get_current_user(
    request: Request,
    sast_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: DbSession = Depends(_get_db),
) -> User:
    """Resolve the authenticated user from the session cookie.

    Raises:
        HTTPException 401: if the session is missing, expired, revoked,
            or the user does not exist or is inactive.
    """
    if not sast_session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = get_session(db, sast_session)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user = get_user_by_id(db, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account is inactive")

    return user


def get_optional_user(
    request: Request,
    sast_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: DbSession = Depends(_get_db),
) -> User | None:
    """Like get_current_user but returns None instead of raising 401."""
    if not sast_session:
        return None
    session = get_session(db, sast_session)
    if session is None:
        return None
    user = get_user_by_id(db, session.user_id)
    if user is None or not user.is_active:
        return None
    return user
