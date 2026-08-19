"""Authentication service: password hashing, session management, user CRUD.

Uses bcrypt for password hashing and a server-side session model stored
in SQLite. Session IDs are cryptographically random and delivered to the
browser via an HttpOnly cookie.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from sqlalchemy.orm import Session as DbSession

from app.auth.models import Role, Session, User, UserPublic
from app.core.time import as_aware_utc
from app.db.models import SessionRow, UserRow

logger = logging.getLogger(__name__)

# Session lifetime: 7 days
SESSION_LIFETIME = timedelta(days=7)

# Cookie name used for the session identifier
SESSION_COOKIE_NAME = "sast_session"

# Invalid-credentials error message (same for username and password)
_GENERIC_AUTH_ERROR = "Invalid username or password"


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password* (salted, constant-time)."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification of *password* against *password_hash*."""
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except Exception:
        # Any bcrypt error (malformed hash, etc.) → reject
        return False


# ---------------------------------------------------------------------------
# Session ID helpers
# ---------------------------------------------------------------------------

def generate_session_id() -> str:
    """Generate a cryptographically random session identifier."""
    return secrets.token_urlsafe(32)


def session_id_hash(session_id: str) -> str:
    """Hash a session ID for storage (we store the hash, not the raw token)."""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# User persistence
# ---------------------------------------------------------------------------

def create_user(
    db: DbSession,
    username: str,
    display_name: str,
    password: str,
    role: Role,
    is_active: bool = True,
) -> User:
    """Create and persist a new user.  Returns the User domain model."""
    now = datetime.now(timezone.utc)
    user_id = uuid.uuid4().hex[:16]
    user = User(
        id=user_id,
        username=username,
        display_name=display_name,
        password_hash=hash_password(password),
        role=role,
        is_active=is_active,
        created_at=now,
    )
    row = UserRow(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        password_hash=user.password_hash,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
    )
    db.add(row)
    db.commit()
    logger.info("created user %s (role=%s)", username, role)
    return user


def get_user_by_username(db: DbSession, username: str) -> User | None:
    """Look up a user by username.  Returns None if not found."""
    row = db.query(UserRow).filter(UserRow.username == username).first()
    if row is None:
        return None
    return _row_to_user(row)


def get_user_by_id(db: DbSession, user_id: str) -> User | None:
    """Look up a user by ID.  Returns None if not found."""
    row = db.query(UserRow).filter(UserRow.id == user_id).first()
    if row is None:
        return None
    return _row_to_user(row)


def user_exists(db: DbSession, username: str) -> bool:
    """Check whether a username is already taken."""
    return db.query(UserRow).filter(UserRow.username == username).first() is not None


def _row_to_user(row: UserRow) -> User:
    return User(
        id=row.id,
        username=row.username,
        display_name=row.display_name,
        password_hash=row.password_hash,
        role=row.role,
        is_active=row.is_active,
        created_at=as_aware_utc(row.created_at),
    )


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

def create_session(db: DbSession, user_id: str) -> tuple[str, Session]:
    """Create a new session, return (raw_session_id, Session model).

    The raw session ID is what goes into the cookie.  Only the *hash* of
    the ID is stored in the database.
    """
    now = datetime.now(timezone.utc)
    raw_id = generate_session_id()
    session = Session(
        id=session_id_hash(raw_id),
        user_id=user_id,
        created_at=now,
        expires_at=now + SESSION_LIFETIME,
    )
    row = SessionRow(
        id=session.id,
        user_id=session.user_id,
        created_at=session.created_at,
        expires_at=session.expires_at,
        revoked_at=session.revoked_at,
    )
    db.add(row)
    db.commit()
    return raw_id, session


def get_session(db: DbSession, raw_session_id: str) -> Session | None:
    """Validate and return a session by raw ID.

    Returns None if the session is missing, expired, or revoked.
    """
    hashed = session_id_hash(raw_session_id)
    row = db.query(SessionRow).filter(SessionRow.id == hashed).first()
    if row is None:
        return None
    session = _row_to_session(row)
    now = datetime.now(timezone.utc)
    if session.revoked_at is not None:
        return None
    if as_aware_utc(session.expires_at) < now:
        return None
    return session


def revoke_session(db: DbSession, raw_session_id: str) -> None:
    """Mark a session as revoked (logout)."""
    hashed = session_id_hash(raw_session_id)
    row = db.query(SessionRow).filter(SessionRow.id == hashed).first()
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("session revoked: %s", hashed[:12])


def revoke_all_user_sessions(db: DbSession, user_id: str) -> None:
    """Revoke every session for a given user."""
    rows = (
        db.query(SessionRow)
        .filter(SessionRow.user_id == user_id, SessionRow.revoked_at.is_(None))
        .all()
    )
    now = datetime.now(timezone.utc)
    for row in rows:
        row.revoked_at = now
    if rows:
        db.commit()


def _row_to_session(row: SessionRow) -> Session:
    return Session(
        id=row.id,
        user_id=row.user_id,
        created_at=as_aware_utc(row.created_at),
        expires_at=as_aware_utc(row.expires_at),
        revoked_at=as_aware_utc(row.revoked_at) if row.revoked_at else None,
    )


# ---------------------------------------------------------------------------
# Login / Authenticate
# ---------------------------------------------------------------------------

def authenticate_user(
    db: DbSession, username: str, password: str
) -> User | None:
    """Authenticate by username + password.

    Returns the User on success, None on failure.
    Uses a single generic error message to avoid username enumeration.
    """
    user = get_user_by_username(db, username)
    if user is None:
        # Constant-time dummy hash to prevent timing-based enumeration
        bcrypt.gensalt()
        return None
    if not verify_password(password, user.password_hash):
        return None
    if not user.is_active:
        return None
    return user


def to_public(user: User) -> UserPublic:
    """Strip sensitive fields for API responses."""
    return UserPublic(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        is_active=user.is_active,
    )
