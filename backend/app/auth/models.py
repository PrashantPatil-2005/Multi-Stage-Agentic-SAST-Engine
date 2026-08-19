"""Auth domain models (Pydantic contracts for User and Session).

These models are the source of truth for the auth API contracts, following
the same pattern as the rest of the pipeline: Pydantic models hold the
domain data, SQLAlchemy rows mirror them in SQLite.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

Role = Literal["analyst", "manager", "developer", "auditor"]


class User(BaseModel):
    id: str
    username: str
    display_name: str
    password_hash: str
    role: Role
    is_active: bool = True
    created_at: datetime


class UserPublic(BaseModel):
    """User representation safe for API responses (no password hash)."""

    id: str
    username: str
    display_name: str
    role: Role
    is_active: bool


class Session(BaseModel):
    id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    user: UserPublic
