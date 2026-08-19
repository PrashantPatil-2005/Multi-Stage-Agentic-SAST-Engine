"""Demo user seeding (idempotent).

Creates four demo users on application startup:
  - analyst  / Security Analyst
  - manager  / Security Manager
  - developer / Developer
  - auditor  / Auditor

All share the same demo password (see DEMO_PASSWORD).

Seeding is idempotent: users with the same username are not duplicated.
"""

import logging

from sqlalchemy.orm import Session as DbSession

from app.auth.service import (
    create_user,
    get_user_by_username,
    hash_password,
    user_exists,
    verify_password,
)

logger = logging.getLogger(__name__)

# Demo-only password — documented in developer docs, never logged.
DEMO_PASSWORD = "demo123"

# (username, display_name, role)
_DEMO_USERS = [
    ("analyst", "Security Analyst", "analyst"),
    ("manager", "Security Manager", "manager"),
    ("developer", "Developer", "developer"),
    ("auditor", "Auditor", "auditor"),
]


def seed_demo_users(db: DbSession) -> None:
    """Create demo users if they don't already exist, or fix broken password hashes.

    Safe to call multiple times (idempotent).  If an existing user's
    password hash cannot be verified, it is re-hashed with the demo password.
    """
    for username, display_name, role in _DEMO_USERS:
        existing = get_user_by_username(db, username)
        if existing is not None:
            if not verify_password(DEMO_PASSWORD, existing.password_hash):
                from app.db.models import UserRow

                db_row = db.query(UserRow).filter(UserRow.username == username).first()
                if db_row is not None:
                    db_row.password_hash = hash_password(DEMO_PASSWORD)
                    db.commit()
                    logger.warning(
                        "fixed broken password hash for demo user: %s", username
                    )
            continue
        create_user(db, username, display_name, DEMO_PASSWORD, role)
        logger.info("seeded demo user: %s (role=%s)", username, role)

    logger.info("demo user seeding complete")
