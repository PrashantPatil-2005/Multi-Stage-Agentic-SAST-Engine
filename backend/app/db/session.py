"""Database engine/session helpers.

SQLite is used for local development and tests (no external service needed).
Set SAST_DATABASE_URL to a PostgreSQL URL to run against Postgres.
"""

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str):
    kwargs = {}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(database_url, **kwargs)
    logger.debug("database engine created for %s", database_url.split("@")[-1])
    return engine


def init_db(engine) -> None:
    from app.db import models  # noqa: F401  (register tables)

    Base.metadata.create_all(bind=engine)


def make_session_factory(engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)
