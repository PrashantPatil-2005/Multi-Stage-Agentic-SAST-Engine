"""Application configuration (fixture)."""

import os

DATABASE_PATH = os.environ.get("APP_DB", "app.db")
SECRET_KEY = os.environ.get("APP_SECRET")
DEBUG = os.environ.get("APP_DEBUG", "false").lower() == "true"
