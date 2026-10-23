"""Local development (not for the lab, not for production)."""

from .base import *  # noqa: F403
from .base import BASE_DIR

DEBUG = True
SECRET_KEY = "dev-only-insecure-key-do-not-use-anywhere-else"  # noqa: S105
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR.parent / "var" / "dev.sqlite3"}}
CELERY_TASK_ALWAYS_EAGER = True
