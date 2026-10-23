"""Unit tests: SQLite in memory, Celery eager, fast hasher."""

from .base import *  # noqa: F403

DEBUG = False
SECRET_KEY = "test-only-insecure-key"  # noqa: S105
ALLOWED_HOSTS = ["testserver", "localhost"]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
NIXFORT_REDIS_LOCKS = False  # in-process locks in unit tests
NIXFORT_DATA_DIR = BASE_DIR.parent / "var" / "test"  # noqa: F405
