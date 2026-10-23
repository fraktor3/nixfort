"""Production / lab deployment (Docker Compose behind nginx with TLS).

Every secret is mandatory: a missing variable is a startup error, not a silent default.
"""

import os

from .base import *  # noqa: F403


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"environment variable {name} is required")
    return value


DEBUG = False
SECRET_KEY = _require("DJANGO_SECRET_KEY")
if len(SECRET_KEY) < 40:
    raise RuntimeError("DJANGO_SECRET_KEY is too short (>= 40 chars)")
ALLOWED_HOSTS = [h.strip() for h in _require("DJANGO_ALLOWED_HOSTS").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = [h.strip() for h in _require("DJANGO_CSRF_TRUSTED_ORIGINS").split(",") if h.strip()]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _require("POSTGRES_DB"),
        "USER": _require("POSTGRES_USER"),
        "PASSWORD": _require("POSTGRES_PASSWORD"),
        "HOST": os.environ.get("POSTGRES_HOST", "postgres"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 60,
    }
}

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = False  # nginx redirects 80 -> 443
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
NIXFORT_REDIS_LOCKS = True

# nginx terminates TLS and redirects 80->443; the app is reached by IP (no subdomains, no preload list).
SILENCED_SYSTEM_CHECKS = ["security.W005", "security.W008", "security.W021"]
