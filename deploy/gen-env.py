#!/usr/bin/env python3
"""Create .env with random secrets (only if it does not exist)."""

import pathlib
import secrets
import sys

root = pathlib.Path(__file__).resolve().parent.parent
env = root / ".env"
if env.exists():
    sys.exit(".env already exists - not overwritten")
example = (root / ".env.example").read_text(encoding="utf-8")
example = example.replace("DJANGO_SECRET_KEY=change-me-50-random-chars", f"DJANGO_SECRET_KEY={secrets.token_urlsafe(50)}")
example = example.replace("POSTGRES_PASSWORD=change-me", f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")
env.write_text(example, encoding="utf-8")
env.chmod(0o600)
print("created .env")
