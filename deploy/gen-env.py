#!/usr/bin/env python3
"""Create .env with random secrets (only if it does not exist)."""

import pathlib
import secrets
import sys

root = pathlib.Path(__file__).resolve().parent.parent
env = root / ".env"
if env.exists():
    text = env.read_text(encoding="utf-8")
    if "REDIS_PASSWORD=" not in text:  # upgrade of an older .env (before ADR-026)
        env.write_text(text.rstrip("\n") + f"\nREDIS_PASSWORD={secrets.token_hex(24)}\n", encoding="utf-8")
        print("added REDIS_PASSWORD to existing .env")
        sys.exit(0)
    sys.exit(".env already exists - not overwritten")
example = (root / ".env.example").read_text(encoding="utf-8")
example = example.replace(
    "DJANGO_SECRET_KEY=change-me-50-random-chars", f"DJANGO_SECRET_KEY={secrets.token_urlsafe(50)}"
)
example = example.replace("POSTGRES_PASSWORD=change-me", f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")
example = example.replace("REDIS_PASSWORD=change-me", f"REDIS_PASSWORD={secrets.token_hex(24)}")
env.write_text(example, encoding="utf-8")
env.chmod(0o600)
print("created .env")
