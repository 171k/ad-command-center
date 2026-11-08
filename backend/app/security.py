"""Password hashing, token generation and CSRF helpers.

- Passwords hashed with Argon2id (argon2-cffi defaults are memory-hard and modern).
- Session tokens are high-entropy random strings; only their SHA-256 hash is
  stored, so a DB read cannot resume a session.
- CSRF uses the double-submit pattern: a random token in a readable cookie must
  match the X-CSRF-Token header on state-changing requests.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

_ph = PasswordHasher()  # Argon2id defaults


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")
