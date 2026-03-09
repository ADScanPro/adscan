"""Centralized password generation and validation helpers."""

from __future__ import annotations

import secrets
import string


def generate_strong_password(length: int = 12) -> str:
    """Generate a random password with AD-friendly complexity guarantees."""
    if length < 12:
        length = 12

    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*_-+="
    pool = lowers + uppers + digits + symbols

    chars = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))

    shuffled: list[str] = []
    while chars:
        shuffled.append(chars.pop(secrets.randbelow(len(chars))))
    return "".join(shuffled)


def is_password_complex(value: str) -> bool:
    """Return True when a password meets the minimum AD complexity target."""
    password = str(value or "")
    if len(password) < 12:
        return False
    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() for char in password)
    return has_lower and has_upper and has_digit and has_symbol
