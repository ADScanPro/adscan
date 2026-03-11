"""Centralized password generation and validation helpers."""

from __future__ import annotations

import secrets
import string

CLI_SAFE_PASSWORD_SYMBOLS = "!#$%^&*_+="
CLI_SAFE_PASSWORD_ALNUM = string.ascii_lowercase + string.ascii_uppercase + string.digits


def generate_strong_password(length: int = 12) -> str:
    """Generate a random password with AD and CLI-safe complexity guarantees.

    The generated password intentionally avoids characters and edge-cases that
    frequently break shell-built command strings or argument parsers in third-
    party tools:
    - first character is always alphanumeric
    - no whitespace
    - no quotes/backslashes
    - no leading hyphen
    """
    if length < 12:
        length = 12

    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = CLI_SAFE_PASSWORD_SYMBOLS
    pool = CLI_SAFE_PASSWORD_ALNUM + symbols

    first_char = secrets.choice(CLI_SAFE_PASSWORD_ALNUM)
    chars = [first_char]

    if first_char not in lowers:
        chars.append(secrets.choice(lowers))
    if first_char not in uppers:
        chars.append(secrets.choice(uppers))
    if first_char not in digits:
        chars.append(secrets.choice(digits))
    chars.append(secrets.choice(symbols))
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))

    shuffled: list[str] = []
    tail = chars[1:]
    while tail:
        shuffled.append(tail.pop(secrets.randbelow(len(tail))))
    return first_char + "".join(shuffled)


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
