"""Configuration models using pydantic-settings."""

from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Optional

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from adscan_internal.bloodhound_ce_compose import BLOODHOUND_CE_DEFAULT_WEB_PORT

try:
    import pwd  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    pwd = None


def _get_effective_user_home() -> Path:
    """Return the home directory that should own BloodHound CLI config/state.

    If running under sudo, prefer the invoking user's home directory so we don't
    split configuration between `/root` and the normal user's home.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        if pwd is not None:
            try:
                return Path(pwd.getpwnam(sudo_user).pw_dir)
            except KeyError:
                pass
    return Path.home()


CONFIG_FILE = _get_effective_user_home() / ".bloodhound_config"


class CEConfig(BaseSettings):
    """Settings for BloodHound CE edition."""

    base_url: AnyHttpUrl = Field(
        default=f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
    )
    api_token: Optional[str] = None
    username: str = "admin"
    password: Optional[str] = None
    verify: bool = True

    model_config = SettingsConfigDict(env_prefix="ce_", env_file=".env", extra="ignore")


class LegacyConfig(BaseSettings):
    """Settings for BloodHound legacy (Neo4j)."""

    uri: str = Field(default="bolt://localhost:7687")
    user: str = "neo4j"
    password: str = "neo4j"

    model_config = SettingsConfigDict(
        env_prefix="legacy_", env_file=".env", extra="ignore"
    )


def load_ce_config() -> CEConfig:
    """Load CE config from env vars, .env y ~/.bloodhound_config."""
    defaults = {}
    if CONFIG_FILE.exists():
        parser = configparser.ConfigParser()
        parser.read(CONFIG_FILE)
        if parser.has_section("CE"):
            defaults.update(parser["CE"])  # type: ignore[arg-type]
    return CEConfig(**defaults)


def load_legacy_config() -> LegacyConfig:
    """Load legacy config from env vars, .env y ~/.bloodhound_config."""
    defaults = {}
    if CONFIG_FILE.exists():
        parser = configparser.ConfigParser()
        parser.read(CONFIG_FILE)
        if parser.has_section("LEGACY"):
            defaults.update(parser["LEGACY"])  # type: ignore[arg-type]
    return LegacyConfig(**defaults)


def write_ce_config(
    *,
    base_url: str,
    api_token: str,
    username: str,
    password: str,
    verify: bool = True,
    edition: str = "ce",
) -> None:
    """Persist BloodHound CE configuration in standard format."""
    config = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        config.read(CONFIG_FILE)

    config["CE"] = {
        "base_url": str(base_url),
        "api_token": api_token,
        "username": username,
        "password": password,
        "verify": str(verify).lower(),
    }
    if "GENERAL" not in config:
        config["GENERAL"] = {}
    config["GENERAL"]["edition"] = edition

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as config_file:
        config.write(config_file)


def write_ce_config_skeleton(
    *,
    base_url: str,
    username: str = "admin",
    password: str | None = None,
    verify: bool = True,
    edition: str = "ce",
) -> None:
    """Create a minimal CE config file without an API token."""
    config = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        config.read(CONFIG_FILE)

    config["CE"] = {
        "base_url": str(base_url),
        "api_token": "",
        "username": username,
        "password": password or "",
        "verify": str(verify).lower(),
    }
    if "GENERAL" not in config:
        config["GENERAL"] = {}
    config["GENERAL"]["edition"] = edition

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as config_file:
        config.write(config_file)


def validate_ce_config() -> bool:
    """Return True if ~/.bloodhound_config contains expected CE fields."""
    if not CONFIG_FILE.exists():
        return False

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    if "CE" not in config:
        return False
    required = {"base_url", "api_token", "username", "password", "verify"}
    ce_keys = set(k.lower() for k in config["CE"].keys())
    if not required.issubset(ce_keys):
        return False
    if "GENERAL" not in config:
        return False
    if config["GENERAL"].get("edition") != "ce":
        return False
    return True
