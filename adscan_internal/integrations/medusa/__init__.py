"""Medusa integration helpers.

This package exposes a small, reusable abstraction for Medusa so protocol
backends can move away from other tools without coupling service logic to one
CLI flow.
"""

from .helpers import MedusaSweepSettings, build_medusa_login_sweep_command
from .parsers import MedusaAccountMatch, parse_medusa_account_matches
from .runner import MedusaContext, MedusaRunner
from .settings import get_recommended_medusa_settings

__all__ = [
    "MedusaAccountMatch",
    "MedusaContext",
    "MedusaRunner",
    "MedusaSweepSettings",
    "build_medusa_login_sweep_command",
    "get_recommended_medusa_settings",
    "parse_medusa_account_matches",
]
