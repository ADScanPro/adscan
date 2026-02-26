#!/usr/bin/env python3
"""Entry point for running ``python -m bloodhound_cli``."""

from .main import main


def run() -> None:
    """Invoke the CLI main entry point."""
    main()


if __name__ == "__main__":
    run()
