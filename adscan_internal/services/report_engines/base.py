"""Base interface and registry for PDF engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class EngineRenderError(RuntimeError):
    """Raised when a PDF engine fails to render HTML to PDF."""


class ReportEngine(ABC):
    """Abstract base class for PDF render engines.

    An engine converts an HTML string (already rendered from a Jinja template
    and theme CSS) into PDF bytes. Engines differ in CSS capability,
    distribution footprint, and rendering fidelity.
    """

    name: str = "base"

    @abstractmethod
    def render_pdf(
        self,
        html_str: str,
        *,
        base_url: str | Path | None = None,
        options: dict[str, Any] | None = None,
    ) -> bytes:
        """Render an HTML string to PDF bytes.

        Args:
            html_str: Full HTML document as string (with embedded CSS and data URIs).
            base_url: Optional base URL for resolving relative resources.
            options: Engine-specific options (page size, margins, print-mode, etc.).

        Returns:
            Raw PDF bytes.

        Raises:
            EngineRenderError: If rendering fails.
        """

    def is_available(self) -> tuple[bool, str]:
        """Return ``(available, reason)`` indicating if the engine can run.

        Default implementation returns ``(True, "")`` — subclasses may probe
        runtime libraries, binaries, or installed browsers.
        """
        return True, ""


# ── Registry ──────────────────────────────────────────────────────────────

_REGISTRY: dict[str, type[ReportEngine]] = {}


def register_engine(engine_cls: type[ReportEngine]) -> type[ReportEngine]:
    """Register a ``ReportEngine`` subclass under its ``name``."""
    key = engine_cls.name.lower()
    if not key or key == "base":
        raise ValueError(f"Engine class {engine_cls.__name__} must declare a non-empty, non-'base' name attribute.")
    _REGISTRY[key] = engine_cls
    return engine_cls


def get_engine(name: str) -> ReportEngine:
    """Instantiate an engine by registered name."""
    key = (name or "").lower()
    if key not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        raise KeyError(f"Unknown PDF engine '{name}'. Available: {available}")
    return _REGISTRY[key]()


def list_engines() -> list[str]:
    """Return sorted list of registered engine names."""
    return sorted(_REGISTRY)
