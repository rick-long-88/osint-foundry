"""Web UI package for osint-foundry.

Exposes the interactive HTML report viewer (Leaflet + findings table) and
the underlying exports writer used by the ``web`` CLI command.
"""

from .ui import build_ui_html, fast_serve, serve_report  # noqa: F401

__all__ = ["build_ui_html", "serve_report", "fast_serve"]
