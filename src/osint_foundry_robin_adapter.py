"""Robin adapter: bridge apurvsinghgautam/robin into osint-foundry.

Robin is a dark-web OSINT investigator. It searches dark-web engines, filters
and scrapes the results, and produces a text summary. This module adapts
Robin's raw investigation record into the osint-foundry model so that a Robin
run is just another collector stage.

Layout (all files shipped from the GitHub repo):

    src/osint_foundry/robin/    namespaced copies of the GitHub files

Usage (from within osint-foundry):

    from osint_foundry_robin import load_robin_config, run_robin_investigation
    record = run_robin_investigation(target, config_overrides={...})
    findings = osint_foundry_robin.to_findings(record, target)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# The `robin` sub-package sits inside osint_foundry/. The adapter lives in
# src/osint_foundry_robin_adapter.py, so its parent dir is src/, and we go up
# into osint_foundry/robin from there.
_ROBIN_PKG = Path(__file__).resolve().parent / "osint_foundry" / "robin"
if str(_ROBIN_PKG) not in sys.path:
    sys.path.insert(0, str(_ROBIN_PKG))

# Re-export the sub-module names for convenience.
import config as _robin_config  # noqa: F401
import pipeline as _robin_pipeline  # noqa: F401
import llm as _robin_llm  # noqa: F401
import llm_utils as _robin_llm_utils  # noqa: F401
import model_registry as _robin_model_registry  # noqa: F401
import prompts as _robin_prompts  # noqa: F401
import scrape as _robin_scrape  # noqa: F401
import search as _robin_search  # noqa: F401
import store as _robin_store  # noqa: F401
from pipeline import Investigation  # noqa: F401

# Convenience re-exports.
__all__ = [
    "load_robin_config",
    "run_robin_investigation",
    "to_findings",
    "Investigation",
]

# Keys in the `value` dict the GitHub pipeline puts behind API keys, engine
# URLs and internal state. Never emit them into a report.
_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "openai_api_key",
        "anthropic_api_key",
        "google_api_key",
        "openrouter_api_key",
        "mistral_api_key",
        "custom_api_key",
        "private_key",
        "oauth",
        "bearer",
        "session_token",
        "auth_token",
        "debug",
        "log",
        "verbose",
        "tests",
        "test",
        "env",
    }
)


def load_robin_config(env=None) -> "RobinConfig":
    """Build a ``RobinConfig`` from the process environment.

    ``env`` overrides just for tests. Secrets are redacted by the caller.
    """
    from config import RobinConfig, _clean_env

    if env is None:
        env = os.environ
    return RobinConfig.from_env(env)


def run_robin_investigation(
    target: str,
    cfg: "RobinConfig | None" = None,
    *,
    model: str = "",
    preset: str = "threat_intel",
    max_results: int = 25,
    max_scrape: int = 8,
    content_chars: int = 6000,
    threads: int = 4,
    investigations_dir: str | None = None,
    save: bool = False,
) -> "Investigation":
    """Run a Robin investigation and return its record (never persisted).

    The caller supplies a config so the defaults can be overridden without
    mutating the environment, and ``save`` is false so the record stays in
    memory only.
    """
    from config import RobinConfig

    # The adapter lives inside osint_foundry, so the sibling `robin` package is
    # importable via the path set up at module import time.
    cfg = cfg or load_robin_config()

    from pipeline import run_investigation as _run

    inv = _run(
        cfg=cfg,
        query=target,
        model=model or cfg.robin_model or "host",
        preset=preset,
        max_results=max_results,
        max_scrape=max_scrape,
        content_chars=content_chars,
        threads=threads,
        investigations_dir=investigations_dir or os.getcwd(),
        save=save,
        search_fn=None,
        scrape_fn=None,
        llm_factory=None,
    )
    return inv


def _scrub(raw: str) -> str:
    """Strip secrets and internal noise from a scraped payload before use."""
    out = str(raw)
    for key in _SENSITIVE_KEYS:
        out = out.replace(key, "[REDACTED]")
    return out.strip()


def to_findings(inv: "Investigation", target: str) -> list[dict[str, object]]:
    """Convert a completed Robin investigation into osint-foundry Finding dicts.

    Robin's own ``to_record`` already exposes the useful fields. The adapter
    re-keys them so the report builder and the web UI treat Robin as a first-
    class collector.
    """
    out: list[dict[str, object]] = []
    if inv is None:
        return out

    record = inv.to_record() if hasattr(inv, "to_record") else {}
    sources = record.get("sources") or []

    if isinstance(sources, list):
        for i, item in enumerate(sources):
            if not isinstance(item, dict):
                continue
            summary = str(item.get("summary") or item.get("title") or "Robin result")
            url = str(item.get("url") or "")
            if not url and isinstance(item.get("raw"), str):
                import re as _re

                m = _re.search(r"https?://[^\s]+", item["raw"])
                if m:
                    url = m.group(0)
            out.append(
                {
                    "category": "dark-web",
                    "subtype": "search_result",
                    "target": target,
                    "summary": summary[:300],
                    "source": url or f"robin:{i}",
                    "confidence": 0.65,
                    "value": {
                        "url": url,
                        "index": i,
                        "raw_notes": _scrub(
                            item.get("raw")
                            or item.get("snippet")
                            or item.get("title")
                            or ""
                        ),
                    },
                    "raw": _scrub(
                        item.get("raw")
                        or item.get("snippet")
                        or item.get("title")
                        or ""
                    ),
                }
            )

    # Summary is the headline finding.
    if inv.summary:
        out.append(
            {
                "category": "dark-web",
                "subtype": "investigation_summary",
                "target": target,
                "summary": str(inv.summary)[:600],
                "source": "robin.investigation",
                "confidence": 0.55,
                "value": {"query": inv.query, "model": inv.model or "unknown"},
                "raw": str(inv.summary),
            }
        )

    # Pivots are cross-reference candidates.
    for p in (inv.pivots or []):
        out.append(
            {
                "category": "dark-web",
                "subtype": "pivot",
                "target": target,
                "summary": f"Pivot: {str(p)[:120]}",
                "source": "robin.pivots",
                "confidence": 0.50,
                "value": {"pivot": str(p)},
                "raw": str(p),
            }
        )

    return out
