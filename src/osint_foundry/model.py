"""Core data model: findings and the intelligence report they compose."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


@dataclass
class Finding:
    """A single sourced, confidence-scored intelligence item."""

    category: str          # pipeline stage that produced it
    subtype: str           # e.g. "haveibeenpwned", "a_record", "10k"
    target: str            # the queried target (domain/email/ip/cve id)
    summary: str           # human-readable one-liner
    source: str            # tool + endpoint / URL that produced it
    confidence: float = 1.0  # 0.0 (no confidence) -> 1.0 (high)
    value: dict[str, Any] = field(default_factory=dict)
    raw: str = ""          # trimmed text payload for the report

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "subtype": self.subtype,
            "target": self.target,
            "summary": self.summary,
            "source": self.source,
            "confidence": round(self.confidence, 3),
            "value": self.value,
            "raw": self.raw,
        }


@dataclass
class Report:
    """The finished intelligence product."""

    target: str
    started_at: str = ""
    finished_at: str = ""
    status: str = "completed"  # completed | failed | partial
    collectors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "collectors": self.collectors,
            "finding_count": len(self.findings),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_report(target: str) -> Report:
    return Report(
        target=target,
        started_at=now_iso(),
        summary={"target_type": _guess_target_type(target)},
    )


def _guess_target_type(target: str) -> str:
    t = target.strip().lower()
    if "@" in t:
        return "email"
    if t.endswith((".com", ".org", ".net", ".io", ".co", ".gov", ".edu", ".biz")):
        return "domain"
    if "." in t and not t.startswith("."):
        # could be a name, handle, or domain
        return "identifier"
    return "identifier"
def find(report, category=None, subtype=None, src=None):
    """Yield human-readable lines matching every filter (None = any)."""
    for f in report.findings:
        if category is not None and f.category != category:
            continue
        if subtype is not None and f.subtype != subtype:
            continue
        if src is not None and src not in f.source:
            continue
        yield f"[{f.category}] {f.subtype}: {f.summary} (conf {f.confidence:.0%}, src {f.source})"
