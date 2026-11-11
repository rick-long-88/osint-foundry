"""Web archive stage.

Queries the Internet Archive's CDX index for historical snapshots of the
target. Produces a timeline of availability so the local investigations can
reconstruct how a domain's content changed over time — same signal that
drives osintpilot's archive step but surfaced as a structured timeline.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..model import Finding, Report
from ..transport import fetch
from .base import Collector


class WebArchiveCollector(Collector):
    """Timeline of web-archive availability for a target."""

    kind = "archive"
    sources = [
        "web.archive.org/cdx/search/cdx",
        "archive.org/wayback/available",
    ]

    def collect(self, target: str, report: Report) -> None:
        self._cdx_timeline(target, report)

    @classmethod
    def _cdx_timeline(cls, target: str, report: Report) -> None:
        url = f"http://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=30&from=2010&to=2026&collapse=digest"
        res = fetch(url, timeout=(6, 20))
        if not res.get("ok"):
            report.findings.append(
                Finding(
                    category="archive",
                    subtype="cdx",
                    target=target,
                    summary=f"CDX timeline lookup failed ({res.get('error')})",
                    source="archive.org",
                    confidence=0.0,
                    raw=res.get("error", ""),
                )
            )
            return
        content = res.get("content", "")
        if not content.strip():
            report.findings.append(
                Finding(
                    category="archive",
                    subtype="cdx",
                    target=target,
                    summary="No archive captures found for target.",
                    source="archive.org CDX",
                    confidence=0.95,
                )
            )
            return
        try:
            data = __import__("json").loads(content)
        except ValueError:
            report.findings.append(
                Finding(
                    category="archive",
                    subtype="cdx",
                    target=target,
                    summary="CDX returned non-JSON (truncated content).",
                    source="archive.org CDX",
                    confidence=0.0,
                    raw=content[:200],
                )
            )
            return
        # CDX rows: [urlkey, timestamp, original, mimetype, statuscode, digest, length]
        rows = data if isinstance(data, list) else data.get("result", [])
        if not rows or len(rows) < 2:
            report.findings.append(
                Finding(
                    category="archive",
                    subtype="cdx",
                    target=target,
                    summary="No CDX records returned.",
                    source="archive.org CDX",
                    confidence=0.95,
                )
            )
            return
        # Column 2 = timestamp, column 4 = status, column 6 = length
        timeline = []
        for row in rows[1:]:
            if len(row) < 7:
                continue
            ts, status, length = row[1], row[4], row[6]
            timeline.append({"timestamp": ts, "status": status, "length": length})

        if timeline:
            span = f"{timeline[0]['timestamp']} → {timeline[-1]['timestamp']}"
            report.findings.append(
                Finding(
                    category="archive",
                    subtype="cdx",
                    target=target,
                    summary=f"Archive timeline ({len(timeline)} captures): {span}",
                    source="archive.org CDX",
                    confidence=0.8,
                    value={"timeline": timeline, "span": span},
                )
            )
        else:
            report.findings.append(
                Finding(
                    category="archive",
                    subtype="cdx",
                    target=target,
                    summary="No archive captures found for target.",
                    source="archive.org CDX",
                    confidence=0.95,
                )
            )
