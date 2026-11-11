"""Public records stage.

Open-source corporate and registrant-record lookups: SEC EDGAR company
filings, OpenCorporates (global company register), and WHOIS/RDAP registrant
data. These are our "public records" drop.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import requests

from ..model import Finding, Report
from ..transport import fetch
from .base import Collector

# wid = WHOIS/EDGAR/OpenCorporates "wide" sources
_WID = [
    "sec.gov EDGAR",
    "opencorporates.com",
    "whois.icann.org",
]

_SENSITIVE = {"password", "secret", "token", "api_key", "private_key"}


class PublicRecordsCollector(Collector):
    """Corporate/filing/registrant records for a target domain or entity name."""

    kind = "records"
    sources = _WID

    def collect(self, target: str, report: Report) -> None:
        if self._looks_like_cve(target):
            return
        # Target may be a company name or domain.
        if self._looks_like_domain(target):
            self._edgar_lookup(target, report)
            self._opencorporates_lookup(target, report)
        else:
            # Free-text company name usually needs the opaque-name endpoint.
            self._opencorporates_lookup(target, report)
            self._generic_whois(target, report)

    # ---- helpers ---------------------------------------------------------

    @classmethod
    def _looks_like_domain(cls, target: str) -> bool:
        return bool(re.fullmatch(r"(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", target.strip()))

    @classmethod
    def _looks_like_cve(cls, target: str) -> bool:
        import re
        return bool(re.fullmatch(r"CVE-\d{4}-\d+", target.strip().upper()))

    def _edgar_lookup(self, target: str, report: Report) -> None:
        """Search SEC EDGAR for filings mentioning TARGET."""
        try:
            res = requests.get(
                f"https://efts.sec.gov/LATEST/search-index?q={target}&size=5",
                headers={"User-Agent": "osint-foundry/0.2"},
                timeout=(5, 12), stream=True,
            )
            res.raise_for_status()
            # Short-circuit after first page.
            count = 0
            for item in res.json().get("matches", [])[:5]:
                cik = item.get("CIK", "")
                title = item.get("Title", "")
                form = item.get("Form", "10-K")
                report.findings.append(
                    Finding(
                        category="records",
                        subtype="sec-edgar",
                        target=target,
                        summary=f"EDGAR '{title}' ({form}, CIK {cik})",
                        source="sec.gov EDGAR",
                        confidence=0.7,
                        value={"cik": cik, "title": title, "form": form},
                    )
                )
                count += 1
            if count:
                report.findings.append(
                    Finding(
                        category="records",
                        subtype="sec-edgar",
                        target=target,
                        summary=f"EDGAR: {count} filing(s) found.",
                        source="sec.gov EDGAR",
                        confidence=0.7,
                    )
                )
        except Exception as exc:  # network / parse
            report.findings.append(
                Finding(
                    category="records",
                    subtype="sec-edgar",
                    target=target,
                    summary=f"EDGAR lookup failed: {exc}",
                    source="sec.gov EDGAR",
                    confidence=0.0,
                    raw=str(exc),
                )
            )

    def _opencorporates_lookup(self, target: str, report: Report) -> None:
        """Query OpenCorporates API for companies named/targeted."""
        name = target.strip()
        # Try a bare company search endpoint (no key = rate limited, just test).
        for endpoint in (f"https://api.opencorporates.com/v0.4/companies/search?name={name}",):
            try:
                res = fetch(endpoint, timeout=(6, 15))
                if not res.get("ok"):
                    continue
                data = __import__("json").loads(res.get("content", "{}"))
                companies = data.get("data", [])
                if companies:
                    for c in companies[:3]:
                        report.findings.append(
                            Finding(
                                category="records",
                                subtype="opencorporates",
                                target=target,
                                summary=f"OpenCorporates: {c.get('jurisdiction', '')} - {c.get('name', '')} ({c.get('incorporation_country', '')})",
                                source="opencorporates.com",
                                confidence=0.75,
                            )
                        )
                else:
                    report.findings.append(
                        Finding(
                            category="records",
                            subtype="opencorporates",
                            target=target,
                            summary="OpenCorporates: no company matches.",
                            source="opencorporates.com",
                            confidence=0.9,
                        )
                    )
                return
            except Exception:
                continue

    def _generic_whois(self, target: str, report: Report) -> None:
        # WHOIS registrant info (IRTP whois) for the lookup target.
        try:
            res = fetch(f"https://whois.icann.org/en/whois-results?query={requests.utils.quote(target)}", timeout=(6, 15))
            if not res.get("ok"):
                report.findings.append(
                    Finding(
                        category="records",
                        subtype="whois",
                        target=target,
                        summary=f"WHOIS lookup failed ({res.get('error')})",
                        source="whois.icann.org",
                        confidence=0.0,
                    )
                )
                return
            text = res.get("content", "")
            if not text.strip():
                report.findings.append(
                    Finding(
                        category="records",
                        subtype="whois",
                        target=target,
                        summary="WHOIS empty (often a rate-limit/privacy response).",
                        source="whois.icann.org",
                        confidence=0.0,
                    )
                )
                return
            # Pull registrant and creation dates if present.
            registrant = re.search(r"Registrant[:\s]*([^\n]{3,120})", text, re.I)
            created = re.search(r"Created[:\s]*([^\n]{3,40})", text, re.I)
            snippet = " | ".join(
                p for p in [registrant.group(1) if registrant else None, created.group(1) if created else None] if p
            )
            report.findings.append(
                Finding(
                    category="records",
                    subtype="whois",
                    target=target,
                    summary=f"WHOIS registrant/creation: {snippet}" if snippet else "WHOIS returned host-level data (no registrant fields exposed).",
                    source="whois.icann.org",
                    confidence=0.7,
                    raw=text[:300],
                )
            )
        except Exception as exc:
            report.findings.append(
                Finding(
                    category="records",
                    subtype="whois",
                    target=target,
                    summary=f"WHOIS failed: {exc}",
                    source="whois.icann.org",
                    confidence=0.0,
                    raw=str(exc),
                )
            )
