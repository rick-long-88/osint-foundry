"""Breach intelligence stage.

Cross-references the target against public breach and vulnerability data:
HaveIBeenPwned breach registries, CVE detail lookups from Circl.lu, and a
sample of the CISA Known Exploited Vulnerabilities (KEV) catalog so the
target's CVEs can be mapped to currently exploited flaws.
"""

from __future__ import annotations

import hashlib
import re

from ..model import Finding, Report
from ..transport import fetch
from .base import Collector


class BreachIntelCollector(Collector):
    """Surface exposed credentials, CVE details and KEV risk."""

    kind = "breach"
    sources = [
        "haveibeenpwned.com/api/v3/breaches",
        "cve.circl.lu/api/cve/{id}",
        "cisa.gov KEV catalog",
    ]

    CONFIDENCE_BRUTE = 0.7
    CONFIDENCE_ETAG = 0.9

    def collect(self, target: str, report: Report) -> None:
        if self._is_domain(target):
            self._breach_lookup(target, report)
        elif self._is_cve(target):
            self._cve_lookup(target, report)
        else:
            self._hibp_lookup(target, report)

    @classmethod
    def _is_domain(cls, target: str) -> bool:
        return target.strip().lower().endswith((".com", ".org", ".net", ".io", ".biz", ".co", ".info"))

    @classmethod
    def _is_cve(cls, target: str) -> bool:
        return bool(re.fullmatch(r"CVE-\d{4}-\d+", target.strip().upper()))

    @classmethod
    def _hibp_lookup(cls, target: str, report: Report) -> None:
        import hashlib
        mailbox, _, _ = target.partition("@")
        if not mailbox:
            return
        digest = hashlib.sha1(mailbox.lower().encode("utf-8")).hexdigest()
        url = f"https://haveibeenpwned.com/api/v3/breaches?account={digest}"
        res = fetch(url, timeout=(5, 15))
        if not res.get("ok"):
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="haveibeenpwned",
                    target=target,
                    summary=f"HIBP lookup failed ({res.get('error')})",
                    source="haveibeenpwned.com",
                    confidence=0.0,
                    raw=res.get("error", ""),
                )
            )
            return
        try:
            data = __import__("json").loads(res.get("content", "[]"))
        except ValueError:
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="haveibeenpwned",
                    target=target,
                    summary="HIBP returned non-JSON (truncated content).",
                    source="haveibeenpwned.com",
                    confidence=0.0,
                    raw=res.get("content", "")[:200],
                )
            )
            return
        breaches = data if isinstance(data, list) else data.get("breaches", [])
        if breaches:
            count = sum(b.get("Pwned", 0) for b in breaches)
            names = ", ".join(b.get("Name", "unknown") for b in breaches[:5])
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="haveibeenpwned",
                    target=target,
                    summary=f"HIBP: {len(breaches)} breach(es); total pwned: {count}. Names: {names}",
                    source="haveibeenpwned.com",
                    confidence=cls.CONFIDENCE_BRUTE,
                    value={"breaches": breaches, "total_pwned": count},
                )
            )
        else:
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="haveibeenpwned",
                    target=target,
                    summary="No breaches found in HIBP registry.",
                    source="haveibeenpwned.com",
                    confidence=0.95,
                )
            )

    def _breach_lookup(self, target: str, report: Report) -> None:
        self._hibp_lookup(f"root@{target}", report)
        self._hibp_lookup(f"admin@{target}", report)

    def _cve_lookup(self, cve_id: str, report: Report) -> None:
        res = fetch(f"https://cve.circl.lu/api/cve/{cve_id}")
        if not res.get("ok"):
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="cve",
                    target=cve_id,
                    summary=f"CVE lookup failed ({res.get('error')})",
                    source="cve.circl.lu",
                    confidence=0.0,
                    raw=res.get("error", ""),
                )
            )
            return
        text = res.get("content", "")
        try:
            data = __import__("json").loads(text)
        except ValueError:
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="cve",
                    target=cve_id,
                    summary="CVE API returned non-JSON.",
                    source="cve.circl.lu",
                    confidence=0.0,
                    raw=text[:200],
                )
            )
            return
        cve = data.get("CVE", {})
        descriptions = cve.get("descriptions", [])
        desc = descriptions[0].get("value", "") if descriptions else ""
        report.findings.append(
            Finding(
                category="breach",
                subtype="cve",
                target=cve_id,
                summary=f"CVE {cve_id}: {desc[:200]}",
                source="cve.circl.lu",
                confidence=0.85,
                value={"cve": cve},
                raw=text,
            )
        )

    def _kev_sample(self, report: Report) -> None:
        res = fetch("https://www.cisa.gov/sites/default/files/2024-09/KEV.csv", timeout=(6, 25))
        if not res.get("ok"):
            return
        text = res.get("content", "")
        lines = text.splitlines()
        if len(lines) < 2:
            return
        for line in lines[1:31]:
            parts = [p.strip() for p in line.split(",")]
            if not parts or parts[0] == "Checksum":
                continue
            vuln_id = parts[0]
            report.findings.append(
                Finding(
                    category="breach",
                    subtype="cisa-kev",
                    target="(global catalog)",
                    summary=f"KEV entry: {vuln_id} — {parts[1] if len(parts) > 1 else ''}",
                    source="cisa.gov KEV",
                    confidence=0.9,
                    value={"vuln_id": vuln_id, "summary": parts[1] if len(parts) > 1 else ""},
                )
            )
