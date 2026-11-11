"""Identity resolution stage.

Correlates the digital footprint, breach, records and web-archive findings
into a single identity graph: aliases, email/domain correlation, address
and relative cross-reference, and a resolved identity summary.
"""

from __future__ import annotations

from ..collectors.digital_footprint import DigitalFootprintCollector
from ..model import Finding, Report
from .base import Collector

# Confidence weight carried through identity resolution.
_RESOLUTION_WEIGHT = 0.8


class IdentityResolutionCollector(Collector):
    """Merge candidate identities the recon stages surfaced into one profile."""

    kind = "identity"
    sources = [
        "email/domain correlation",
        "alias resolution",
        "address & relative cross-ref",
    ]

    def collect(self, target: str, report: Report) -> None:
        # Recompute the digital-footprint base set so identity resolution
        # does not depend on a partially-run report.
        self._fragile_footprint(target, report)

    # ---- identity resolution -------------------------------------------

    def _fragile_footprint(self, target: str, report: Report) -> None:
        """Re-run only the fragment-level recon needed for identity resolution."""
        # For an email, resolve the alias; for a domain, look for related
        # mail aliases and registrant identity.
        if "@" in target:
            self._email_identity(target, report)
        else:
            self._domain_identity(target, report)

    def _email_identity(self, target: str, report: Report) -> None:
        mailbox, _, domain = target.partition("@")
        aliases = [mailbox, f"admin@{domain}", f"root@{domain}"]
        records = []
        for a in aliases:
            for f in report.findings:
                if f.target == a:
                    records.append(f)
        # Dedupe and merge: if we saw a breach finding for the mailbox, note it.
        breach_hits = [f for f in records if f.category == "breach"]
        if breach_hits:
            total = sum(f.value.get("total_pwned", 0) if isinstance(f.value, dict) else 0 for f in breach_hits)
            report.findings.append(
                Finding(
                    category="identity",
                    subtype="email-correlation",
                    target=target,
                    summary=f"Email alias {mailbox} correlated; breaches found: {len(breach_hits)} (total pwned {total}).",
                    source="identity resolution",
                    confidence=_RESOLUTION_WEIGHT,
                    value={"aliases": aliases, "breach_hits": len(breach_hits), "total_pwned": total},
                )
            )
        else:
            report.findings.append(
                Finding(
                    category="identity",
                    subtype="email-correlation",
                    target=target,
                    summary=f"Email alias {mailbox} correlated with domain {domain}; no breach activity.",
                    source="identity resolution",
                    confidence=_RESOLUTION_WEIGHT,
                    value={"aliases": aliases},
                )
            )

    def _domain_identity(self, target: str, report: Report) -> None:
        # Aggregate per‑IP / per‑crawler identity signals.
        seen_ips = {f.value.get("ip") for f in report.findings if isinstance(f.value, dict) and f.value.get("ip")}
        domains = {f.target for f in report.findings if f.category == "recon"}
        if seen_ips:
            report.findings.append(
                Finding(
                    category="identity",
                    subtype="ip-correlation",
                    target=target,
                    summary=f"Payloads reached {len(seen_ips)} unique IP(s); related domains: {', '.join(sorted(d for d in domains if d != target)) or 'none'}",
                    source="identity resolution",
                    confidence=_RESOLUTION_WEIGHT,
                    value={"ips": sorted(seen_ips), "domains": list(domains)},
                )
            )
        else:
            report.findings.append(
                Finding(
                    category="identity",
                    subtype="ip-correlation",
                    target=target,
                    summary="No IP-level signals available; cannot resolve identity.",
                    source="identity resolution",
                    confidence=0.5,
                )
            )
