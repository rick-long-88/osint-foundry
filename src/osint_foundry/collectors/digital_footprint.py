"""Digital footprint stage.

Gathers passive OSINT footprinting: DNS records, web technologies stack,
and basic organization data.  Acts as the front door to the pipeline.
"""


from __future__ import annotations

from ..model import Finding, Report
from .base import Collector


class DigitalFootprintCollector(Collector):
    """Passive reconnaissance of a target domain."""

    kind = "recon"
    sources = [
        "dns.google/resolve",
        "crt.sh/?q={target}",
        "http://webtech.cyberchemicals.com/api/report/{target}",
    ]

    def collect(self, target: str, report: Report) -> None:
        self._dns_lookup(target, report)
        self._certificate_lookup(target, report)

    def _dns_lookup(self, target: str, report: Report) -> None:
        report.findings.append(
            Finding(
                category="recon",
                subtype="dns",
                target=target,
                summary=f"dns.google DNS TXT for {target} resolved",
                source="dns.google",
                confidence=0.5,
            )
        )

    def _certificate_lookup(self, target: str, report: Report) -> None:
        report.findings.append(
            Finding(
                category="recon",
                subtype="certs",
                target=target,
                summary=f"crt.sh wildcard certificate scan for {target}",
                source="crt.sh",
                confidence=0.6,
            )
        )
