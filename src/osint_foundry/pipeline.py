"""Pipeline: the six-stage osintpilot-style investigation.

Stages (mapped 1:1 to osintpilot's AI agents):
  1. Digital footprint mapping  -> `destinations`
  2. Breach intelligence        -> `breach`
  3. Public records             -> `public_registry`
  4. Web & browser automation   -> `web_archive`
  5. Identity resolution        -> `identity`
  6. Structured report export   -> `report`
"""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup
from dataclasses import dataclass, field

from .model import Finding, Report
from .recon import run_recon
from .sources import clean_text, SOURCE_ROUTES
from .transport import fetch

# Domains this tooling knows are embedded services; also searched with their
# parent domain when an exact hit is empty.
_SUSPECT_SUFFIXES = (
    ".github.io", ".pages.dev", ".netlify.app", ".vercel.app",
    "-app.github.dev", "-web.github.dev",
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Username look-alikes we sweep for a name (first initial + full first name).
_USERNAMES = ("", "_", "-", ".", "first", "last", "login", "user")

_DOMAIN_SUFFIXES = (".com", ".org", ".net", ".io", ".co", ".gov", ".edu", ".biz")


def _looks_like_name(target: str) -> bool:
    """Heuristic: is the target a human name/handle rather than a bare domain?"""
    t = target.strip()
    if not t:
        return False
    if " " in t:  # full name with a space
        return True
    # Username-like (no dot, no known TLD) reads like a person/handle.
    if "." not in t and not t.lower().endswith(_DOMAIN_SUFFIXES):
        return True
    return False


@dataclass
class Destination:
    platform: str
    handle: str
    url: str
    note: str = ""


# Numeric label for the "confidence" column rendered in Markdown.
_CONFIDENCE_ORDER = {
    1.0: 1,
    0.9: 2,
    0.8: 3,
    0.7: 4,
    0.6: 5,
    0.5: 6,
    0.4: 7,
    0.3: 8,
    0.2: 9,
    0.1: 10,
    0.0: 11,
}


# --------------------------------------------------------------------------- #
# Stage 1: Digital footprint mapping (account lookup sweep)
# --------------------------------------------------------------------------- #
def _sweep_email(email: str, report: Report) -> None:
    if not _EMAIL_RE.match(email):
        return
    domain = email.rsplit("@", 1)[-1].lower()
    report.findings.append(
        Finding(
            category="digital-footprint",
            subtype="email",
            target=email,
            summary=f"Target email resolves to domain {domain}; we sweep account look-alikes + breach intel.",
            source="hibp / ddg (heuristics)",
            confidence=0.5,
            value={"email": email, "domain": domain},
        )
    )


def _sweep_lookalikes(handle: str, report: Report, domain: str | None = None) -> None:
    """Generate likely email-account look-alikes from a name/handle.

    This is a heuristic digital-footprint collector: real account discovery is
    done by crawlers (covered in the web-archive stage). We emit *candidate*
    addresses only, clearly marked low-confidence.
    """
    base = handle.strip().lower().lstrip("@")
    if not base:
        return
    variants = {base}
    for sep in ("", "_", "-", "."):
        if base:
            variants.add(f"{base[0]}{sep}{base}")
            variants.add(f"{base[0]}{sep}{base[0]}")
    for v in sorted(v for v in variants if v):
        cand = v.lstrip("@")
        # Build an email-style account address at the given domain.
        if domain:
            cand = f"@{cand}.{domain}"
        if _EMAIL_RE.match(cand):
            report.findings.append(
                Finding(
                    category="digital-footprint",
                    subtype="lookalike_account",
                    target=cand,
                    summary=f"Account look-alike {cand} of {handle}.",
                    source="heuristics (local)",
                    confidence=0.2,
                    value={"handle": cand},
                )
            )


# Domain name suffixes that are themselves hostnames (not target domains),
# so we do not treat them as the resolution target for a different domain.
_SUSPECT_SUFFIXES = (".github.io", ".pages.dev", ".netlify.app", ".vercel.app",
                     "-app.github.dev", "-web.github.dev")


# --------------------------------------------------------------------------- #
# Stage 2: Breach intelligence
# --------------------------------------------------------------------------- #
def _breach_lookup(email: str, report: Report) -> None:
    res = fetch(f"https://haveibeenpwned.com/api/v3/breaches?account={email}")
    if not res.get("ok"):
        report.findings.append(
            Finding(
                category="breach",
                subtype="hibp_unavailable",
                target=email,
                summary=f"Have I Been Pwned returned {res.get('error') or 'no data'} for {email}.",
                source="haveibeenpwned.com",
                confidence=0.0,
                value={"error": res.get("error")},
            )
        )
        return
    try:
        breaches = __import__("json").loads(res.get("content", "[]"))
    except Exception:  # noqa: BLE001
        breaches = []
    if not breaches:
        report.findings.append(
            Finding(
                category="breach",
                subtype="hibp_clean",
                target=email,
                summary=f"Email {email} does not appear in the Have I Been Pwned breach data set.",
                source="haveibeenpwned.com",
                confidence=0.9,
                value={"account": email},
            )
        )
        return
    for b in breaches:
        report.findings.append(
            Finding(
                category="breach",
                subtype="hibp_breach",
                target=email,
                summary=f"Email exposed in breach '{b.get('Name','?')}' ({b.get('BreachDate','?')}) with {b.get('PwnCount','?')} records.",
                source=f"haveibeenpwned.com/api/v3/breaches?account={email}",
                confidence=0.85,
                value={"breach": b},
            )
        )


# --------------------------------------------------------------------------- #
# Stage 3: Public records (corporate registries)
# --------------------------------------------------------------------------- #
def _corporate_registry(company: str, report: Report) -> None:
    # SEC EDGAR (free, no key): 10-K filings for a company name.
    res = fetch(f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={company}&type=10-K&count=10")
    if res.get("ok"):
        soup = BeautifulSoup(res.get("content", ""), "lxml")
        rows = soup.select("table.table-sizeable tbody tr")
        if rows:
            for r in rows[:6]:
                cols = [clean_text(td.get_text(" ", strip=True)) for td in r.find_all("td")]
                if cols:
                    report.findings.append(
                        Finding(
                            category="public-record",
                            subtype="sec_edgar_10k",
                            target=company,
                            summary=f"SEC EDGAR 10-K filing: {cols[1]} ({cols[2]})",
                            source="sec.gov (EDGAR)",
                            confidence=0.9,
                            value={"company": cols[1], "form": cols[2], "date": cols[3]},
                        )
                    )
            return
    report.findings.append(
        Finding(
            category="public-record",
            subtype="corporate_lookup_unavailable",
            target=company,
            summary=f"Corporate registry lookup for {company} unavailable ({res.get('error') or 'no filings found'}).",
            source="sec.gov (EDGAR)",
            confidence=0.0,
            value={"company": company},
        )
    )


# --------------------------------------------------------------------------- #
# Stage 4: Web & browser automation (archived + index lookups)
# --------------------------------------------------------------------------- #
def _web_archive(domain: str, report: Report) -> None:
    # Availability snapshot.
    res = fetch(f"https://archive.org/wayback/available?url={domain}")
    if res.get("ok"):
        try:
            snap = __import__("json").loads(res.get("content", "{}"))
        except Exception:  # noqa: BLE001
            snap = {}
        if snap.get("archived_snapshots") and snap["archived_snapshots"].get("closest"):
            s = snap["archived_snapshots"]["closest"]
            report.findings.append(
                Finding(
                    category="web-archive",
                    subtype="wayback_snapshot",
                    target=domain,
                    summary=f"Wayback closest snapshot: {s.get('timestamp')} | {s.get('url')}",
                    source="archive.org/wayback/available",
                    confidence=0.9,
                    value={"timestamp": s.get("timestamp"), "url": s.get("url")},
                )
            )
    # Full CDX listing (first 20 captures).
    res = fetch(SOURCE_ROUTES["cdx"][0].format(fqdn=domain))
    if res.get("ok"):
        try:
            rows = __import__("json").loads(res.get("content", "[]"))
        except Exception:  # noqa: BLE001
            rows = []
        for r in rows[1:6]:  # skip header
            if len(r) >= 4:
                report.findings.append(
                    Finding(
                        category="web-archive",
                        subtype="wayback_cdx",
                        target=domain,
                        summary=f"Wayback capture: {r[1]} | {r[2]} | {r[3]}",
                        source="web.archive.org/cdx",
                        confidence=0.7,
                        value={"timestamp": r[1], "mimetype": r[2], "length": r[3]},
                    )
                )


def _ddg_query(q: str, report: Report, max_hits: int = 4) -> None:
    res = fetch(SOURCE_ROUTES["ddg"][0].format(q=q))
    if not res.get("ok"):
        return
    soup = BeautifulSoup(res.get("content", ""), "html.parser")
    for link in soup.select("a.result__a")[:max_hits]:
        report.findings.append(
            Finding(
                category="digital-footprint",
                subtype="search_result",
                target=q,
                summary=f"Search result: {link.get_text(' ', strip=True)} | {link.get('href','')}",
                source="html.duckduckgo.com",
                confidence=0.4,
                value={"query": q, "url": link.get("href", "")},
            )
        )


# --------------------------------------------------------------------------- #
# Stage 5: Identity resolution (entity correlation)
# --------------------------------------------------------------------------- #
@dataclass
class _Profile:
    aliases: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    confidence: float = 0.0


def _resolve(aliases: list[str], report: Report) -> None:
    """Correlate name + email + domain into a single entity profile."""
    seen: set[str] = set()
    net = _Profile()
    for a in aliases:
        a = (a or "").strip().lower()
        if a and a not in seen:
            seen.add(a)
            net.aliases.append(a)
            net.sources.append("local-resolution")
    # Merge by source / category if duplicates exist (simple dedupe).
    net.confidence = round(0.6 if any("@" in a for a in net.aliases) else 0.5, 3)
    if net.aliases:
        report.findings.append(
            Finding(
                category="identity",
                subtype="resolution",
                target="mixed",
                summary=f"Resolved {len(net.aliases)} alias(es) for the subject.",
                source="local identity resolution",
                confidence=net.confidence,
                value={"aliases": net.aliases, "confidence": net.confidence},
            )
        )


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
def run_pipeline(target: str, stages: list[str] | None = None) -> Report:
    """Run the osintpilot-style pipeline for *target* (domain/email/handle/name)."""
    target = str(target).strip()
    report = Report(target=target)

    # Decide which stages the user (or default) wants.
    if stages is None:
        stages = ["recon", "digital-footprint", "breach", "public-record",
                  "web-archive", "identity", "web-check", "openosint-actors"]

    report.collectors = list(stages)

    if "recon" in stages:
        report = run_recon(target, report)

    # Extract components to run per-stage; email / domain / name resolution.
    domain = None
    email = None
    name = target

    if _EMAIL_RE.match(target):
        email = target
        domain = target.rsplit("@", 1)[-1].lower()
    elif str(target).endswith((".com", ".org", ".net", ".io", ".co", ".gov",
                                ".edu", ".biz")) or ("." in target and not _is_ip(target)):
        domain = target.lower().rstrip(".")

    # 1. digital footprint
    if "digital-footprint" in stages:
        if email:
            _sweep_email(email, report)
        elif domain:
            _sweep_email(f"contact@{domain}", report)
        # Account look-alikes are only generated for a name/handle (not a bare domain).
        if domain and _looks_like_name(target):
            _sweep_lookalikes(target, report, domain)

    # 2. breach
    if "breach" in stages and email and _EMAIL_RE.match(email):
        _breach_lookup(email, report)

    # 3. public records
    if "public-record" in stages and domain:
        _corporate_registry(target, report)

    # 4. web archive
    if "web-archive" in stages and domain:
        _web_archive(domain, report)

    # 5. identity resolution
    if "identity" in stages and domain:
        _resolve([target, email or f"admin@{domain}", f"info@{domain}"], report)

    # 6. web security reconnaissance (web-check)
    if "web-check" in stages and domain:
        _run_web_check(domain, report)

    # 7. passive actor-based recon (OpenOSINT)
    if "openosint-actors" in stages:
        _run_openosint_actors(target, report)

    report.finished_at = now_iso()
    report.status = "partial" if report.findings else "completed"
    return report


# Re-export helpers used by CLI.
def now_iso():
    from .model import now_iso as _n
    return _n()


# --------------------------------------------------------------------------- #
# Stage 6: Web security reconnaissance (web-check)
# --------------------------------------------------------------------------- #
def _run_web_check(domain: str, report: Report) -> None:
    """Run web-check passive recon for a domain."""
    from osint_foundry.web_check import WebCheckCollector

    collector = WebCheckCollector()
    try:
        collector.collect(domain, report)
    except Exception as e:  # noqa: BLE001
        logger.warning("web-check stage failed for %s: %s", domain, e)
        report.findings.append(
            Finding(
                category="web-check",
                subtype="unavailable",
                target=domain,
                summary=f"web-check stage failed: {e}",
                source="lissy93/web-check",
                confidence=0.0,
                value={"error": str(e)},
            )
        )


# --------------------------------------------------------------------------- #
# Stage 7: Passive actor-based recon (OpenOSINT)
# --------------------------------------------------------------------------- #
def _run_openosint_actors(target: str, report: Report) -> None:
    """Run OpenOSINT actor-based recon for a target."""
    from osint_foundry.openosint_actors import OpenOsintActorsCollector

    collector = OpenOsintActorsCollector()
    try:
        collector.collect(target, report)
    except Exception as e:  # noqa: BLE001
        logger.warning("OpenOSINT actors stage failed for %s: %s", target, e)
        report.findings.append(
            Finding(
                category="openosint-actors",
                subtype="unavailable",
                target=target,
                summary=f"OpenOSINT actors stage failed: {e}",
                source="OpenOSINT/OpenOSINT",
                confidence=0.0,
                value={"error": str(e)},
            )
        )
