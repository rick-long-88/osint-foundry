"""Passive recon module.

Reuses the hermes-osint-map passive-recon source list plus additional
public passive-intelligence endpoints (security headers, tech-stack
fingerprinting, DNS record types).

Added recon sources:
  * Security headers (HSTS, CSP, X-Frame-Options, ...) + HTML meta tags
  * Web tech-stack fingerprinting (Wappalyzer-style from HTML)
  * DNS: SMIMEA, TLSA, OPENPGPKEY, SSHFP record types
  * Passive DNS enumeration (crt.sh + Wayback CDX)
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable

import dns.resolver
from bs4 import BeautifulSoup

from .model import Finding, Report
from .sources import SOURCE_ROUTES, clean_text
from .transport import fetch

# Config matched from the osint-map recon toolkit (hostname/key-less).
RESOLVER = dns.resolver.Resolver()
RESOLVER.timeout = 5
RESOLVER.lifetime = 8
RESOLVER.nameservers = ["8.8.8.8", "1.1.1.1"]

_RR_TYPES = {
    "A": dns.rdatatype.A,
    "AAAA": dns.rdatatype.AAAA,
    "MX": dns.rdatatype.MX,
    "TXT": dns.rdatatype.TXT,
    "NS": dns.rdatatype.NS,
    "CNAME": dns.rdatatype.CNAME,
    "SOA": dns.rdatatype.SOA,
    "SSHFP": dns.rdatatype.SSHFP,
    "TLSA": dns.rdatatype.TLSA,
    "SMIMEA": dns.rdatatype.SMIMEA,
    "OPENPGPKEY": dns.rdatatype.OPENPGPKEY,
}

# Short labels for the report.
_CNAME_HINTS = {
    "www", "mail", "ns1", "ns2", "ns3", "ns4", "dev", "api", "cdn", "vpn",
    "test", "stage", "staging", "beta", "demo", "shop", "blog", "web", "ftp",
}

import re  # noqa: E402


def _dns_lookup(fqdn: str, rrtype: str) -> list[str] | None:
    try:
        answers = RESOLVER.resolve(fqdn, _RR_TYPES[rrtype])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return None
    return [a.to_text(omit_final_dot=True) for a in answers]


def _dns_txt(fqdn: str) -> list[str] | None:
    try:
        answers = RESOLVER.resolve(fqdn, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return None
    return [clean_text(a.strings[0].decode("utf-8", errors="replace")) for a in answers]


def _rdap(fqdn: str) -> str:
    """RDAP registration lookup (RFC 7483)."""
    res = fetch(f"https://rdap.org/domain/{fqdn}")
    if not res.get("ok"):
        return f"RDAP lookup for {fqdn} failed ({res.get('error')})"
    return clean_text(res.get("content", ""))[:1200]


def _crt_sh(fqdn: str) -> list[str]:
    res = fetch(f"https://crt.sh/?q=%25.{fqdn}&output=json")
    if not res.get("ok"):
        return []
    try:
        rows = __import__("json").loads(res.get("content", "[]"))
    except Exception:  # noqa: BLE001
        return []
    outs: list[str] = []
    seen = set()
    for r in rows:
        name = (r.get("name_value") or "").lower().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            outs.append(name)
        for sub in (r.get("dns_name") or "").lower().split():
            sub = sub.rstrip(".")
            if sub and sub not in seen:
                seen.add(sub)
                outs.append(sub)
    return outs


def _cve(cve_id: str) -> str:
    res = fetch(f"https://cve.circl.lu/api/cve/{cve_id}")
    if not res.get("ok"):
        return f"CVE {cve_id} lookup failed ({res.get('error')})"
    return clean_text(res.get("content", ""))[:900]


def _cisa_kev() -> list[str]:
    """Fetch the CISA Known Exploited Vulnerabilities catalog header row CVE IDs."""
    res = fetch("https://www.cisa.gov/sites/default/files/2024-09/KEV.csv", timeout=(6, 25))
    if not res.get("ok"):
        return []
    text = res.get("content", "")
    return [line.split(",")[1] for line in text.splitlines()[1:70] if line and not line.startswith("Checksum")]


def _ipwhois(ip: str) -> str:
    res = fetch(f"https://ipwho.is/{ip}")
    if not res.get("ok"):
        return f"ipwho.is for {ip} failed ({res.get('error')})"
    return clean_text(res.get("content", ""))[:900]


def _mac_vendor(mac: str) -> str:
    res = fetch(f"https://api.macvendors.com/{mac}", timeout=(4, 12))
    if not res.get("ok"):
        return f"MAC {mac} vendor lookup failed"
    return clean_text(res.get("content", ""))[:200]


def _github_user(login: str) -> str:
    res = fetch(f"https://api.github.com/users/{login}")
    if not res.get("ok"):
        return f"GitHub user {login} lookup failed"
    return clean_text(res.get("content", ""))[:700]


def _github_org(login: str) -> str:
    res = fetch(f"https://api.github.com/orgs/{login}")
    if not res.get("ok"):
        return f"GitHub org {login} lookup failed"
    return clean_text(res.get("content", ""))[:700]


def _looks_like_handle(s: str) -> bool:
    if not s or len(s) < 2 or len(s) > 39:
        return False
    return s.isalnum() and not s.startswith("_")


def _is_domain(s: str) -> bool:
    """Rough public-domain guard: FQDN-ish, not an IP, not a bare name."""
    t = s.strip().lower().rstrip(".")
    if not t:
        return False
    if _is_ip(t):
        return False
    if t.count(".") < 1:
        return False
    # Disallow IP-literal-looking strings and leading dots/hyphens.
    if t.startswith((".", "-", "_")) or t.endswith((".", "-", "_")):
        return False
    return True


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Added recon collectors
# --------------------------------------------------------------------------- #


def _collect_security_headers(fqdn: str, report: Report) -> None:
    """Fetch the homepage and extract security-relevant HTTP headers + meta tags."""
    res = fetch(f"https://{fqdn}/", timeout=(6, 20))
    if not res.get("ok"):
        report.findings.append(
            Finding(
                category="recon",
                subtype="security_headers",
                target=fqdn,
                summary=f"Homepage headers fetch failed ({res.get('error') or 'no data'}).",
                source="https://" + fqdn,
                confidence=0.0,
                value={"error": res.get("error")},
            )
        )
        return
    headers = res.get("headers", {})
    hsts = headers.get("strict-transport-security", "")
    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")
    xcto = headers.get("x-content-type-options", "")
    # CSP can also be declared via <meta http-equiv="Content-Security-Policy">.
    soup = BeautifulSoup(res.get("content", ""), "html.parser")
    meta_csp = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})
    if meta_csp and not csp:
        csp = clean_text(meta_csp.get("content", ""))

    found = []
    for label, val in (("Strict-Transport-Security", hsts), ("Content-Security-Policy", csp),
                       ("X-Frame-Options", xfo), ("X-Content-Type-Options", xcto)):
        if val:
            found.append(f"{label}: {val[:160]}")
    if not found:
        found.append("No security headers detected.")

    report.findings.append(
        Finding(
            category="recon",
            subtype="security_headers",
            target=fqdn,
            summary="; ".join(found),
            source=f"https://{fqdn}/",
            confidence=0.7,
            value={"headers": {k: v for k, v in headers.items() if k.lower().startswith(("strict-transport", "content-security", "x-frame", "x-content"))}},
        )
    )


def _collect_html_fingerprint(fqdn: str, report: Report) -> None:
    """Parse title, meta description, canonical + detect frameworks from HTML."""
    res = fetch(f"https://{fqdn}/", timeout=(6, 20))
    if not res.get("ok"):
        report.findings.append(
            Finding(
                category="recon",
                subtype="html_fingerprint",
                target=fqdn,
                summary="Homepage HTML fetch failed.",
                source="https://" + fqdn,
                confidence=0.0,
                value={"error": res.get("error")},
            )
        )
        return
    soup = BeautifulSoup(res.get("content", ""), "html.parser")
    title = clean_text(soup.title.get_text()) if soup.title else ""
    meta_desc = ""
    for m in soup.find_all("meta"):
        c = m.get("content", "").strip()
        if m.get("name", "").lower() == "description" and c:
            meta_desc = c
        if m.get("name", "").lower() == "keywords" and c:
            meta_desc += f" | keywords: {c}"
    canonical = ""
    for m in soup.find_all("link", rel=lambda r: r and "canonical" in (r or [])):
        canonical = clean_text(m.get("href", ""))
        break
    og = ""
    for m in soup.find_all("meta", attrs={"property": lambda p: p and p.startswith("og:")}):
        og += f"| {clean_text(m.get('property', ''))}: {clean_text(m.get('content', ''))[:120]}"

    tech: list[str] = []
    body = soup.find("body")
    wp_markup = bool(body and ("wp-content" in str(body) or "wordpress" in str(body).lower()))
    if "wp-content" in res.get("content", "") or wp_markup:
        tech.append("WordPress")
    if "cdata" in str(soup) or "cms" in str(soup).lower():
        pass
    # Heuristic markers
    if "babel" in str(soup) or "webpack" in str(soup):
        tech.append("Webpack/Babel")
    if "next.js" in str(soup).lower():
        tech.append("Next.js")
    if "angular" in str(soup).lower():
        tech.append("Angular")
    if "react" in str(soup).lower() and "create-element" in str(soup):
        tech.append("React")
    if "jquery" in str(soup):
        tech.append("jQuery")
    if "bootstrap" in str(soup).lower():
        tech.append("Bootstrap")
    if "tailwind" in str(soup).lower():
        tech.append("Tailwind")

    findings = []
    if title:
        findings.append(f"title: {title[:100]}")
    if meta_desc:
        findings.append(f"meta description: {meta_desc[:120]}")
    if canonical:
        findings.append(f"canonical: {canonical[:100]}")
    if og:
        findings.append(f"og tags: {og[:160]}")
    if tech:
        findings.append(f"tech stack: {', '.join(tech)}")

    if not findings:
        findings.append("No fingerprintable HTML metadata.")
    report.findings.append(
        Finding(
            category="recon",
            subtype="html_fingerprint",
            target=fqdn,
            summary="; ".join(findings),
            source="https://" + fqdn,
            confidence=0.6,
            value={"title": title, "meta_description": meta_desc, "canonical": canonical, "og": og, "tech": tech},
        )
    )


def _collect_dns_extras(fqdn: str, report: Report) -> None:
    """SMIMEA, TLSA, OPENPGPKEY, SSHFP record types."""
    for rrtype, label in (("SMIMEA", "SMIMEA record"), ("TLSA", "TLSA record"),
                          ("OPENPGPKEY", "OPENPGPKEY record"), ("SSHFP", "SSHFP record")):
        vals = _dns_lookup(fqdn, rrtype)
        if vals:
            report.findings.append(
                Finding(
                    category="recon",
                    subtype=f"dns:{label}",
                    target=fqdn,
                    summary=f"{rrtype.upper()} records: {', '.join(vals[:6])}{' +more' if len(vals) > 6 else ''}",
                    source="dns.google / dnspython",
                    confidence=1.0,
                    value={"type": rrtype, "values": vals},
                )
            )


def _collect_route_addons(fqdn: str, report: Report) -> None:
    """Public internet-wide / passive-intel lookup add-ons (free endpoints)."""
    for kind in ("headers", "tech", "subdomains", "dnsrec"):
        route = SOURCE_ROUTES.get(kind)
        if not route:
            continue
        res = fetch(route[0].format(fqdn=fqdn))
        if not res.get("ok"):
            continue
        content = res.get("content", "")
        if kind == "headers":
            items = [l for l in content.splitlines() if ":" in l]
            report.findings.append(
                Finding(
                    category="recon",
                    subtype="passivetls_headers",
                    target=fqdn,
                    summary="; ".join(items[:12]),
                    source=route[0],
                    confidence=0.5,
                    value={"raw": content[:800]},
                )
            )
        elif kind == "tech":
            text = clean_text(content)
            if text:
                report.findings.append(
                    Finding(
                        category="recon",
                        subtype="tech_fingerprint",
                        target=fqdn,
                        summary=f"Tech: {text[:160]}",
                        source=route[0],
                        confidence=0.4,
                        value={"raw": text[:600]},
                    )
                )
        elif kind == "subdomains":
            lines = [l for l in content.splitlines() if l.strip()]
            if lines:
                report.findings.append(
                    Finding(
                        category="recon",
                        subtype="passive_subdomains",
                        target=fqdn,
                        summary=f"Subdomains (passive): {', '.join(lines[:20])}{' +more' if len(lines) > 20 else ''}",
                        source=route[0],
                        confidence=0.6,
                        value={"subdomains": lines[:20]},
                    )
                )
        elif kind == "dnsrec":
            lines = [l for l in content.splitlines() if l.strip()]
            if lines:
                report.findings.append(
                    Finding(
                        category="recon",
                        subtype="dns_records",
                        target=fqdn,
                        summary=f"DNS records (passive): {', '.join(lines[:14])}{' +more' if len(lines) > 14 else ''}",
                        source=route[0],
                        confidence=0.5,
                        value={"records": lines[:14]},
                    )
                )


def run_recon(target: str, report: Report | None = None) -> Report:
    """Collect passive-recon findings for a target (domain, hostname, IP, or email)."""
    report = report or Report(target=target)
    fqdn = str(target).strip().lower().rstrip(".")

    # Public-resolver discipline: only DNS/URL/IP targets are looked up
    # outbound. Email and CWE/CISA identifiers are handled by other modules.
    if not _is_domain(fqdn) and not _is_ip(fqdn):
        return report

    for kind, (url, parser) in SOURCE_ROUTES.items():
        if kind == "dns":
            _collect_dns(fqdn, url, report)
        elif kind == "rdap":
            _collect_rdap(fqdn, url, report)
        elif kind == "crt_sh":
            _collect_crt_sh(fqdn, url, report)
        elif kind == "cve":
            continue  # CVE lookups are keyed by ID, surfaced elsewhere
        elif kind == "cisa_kev":
            continue  # long catalog surfaced via cve lookup + kbreach later
        elif kind == "ipwhois":
            _collect_ipwhois(fqdn, url, report)
        elif kind == "ipinfo":
            _collect_ipinfo(fqdn, url, report)
        elif kind == "github_user":
            _collect_github_user(fqdn, url, report)
        elif kind == "github_org":
            _collect_github_org(fqdn, url, report)
        elif kind == "macvendors":
            continue  # MAC lookups keyed by a MAC address, not the target
        elif kind in ("headers", "tech", "subdomains", "dnsrec"):
            _collect_route_addons(fqdn, report)

    # Collect the extra DNS record types always (cheap, public).
    _collect_dns_extras(fqdn, report)
    # Collect the HTML/security-header fingerpinters on the homepage.
    _collect_security_headers(fqdn, report)
    _collect_html_fingerprint(fqdn, report)

    return report


# --------------------------------------------------------------------------- #
# Original osint-map collectors (kept for parity)
# --------------------------------------------------------------------------- #


def _collect_dns(fqdn: str, url: str, report: Report) -> None:
    for rrtype, label in (("A", "A record"), ("AAAA", "AAAA record"), ("TXT", "TXT record"),
                          ("MX", "MX record"), ("NS", "NS record")):
        if rrtype == "AAAA" and ":" in fqdn:
            vals = _dns_lookup(fqdn, "AAAA")
        else:
            vals = _dns_lookup(fqdn, rrtype)
        if vals:
            report.findings.append(
                Finding(
                    category="recon",
                    subtype=f"dns:{label}",
                    target=fqdn,
                    summary=f"{rrtype.upper()} records: {', '.join(vals[:6])}{' +more' if len(vals) > 6 else ''}",
                    source="dns.google / dnspython",
                    confidence=1.0,
                    value={"type": rrtype, "values": vals},
                )
            )


def _collect_rdap(fqdn: str, url: str, report: Report) -> None:
    text = _rdap(fqdn)
    report.findings.append(
        Finding(
            category="recon",
            subtype="rdap",
            target=fqdn,
            summary=f"RDAP registration lookup (truncated): {text[:160]}",
            source="rdap.org",
            confidence=1.0,
            raw=text,
            value={"rdap": text},
        )
    )


def _collect_crt_sh(fqdn: str, url: str, report: Report) -> None:
    subs = _crt_sh(fqdn)
    if subs:
        report.findings.append(
            Finding(
                category="recon",
                subtype="certificate_transparency",
                target=fqdn,
                summary=f"Certificate Transparency certificates (subdomains): {','.join(subs[:15])}{' +more' if len(subs) > 15 else ''}",
                source="crt.sh",
                confidence=1.0,
                value={"subdomains": subs},
            )
        )


def _collect_ipwhois(fqdn: str, url: str, report: Report) -> None:
    ip = _resolve_first(fqdn)
    if not ip:
        return
    text = _ipwhois(ip)
    report.findings.append(
        Finding(
            category="recon",
            subtype="ipwhois",
            target=fqdn,
            summary=f"IP geolocation/ASN: {text[:140]}",
            source="ipwho.is",
            confidence=0.8,
            raw=text,
            value={"ip": ip},
        )
    )


def _collect_ipinfo(fqdn: str, url: str, report: Report) -> None:
    ip = _resolve_first(fqdn)
    if not ip:
        return
    res = fetch(f"https://ipinfo.io/{ip}/json")
    if not res.get("ok"):
        return
    data = __import__("json").loads(res.get("content", "{}"))
    if data.get("org") or data.get("city"):
        report.findings.append(
            Finding(
                category="recon",
                subtype="ipinfo",
                target=fqdn,
                summary=f"IP geolocation: {data.get('city','?')}, {data.get('country','?')} | ASN {data.get('org','?')}",
                source="ipinfo.io",
                confidence=0.8,
                value=data,
            )
        )


def _collect_github_user(fqdn: str, url: str, report: Report) -> None:
    # Only look up GitHub when the target itself looks like a handle.
    if not _looks_like_handle(fqdn):
        return
    text = _github_user(fqdn)
    report.findings.append(
        Finding(
            category="recon",
            subtype="github_user",
            target=fqdn,
            summary=f"GitHub user/profile (truncated): {text[:120]}",
            source="api.github.com",
            confidence=0.8,
            raw=text,
            value={"github": text},
        )
    )


def _collect_github_org(fqdn: str, url: str, report: Report) -> None:
    if not _looks_like_handle(fqdn):
        return
    res = fetch(f"https://api.github.com/orgs/{fqdn}")
    if not res.get("ok"):
        return
    data = __import__("json").loads(res.get("content", "{}"))
    if data.get("name"):
        report.findings.append(
            Finding(
                category="recon",
                subtype="github_org",
                target=fqdn,
                summary=f"GitHub organisation: {data.get('name','?')} (public members {data.get('public_members_count','?')})",
                source="api.github.com",
                confidence=0.8,
                value=data,
            )
        )


def _resolve_first(fqdn: str) -> str | None:
    try:
        return RESOLVER.resolve(fqdn, "A").rrset[0].to_text(omit_final_dot=True)
    except Exception:  # noqa: BLE001
        return None
