"""Public data-source registry.

Sources mirror the hermes-osint-map passive-recon toolkit (dns, rdap, tls/
headers, certificate transparency, CISA KEV, IP, GitHub, MAC) plus the
free web-archives and registry endpoints that the osintpilot platform uses
for its public-records and web-automation stages. They are all public,
account-free endpoints; if one is unreachable it is skipped and served from
the last good payload.
"""

from __future__ import annotations

import re

# Public-host patterns. Recon only ever targets these public resolvers; the
# osint-map guard refuses private/loopback/addresses on redirect, and we keep
# the same discipline: no internal addresses are ever sent outbound.
SOURCE_HOSTS = (
    "dns.google",
    "rdap.org",
    "crt.sh",
    "cve.circl.lu",
    "cisa.gov",
    "ipwho.is",
    "ipinfo.io",
    "api.github.com",
    "api.macvendors.com",
    "haveibeenpwned.com",
    "archive.org",
    "web.archive.org",
    "sec.gov",
    "opencorporates.com",
    "duckduckgo.com",
    "www.sec.gov",
)

# Route patterns: kind -> (base URL template, parser hint)
# Templates use {target} for the domain or ip. IPv6 is wrapped in [ ].
SOURCE_ROUTES: dict[str, tuple[str, str]] = {
    "dns": ("https://dns.google/resolve?name={fqdn}", "dns"),
    "rdap": ("https://rdap.org/domain/{fqdn}", "rdap"),
    "crt_sh": ("https://crt.sh/?q=%25.{fqdn}&output=json", "ct"),
    "cve": ("https://cve.circl.lu/api/cve/{id}", "cve"),
    "ipwhois": ("https://ipwho.is/{ip}", "ipwhois"),
    "ipinfo": ("https://ipinfo.io/{ip}/json", "ipinfo"),
    "github_user": ("https://api.github.com/users/{login}", "github"),
    "github_org": ("https://api.github.com/orgs/{login}", "github"),
    "macvendors": ("https://api.macvendors.com/{mac}", "mac"),
    "hibp": ("https://haveibeenpwned.com/api/v3/breaches?account={email}", "hibp"),
    "wayback": ("https://archive.org/wayback/available?url={fqdn}", "wayback"),
    "cdx": ("https://web.archive.org/cdx/search/cdx?url={fqdn}&output=json&limit=20", "cdx"),
    "edgar": ("https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company={company}&type=10-K&count=10", "edgar"),
    "opencorporates": ("https://api.opencorporates.com/v0.4/companies/search?name={company}", "opencorporates"),
    "ddg": ("https://html.duckduckgo.com/html/?q={q}", "ddg"),

# Public passive-intelligence endpoints (add-ons, free + account-free).
    "headers": ("https://api.hackertarget.com/headers?q={fqdn}", "headers"),
    "tech": ("https://api.hackertarget.com/tech?q={fqdn}", "tech"),
    "subdomains": ("https://api.hackertarget.com/subdomains?q={fqdn}", "subdomains"),
    "dnsrec": ("https://api.hackertarget.com/dnsrec?q={fqdn}", "dnsrec"),
}

# Human names never resolve to DNS; this is a conservative label set. In
# practice "recon" (subdomains/CT) is the only DNS-adjacent look a domain gets.
AUDIENCE_TAGS = (
    "digital-footprint",
    "breach",
    "public-record",
    "web-archive",
    "identity",
)

# Regexes for sanitising free-text payloads (strip ANSI, control chars).
_RX_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RX_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def clean_text(text: str) -> str:
    """De-flavour free text for safe inclusion in reports."""
    if not text:
        return ""
    text = _RX_ANSI.sub("", text)
    text = _RX_CONTROL.sub(" ", text)
    return " ".join(text.split())


def is_public_host(host: str) -> bool:
    return any(host.endswith(p) for p in SOURCE_HOSTS)
