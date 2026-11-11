"""Web-check integration.

Wraps the web-check (lissy93/web-check) Express 5 full-stack app as a passive
recon collector.  The server exposes a REST API of security checks (DNS, TLS,
WHOIS, subdomains, cookies, trackers, threats, quality, mixed-content, ...),
each at /api/<check>.  This collector starts the server in a background
subprocess, queries the relevant endpoints for the target domain, parses the
JSON responses, and converts them to osint-foundry Finding objects.

External dependencies (must be installed in the osint-foundry venv):
  npm install      # in the web-check repo (lissy93/web-check)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .model import Finding, Report

logger = logging.getLogger("osint-foundry.web-check")

# Endpoint -> (kind, confidence, description).  All known web-check API routes.
# Each endpoint takes a `url` query param (https://<target>/).
WEB_CHECK_ENDPOINTS = {
    # DNS / hosting
    "dns": ("dns", 1.0, "DNS record lookup"),
    "dnssec": ("dnssec", 0.9, "DNSSEC validation status"),
    "dns-server": ("dns_server", 0.9, "DNS server identification"),
    "whois": ("whois", 0.9, "Domain registration data"),
    "subdomains": ("subdomains", 0.7, "Passive subdomain enumeration"),
    "tech-stack": ("tech_stack", 0.5, "Technology fingerprinting"),
    # TLS / HTTPS
    "tls-connection": ("tls_connection", 0.8, "TLS connection details"),
    "tls-labs": ("tls_labs", 0.9, "SSL Labs grade"),
    "hsts": ("hsts", 0.9, "HSTS policy"),
    "headers": ("http_headers", 0.8, "HTTP response headers"),
    # Web security
    "cookies": ("cookies", 0.6, "Cookie security attributes"),
    "robots-txt": ("robots_txt", 0.7, "robots.txt inspection"),
    "security-txt": ("security_txt", 0.7, "security.txt discovery"),
    "mixed-content": ("mixed_content", 0.8, "Mixed content detection"),
    # Threat intelligence
    "threats": ("threats", 0.7, "Threat intelligence / reputation"),
    "breaches": ("breaches", 0.7, "Known data breaches"),
    # Quality / accessibility
    "quality": ("quality", 0.6, "Page quality score"),
    "location": ("location", 0.5, "Physical server location"),
}

# Minimal endpoint set that needs no API keys / third-party auth.
_PUBLIC_ENDPOINTS = {
    "dns",
    "dnssec",
    "dns-server",
    "whois",
    "subdomains",
    "tech-stack",
    "tls-connection",
    "hsts",
    "headers",
    "cookies",
    "robots-txt",
    "security-txt",
    "mixed-content",
    "quality",
    "location",
}

# Endpoints that require a Google Cloud API key (threats, breaches) - skipped by
# default when no GOOGLE_CLOUD_API_KEY is set.
_KEY_REQUIRED_ENDPOINTS = {"threats", "breaches"}


class WebCheckError(Exception):
    """Raised when the web-check server is unavailable or a check fails."""

    pass


def _find_free_port(start: int = 3001, end: int = 3100) -> int:
    """Return the first free TCP port in [start, end]."""
    import socket

    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise WebCheckError(f"No free port found in range {start}-{end}")


def _http_get(url: str, timeout: float = 15.0) -> dict[str, Any]:
    """Perform an HTTP GET and return the parsed JSON response."""
    req = urllib.request.Request(url, headers={"User-Agent": "osint-foundry/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"ok": False, "status": e.code, "body": body, "error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e), "body": ""}


def _is_json(body: str) -> bool:
    if not body:
        return False
    try:
        json.loads(body)
        return True
    except Exception:  # noqa: BLE001
        return False


def _parse_endpoint(endpoint: str, resp: dict[str, Any], target: str) -> list[Finding]:
    """Convert a single web-check endpoint response into Finding objects."""
    findings: list[Finding] = []
    raw_body = resp.get("body", "")
    ok = resp.get("ok", False) and _is_json(raw_body)

    source_url = f"http://127.0.0.1:{_WEB_CHECK_PORT}/api/{endpoint}"
    subtype, confidence, description = WEB_CHECK_ENDPOINTS[endpoint]

    if not ok:
        findings.append(
            Finding(
                category="web-check",
                subtype=subtype,
                target=target,
                summary=f"{description}: request failed (HTTP {resp.get('status')})",
                source=source_url,
                confidence=0.0,
                value={"status": resp.get("status"), "error": raw_body[:200]},
            )
        )
        return findings

    try:
        data = json.loads(raw_body)
    except Exception:  # noqa: BLE001
        findings.append(
            Finding(
                category="web-check",
                subtype=subtype,
                target=target,
                summary=f"{description}: unparseable response",
                source=source_url,
                confidence=0.0,
                value={"raw": raw_body[:500]},
            )
        )
        return findings

    # Extract the meaningful findings from the response.
    # web-check returns { result: ..., data: ..., skipped: ..., error: ... }
    skip_msg = data.get("skipped") or data.get("error")
    if skip_msg:
        findings.append(
            Finding(
                category="web-check",
                subtype=subtype,
                target=target,
                summary=f"{description}: skipped ({skip_msg})",
                source=source_url,
                confidence=0.0,
                value={"skipped": skip_msg},
            )
        )
        return findings

    # The `result` field is an object with per-check results.
    result = data.get("result") or data.get("data") or data

    if isinstance(result, dict):
        for key, val in result.items():
            if isinstance(val, (dict, list)):
                findings.append(
                    Finding(
                        category="web-check",
                        subtype=f"{subtype}:{key}",
                        target=target,
                        summary=f"{description}: {str(val)[:160]}",
                        source=source_url,
                        confidence=confidence,
                        value={"check": key, "result": val},
                    )
                )
            else:
                findings.append(
                    Finding(
                        category="web-check",
                        subtype=subtype,
                        target=target,
                        summary=f"{description}: {key}={str(val)[:120]}",
                        source=source_url,
                        confidence=confidence,
                        value={"check": key, "value": val},
                    )
                )
    elif isinstance(result, list):
        findings.append(
            Finding(
                category="web-check",
                subtype=subtype,
                target=target,
                summary=f"{description}: {len(result)} items returned",
                source=source_url,
                confidence=confidence,
                value={"count": len(result), "sample": str(result[:3])},
            )
        )
    else:
        findings.append(
            Finding(
                category="web-check",
                subtype=subtype,
                target=target,
                summary=f"{description}: {str(result)[:160]}",
                source=source_url,
                confidence=confidence,
                value={"result": result},
            )
        )

    return findings


class WebCheckCollector:
    """Passive web security recon via the web-check Express API."""

    kind = "web-check"
    sources = ["lissy93/web-check"]

    def __init__(self, server_dir: str | None = None, port: int | None = None) -> None:
        self.server_dir = Path(server_dir or "/home/bigdaddy/web-check")
        self.port = port or _find_free_port()
        self._proc: subprocess.Popen | None = None

    def start_server(self) -> None:
        """Start the web-check Express server in a background subprocess."""
        global _WEB_CHECK_PORT
        _WEB_CHECK_PORT = self.port
        if self._proc is not None and self._proc.poll() is None:
            return  # already running
        # Ensure node_modules exist
        npm_path = self.server_dir / "node_modules"
        if not npm_path.exists():
            logger.info("web-check: installing npm dependencies...")
            subprocess.run(
                ["npm", "install"], cwd=self.server_dir, check=False, capture_output=True
            )
        # Start the Express server (server.js) on the chosen port
        env = dict(os.environ)
        env["PORT"] = str(self.port)
        self._proc = subprocess.Popen(
            ["node", "server.js"],
            cwd=self.server_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
        )
        # Wait for the server to accept connections
        base_url = f"http://127.0.0.1:{self.port}"
        for _ in range(40):
            res = _http_get(f"{base_url}/healthz", timeout=1)
            if res.get("ok") or res.get("status") == 200:
                return
            time.sleep(0.5)
        raise WebCheckError(f"web-check server failed to start on port {self.port}")

    def stop_server(self) -> None:
        """Terminate the background server."""
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def collect(self, target: str, report: Report) -> None:
        """Collect web-check findings for the target domain."""
        global _WEB_CHECK_PORT
        _WEB_CHECK_PORT = self.port
        fqdn = str(target).strip().lower().rstrip(".")
        # Only run against hostnames (web-check checks are for domains, not IPs)
        if "://" in fqdn or "/" in fqdn or ":" in fqdn:
            return
        self.start_server()
        try:
            base_url = f"http://127.0.0.1:{self.port}"
            for endpoint in WEB_CHECK_ENDPOINTS:
                # Skip key-required endpoints if no API key
                if endpoint in _KEY_REQUIRED_ENDPOINTS:
                    env_key = "GOOGLE_CLOUD_API_KEY"
                    # (skip — would need key)
                    continue
                url = f"{base_url}/api/{endpoint}?url={urllib.parse.quote(fqdn)}"
                resp = _http_get(url, timeout=20)
                findings = _parse_endpoint(endpoint, resp, fqdn)
                report.findings.extend(findings)
        finally:
            self.stop_server()


# Global port used for server lifecycle
_WEB_CHECK_PORT: int = 3001
