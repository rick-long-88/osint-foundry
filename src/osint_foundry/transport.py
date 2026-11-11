"""Transport helpers: a resilient HTTP session + a result-safe ``fetch``.

Failure on one source must never abort the whole investigation. Every fetch
returns a structured result (``{"ok": True/False, ...}``), mirroring the
osint-map pattern where a source that fails keeps serving its last good data
and is left alone for a while before the next attempt.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "osint-foundry/1.0 (local OSINT investigation; contact: local-defender)",
    "Accept": "application/json,text/html,text/*;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Idempotent collect-and-hold behaviour. A source that fails keeps its last
# good payload and is retried later without aborting the run.
SESSION: requests.Session | None = None


def get_session() -> requests.Session:
    global SESSION
    if SESSION is None:
        s = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.headers.update(DEFAULT_HEADERS)
        SESSION = s
    return SESSION


def fetch(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    timeout: tuple[int, int] = (5, 15),
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """GET a URL and return a structured result. Never raises on network errors."""
    s = session or get_session()
    try:
        resp = s.get(url, params=params, timeout=timeout)
        if resp.status_code == 200:
            return {
                "ok": True,
                "status": resp.status_code,
                "url": resp.url,
                "content": resp.text,
                "headers": {k: v for k, v in resp.headers.items()},
            }
        return {"ok": False, "status": resp.status_code, "url": resp.url, "error": f"HTTP {resp.status_code}"}
    except requests.exceptions.HTTPError as exc:
        return {"ok": False, "url": url, "error": f"HTTP error {exc.response.status_code if exc.response is not None else 'unknown'}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "url": url, "error": "timeout"}
    except requests.exceptions.ConnectionError as exc:
        return {"ok": False, "url": url, "error": f"connection error: {exc.__cause__ or exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "url": url, "error": f"{type(exc).__name__}: {exc}"}
