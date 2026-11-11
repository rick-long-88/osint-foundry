"""OpenOSINT actors integration.

Runs the OpenOSINT/OpenOSINT Apify-style recon actors (domain-recon,
username-recon, news-monitor) as a passive recon collector.  The actors are
self-contained Python scripts that run locally (no Apify account needed) and
query public DNS, certificate transparency, social media, and news sources.

Each actor exposes a `run()` function that returns a JSON-serializable dict
with `actors`, `results`, and metadata.  This module wraps them and converts
their output to osint-foundry Finding objects.

External dependencies (must be installed in the osint-foundry venv):
  pip install -r /home/bigdaddy/OpenOSINT/actors/domain-recon/requirements.txt
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .model import Finding, Report

logger = logging.getLogger("osint_foundry.openosint_actors")

# Actor module paths (offer user repos as fallback)
_OPENOSINT_REPO = Path("/home/bigdaddy/OpenOSINT")
_LOCAL_REPO = Path("/home/bigdaddy/osint-foundry/src/osint_foundry/openosint_actors")

# Actor entry points and the Finding types they produce
ACTOR_MAP = {
    "domain-recon": {
        "path": _OPENOSINT_REPO / "actors" / "domain-recon" / "src" / "main.py",
        "description": "Domain passive reconnaissance (crt.sh, DNS, TLS)",
        "findings_kind": "domain",
    },
    "username-recon": {
        "path": _OPENOSINT_REPO / "actors" / "username-recon" / "src" / "main.py",
        "description": "Username / handle resolution across social platforms",
        "findings_kind": "identity",
    },
    "news-monitor": {
        "path": _OPENOSINT_REPO / "actors" / "news-monitor" / "src" / "main.py",
        "description": "News and media monitoring for the target",
        "findings_kind": "media",
    },
}

# Stage-specific confidence thresholds
_STAGE_CONFIDENCE = {
    "domain": 0.8,
    "identity": 0.7,
    "media": 0.6,
}

# Input schema for each actor
ACTOR_INPUT = {
    "domain-recon": {"target": "example.com"},
    "username-recon": {"usernames": ["anonymous"]},
    "news-monitor": {"query": "example.com"},
}


class OpenOsintError(Exception):
    """Raised when an OpenOSINT actor fails to run."""

def _resolve_actor_path(name: str) -> Path:
    """Return the path to an actor script, trying user repo first then local."""
    candidate = ACTOR_MAP[name]["path"]
    if candidate.exists():
        return candidate
    # Fall back to a user-provided repo location
    fallback = Path(f"/home/bigdaddy/{name}-repo")
    if fallback.exists():
        return fallback / "src" / "main.py"
    raise OpenOsintError(f"Actor '{name}' not found at {candidate}")


def _run_actor(name: str, target: str) -> dict[str, Any]:
    """Run a single OpenOSINT actor as a subprocess and return its JSON output.

    The actors are Apify-style actors that run inside the Apify Actor SDK.
    We write the actor input to an ``INPUT.json`` file in the actor's working
    directory, then execute the actor's main.py script directly. The actor then
    stores its output to the local Apify dataset directory, from which we read
    the results.
    """
    actor_path = _resolve_actor_path(name)
    work_dir = actor_path.parent

    # Parse input from the actor map
    actor_input = ACTOR_MAP.get(name, {}).get("default_input", {})
    # Each actor expects a different input schema; write accordingly
    if name == "domain-recon":
        input_obj = {"target": target}
    elif name == "username-recon":
        input_obj = {"usernames": [target]}
    else:  # news-monitor and others
        input_obj = {"query": target}

    # Write the input file expected by Actor.get_input() (default key: INPUT)
    input_file = work_dir / "INPUT.json"
    with open(input_file, "w") as f:
        json.dump(input_obj, f)

    # Run the actor with a minimal environment to avoid PYTHONPATH conflicts
    # with the host Python environment (e.g. Hermes's pydantic installation).
    # Apify SDK requires these env vars for local execution:
    # - APIFY_TOKEN: dummy token for local mode
    # - APIFY_LOCAL_STORAGE_DIR: where to store datasets/KV stores
    storage_dir = work_dir / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)
    (storage_dir / "key_value_stores" / "default").mkdir(parents=True, exist_ok=True)
    (storage_dir / "datasets" / "default").mkdir(parents=True, exist_ok=True)

    # The osint-foundry virtualenv Python contains apify and all actor deps.
    # Use THIS python, not the host python (e.g. Hermes's), to run actors.
    # Find the venv python path relative to this file.
    # Project structure: src/osint_foundry/__init__.py -> project root at ..
    import sysconfig

    project_root = Path(__file__).resolve().parent.parent.parent
    venv_python = project_root / ".venv" / "bin" / "python3.13"

    # Also inherit PATH and set PYTHONPATH so the venv's packages are found
    # The collector environment includes OSINT_MOCK=1 so actors run in
    # local mock mode without making real API calls.
    env = os.environ.copy()
    venv_site_packages = str(project_root / ".venv" / "lib" / "python3.13" / "site-packages")
    env["PYTHONPATH"] = venv_site_packages
    env["OSINT_MOCK"] = "1"
    env["APIFY_IS_AT_HOME"] = "0"
    env["APIFY_TOKEN"] = "test-token"

    logger.info("Running OpenOSINT actor: %s (%s)", name, actor_path)
    logger.info("Python executable: %s", str(venv_python))
    logger.info("PYTHONPATH: %s", env.get("PYTHONPATH", "NOT SET"))
    # Use the osint-foundry venv's python which has apify/apify_client installed
    cmd = [str(venv_python), str(actor_path)]

    result = subprocess.run(
        cmd,
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )

    # Clean up the input file so it doesn't persist between runs
    try:
        input_file.unlink(missing_ok=True)
    except Exception:
        pass

    if result.returncode != 0:
        raise OpenOsintError(
            f"Actor '{name}' failed rc={result.returncode}: {result.stderr[:300]}"
        )

    # The Apify actor SDK stores its output to a dataset file.
    # Look for the most recent output file in the datasets directory.
    dataset_dir = work_dir / "storage" / "datasets" / "default"
    output_files = list(dataset_dir.glob("*.json"))
    if not output_files:
        # Fallback: actor returned JSON on stdout (e.g. mock mode)
        if result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        raise OpenOsintError(
            f"Actor '{name}' produced no output file in {dataset_dir} "
            f"and no stdout output"
        )

    # Read the most recent output file
    output_file = max(output_files, key=lambda p: p.stat().st_mtime)
    try:
        with open(output_file) as f:
            raw = f.read()
        parsed = json.loads(raw)
        # The Apify SDK wraps output in {"output": <actual>}, unwrap it.
        if isinstance(parsed, dict) and "output" in parsed:
            parsed = parsed["output"]
    except Exception:
        parsed = {"stdout": result.stdout, "stderr": result.stderr}

    return parsed


def _parse_domain_recon_output(data: dict[str, Any], target: str) -> list[Finding]:
    """Convert domain-recon actor output to findings."""
    findings = []
    results = data.get("results", data.get("actors", []))
    if not results:
        results = data.get("output", data)

    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                findings.append(
                    Finding(
                        category="openosint-actors",
                        subtype="domain-recon",
                        target=target,
                        summary=f"Domain found: {item.get('domain', item.get('name', item))}",
                        source="OpenOSINT domain-recon",
                        confidence=_STAGE_CONFIDENCE["domain"],
                        value={"item": item},
                    )
                )
    elif isinstance(results, dict):
        findings.append(
            Finding(
                category="openosint-actors",
                subtype="domain-recon",
                target=target,
                summary=f"Domain-recon results: {str(results)[:200]}",
                source="OpenOSINT domain-recon",
                confidence=_STAGE_CONFIDENCE["domain"],
                value={"results": results},
            )
        )

    return findings


def _parse_username_recon_output(data: dict[str, Any], target: str) -> list[Finding]:
    """Convert username-recon actor output to findings."""
    findings = []
    results = data.get("results", data.get("actors", []))
    if not results:
        results = data.get("output", data)
    if isinstance(results, dict):
        for handle, info in results.items():
            findings.append(
                Finding(
                    category="openosint-actors",
                    subtype="username-recon",
                    target=target,
                    summary=f"Handle @{handle} resolved: {str(info)[:120]}",
                    source="OpenOSINT username-recon",
                    confidence=_STAGE_CONFIDENCE["identity"],
                    value={"handle": handle, "info": info},
                )
            )
    elif isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                findings.append(
                    Finding(
                        category="openosint-actors",
                        subtype="username-recon",
                        target=target,
                        summary=f"Identity resolved: {str(item)[:160]}",
                        source="OpenOSINT username-recon",
                        confidence=_STAGE_CONFIDENCE["identity"],
                        value={"item": item},
                    )
                )
    return findings


def _parse_news_monitor_output(data: dict[str, Any], target: str) -> list[Finding]:
    """Convert news-monitor actor output to findings."""
    findings = []
    results = data.get("results", data.get("articles", []))
    if not results:
        results = data.get("output", data)
    if isinstance(results, list):
        for i, article in enumerate(results[:10]):
            if isinstance(article, dict):
                title = article.get("title", article.get("url", str(article)[:120]))
                findings.append(
                    Finding(
                        category="openosint-actors",
                        subtype="news-monitor",
                        target=target,
                        summary=f"Article #{i+1}: {str(title)[:160]}",
                        source="OpenOSINT news-monitor",
                        confidence=_STAGE_CONFIDENCE["media"],
                        value={"article": article},
                    )
                )
    elif isinstance(results, dict):
        findings.append(
            Finding(
                category="openosint-actors",
                subtype="news-monitor",
                target=target,
                summary=f"News results: {str(results)[:200]}",
                source="OpenOSINT news-monitor",
                confidence=_STAGE_CONFIDENCE["media"],
                value={"results": results},
            )
        )
    return findings


def _get_parser(name: str):
    """Return the output parser function for an actor."""
    parsers = {
        "domain-recon": _parse_domain_recon_output,
        "username-recon": _parse_username_recon_output,
        "news-monitor": _parse_news_monitor_output,
    }
    return parsers.get(name, lambda d, t: [])


class OpenOsintActorsCollector:
    """Passive recon via OpenOSINT Apify-style actors."""

    kind = "openosint-actors"
    sources = ["OpenOSINT/OpenOSINT"]

    def __init__(self, repo_path: str | None = None) -> None:
        self.repo_path = Path(repo_path or "/home/bigdaddy/OpenOSINT")
        self._ensure_dependencies()

    def _ensure_dependencies(self) -> None:
        """Ensure actor dependencies are installed."""
        for actor_name in ACTOR_MAP:
            req_file = (
                self.repo_path
                / "actors"
                / actor_name
                / "requirements.txt"
            )
            if req_file.exists():
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file)],
                    capture_output=True,
                )

    def collect(self, target: str, report: Report) -> None:
        """Run the OpenOSINT actors against the target and collect findings."""
        fqdn = str(target).strip().lower().rstrip(".")
        # Also try username/handle lookups
        if "@" in fqdn:
            fqdn = fqdn.split("@")[1]  # email -> handle

        for actor_name in ACTOR_MAP:
            try:
                data = _run_actor(actor_name, fqdn)
                parser = _get_parser(actor_name)
                findings = parser(data, fqdn)
                report.findings.extend(findings)
            except Exception as e:  # noqa: BLE001
                logger.warning("OpenOSINT actor %s failed: %s", actor_name, e)
                report.findings.append(
                    Finding(
                        category="openosint-actors",
                        subtype=actor_name,
                        target=str(fqdn),
                        summary=f"OpenOSINT actor '{actor_name}' failed: {e}",
                        source="OpenOSINT/OpenOSINT",
                        confidence=0.0,
                        value={"error": str(e)},
                    )
                )


def run_openosint(target: str, report: Report | None = None) -> Report:
    """Convenience function mirroring the same pattern as run_recon()."""
    report = report or Report(target=target)
    collector = OpenOsintActorsCollector()
    collector.collect(str(target), report)
    return report
