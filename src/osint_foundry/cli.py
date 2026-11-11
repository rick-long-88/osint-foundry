"""osint-foundry CLI.

A local OSINT investigation runner that replays the osintpilot-style agent
pipeline (digital footprint, breach intel, public records, web archive,
identity resolution) against a domain, email, name, or handle, reuses the
passive-recon sources from the osint-map toolkit, and emits a sourced,
confidence-scored Markdown/JSON report plus GeoJSON for the local
gods-eye 3D globe.
"""

from __future__ import annotations

import logging

import click

from .model import find
from .pipeline import run_pipeline
from .report import save as save_report
from .spatial import to_geojson_path, to_kml_path
from . import web as web_ui

logger = logging.getLogger("osint-foundry")

_HELP = """osint-foundry -- local OSINT investigation runner
Run: osint <command> [options]
Available commands:
  full             Run the full 6-stage pipeline (default)
  recon            Passive DNS/RDAP/certificate enumeration
  digital-footprint  Email/account look-alike sweep
  breach           Have I Been Pwned check
  public-record    Corporate registry lookup (SEC EDGAR)
  web-archive      Wayback snapshot/CDX lookup
  identity         Identity resolution / correlation
"""


_COMMANDS = {
    "full": "Run the full 6-stage osintpilot-style pipeline",
    "recon": "Passive DNS, RDAP, certificate transparency enumeration",
    "digital-footprint": "Email/account look-alike sweep",
    "breach": "Have I Been Pwned public breach check",
    "public-record": "Corporate registry lookup (SEC EDGAR)",
    "web-archive": "Wayback snapshot/CDX lookup",
    "identity": "Identity resolution / alias correlation",
}


def _emit(f, quiet: bool) -> None:
    if not quiet:
        click.echo(f"  - [{f.category}] {f.summary} (conf {f.confidence:.0%})")


def _cmd_full(target: str, output_dir: str, formats: tuple[str, ...], quiet: bool) -> None:
    report = run_pipeline(target)
    click.echo(f"[osint] target={target} status={report.status} findings={len(report.findings)}")
    for f in report.findings:
        _emit(f, quiet)
    if not quiet:
        for line in find(report, category=None, src=None):
            click.echo(line)
    for fmt in formats:
        if fmt == "md":
            saved = save_report(report, output_dir)
            click.echo(f"[osint] report: {saved['markdown']}")
        elif fmt == "json":
            saved = save_report(report, output_dir)
            click.echo(f"[osint] report: {saved['json']}")
        elif fmt == "geojson":
            geo = to_geojson_path(report, f"{output_dir}{target.replace(' ', '_').replace('/', '_')}.geojson")
            click.echo(f"[osint] geojson: {geo}")
        elif fmt == "kml":
            kml = to_kml_path(report, f"{output_dir}{target.replace(' ', '_').replace('/', '_')}.kml")
            click.echo(f"[osint] kml: {kml}")
    click.echo("[osint] done.")


def _cmd_web_check(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["web-check"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] web-check: {len(report.findings)} finding(s)")


def _cmd_openosint_actors(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["openosint-actors"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] openosint-actors: {len(report.findings)} finding(s)")


def _cmd_recon(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["recon"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] recon: {len(report.findings)} finding(s)")


def _cmd_digital_footprint(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["digital-footprint"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] digital-footprint: {len(report.findings)} finding(s)")


def _cmd_breach(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["breach"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] breach: {len(report.findings)} finding(s)")


def _cmd_public_record(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["public-record"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] public-record: {len(report.findings)} finding(s)")


def _cmd_web_archive(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["web-archive"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] web-archive: {len(report.findings)} finding(s)")


def _cmd_identity(target: str, quiet: bool) -> None:
    report = run_pipeline(target, stages=["identity"])
    for f in report.findings:
        _emit(f, quiet)
    click.echo(f"[osint] identity: {len(report.findings)} finding(s)")


def _help_command(ctx):
    click.echo(_HELP)
    click.echo("Commands:")
    for k, v in _COMMANDS.items():
        click.echo(f"  {k:<20} {v}")


@click.group()
@click.option("--log", "-l", type=click.Choice(["debug", "info", "warning"]),
              default="warning", help="Set logging level (default warning)")
@click.version_option(version="0.1.0", prog_name="osint-foundry")
def osint(log: str) -> None:
    level = getattr(logging, log.upper(), logging.WARNING)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


@osint.command("help")
@click.pass_context
def cmd_help(ctx):
    _help_command(ctx)


@osint.command("full")
@click.argument("target")
@click.option("-o", "--output", "output_dir", default="reports/", show_default=True,
              help="Output directory")
@click.option("-f", "--format", "formats", multiple=True, default=("md",),
              type=click.Choice(["md", "json", "geojson", "kml"]),
              show_default=True, help="Output formats")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_full(target: str, output_dir: str, formats: tuple[str, ...], quiet: bool) -> None:
    _cmd_full(target, output_dir, formats, quiet)


@osint.command("recon")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_recon(target: str, quiet: bool) -> None:
    _cmd_recon(target, quiet)


@osint.command("digital-footprint")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_digital_footprint(target: str, quiet: bool) -> None:
    _cmd_digital_footprint(target, quiet)


@osint.command("breach")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_breach(target: str, quiet: bool) -> None:
    _cmd_breach(target, quiet)


@osint.command("public-record")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_public_record(target: str, quiet: bool) -> None:
    _cmd_public_record(target, quiet)


@osint.command("web-archive")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_web_archive(target: str, quiet: bool) -> None:
    _cmd_web_archive(target, quiet)


@osint.command("identity")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_identity(target: str, quiet: bool) -> None:
    _cmd_identity(target, quiet)


@osint.command("web-check")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_web_check(target: str, quiet: bool) -> None:
    _cmd_web_check(target, quiet)


@osint.command("openosint-actors")
@click.argument("target")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
def cmd_openosint_actors(target: str, quiet: bool) -> None:
    _cmd_openosint_actors(target, quiet)


@osint.command("web")
@click.argument("target")
@click.option("--port", default=8484, show_default=True, help="Port to serve on")
@click.option("--open", "open_browser", is_flag=True, help="Open browser to the viewer")
def cmd_web(target: str, port: int, open_browser: bool) -> None:
    """Serve an interactive HTML report for *target* on localhost."""
    report = run_pipeline(target)
    click.echo(f"[osint] report: {len(report.findings)} findings for {target}")
    click.echo(f"[osint] web UI at http://127.0.0.1:{port}/")
    web_ui.serve_report(report, host="127.0.0.1", port=port, open_browser=open_browser)


def main() -> None:
    osint()


if __name__ == "__main__":
    osint()
