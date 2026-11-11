"""Report export: Markdown + JSON (sourced, confidence-scored) intelligence product."""

from __future__ import annotations

import json
from typing import Any

from .model import Report, now_iso


def to_markdown(report: Report, indent: int = 2) -> str:
    lines: list[str] = []
    lines.append("# OSINT Intelligence Report")
    lines.append("")
    lines.append(f"**Target:** {report.target}")
    lines.append(f"**Status:** {report.status}  ·  **Collectors:** {', '.join(report.collectors) or 'none'}")
    lines.append(f"**Started:** {report.started_at}  ·  **Finished:** {report.finished_at}")
    lines.append("")

    summary = report.summary or {}
    if summary:
        lines.append("## Executive Summary")
        lines.append("")
        for k, v in summary.items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")

    fcount = len(report.findings)
    lines.append(f"## Findings ({fcount})")
    lines.append("")
    if fcount == 0:
        lines.append("_No findings collected. Some sources may have been unreachable or the target is not externally visible._")
        lines.append("")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"### {i}. [{f.category}] {f.summary}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Subtype** | {f.subtype} |")
        lines.append(f"| **Confidence** | {f.confidence:.0%} |")
        lines.append(f"| **Source** | {f.source} |")
        lines.append("")
        if f.value:
            lines.append("#### Structured value")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(f.value, indent=indent, ensure_ascii=False))
            lines.append("```")
            lines.append("")
        if f.raw:
            lines.append("#### Raw text")
            lines.append("")
            lines.append("```text")
            lines.append(f.raw[:1500])
            lines.append("```")
            lines.append("")
    lines.append("")
    return "\n".join(lines)


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def save(report: Report, out_dir: str) -> dict[str, str]:
    """Write Markdown + JSON report files. ``out_dir`` should end with ``/``."""
    import os

    os.makedirs(out_dir, exist_ok=True)
    md = to_markdown(report)
    js = to_json(report)
    md_path = f"{out_dir}report-{report.target.replace(' ', '_').replace('/', '_')}.md"
    js_path = f"{out_dir}report-{report.target.replace(' ', '_').replace('/', '_')}.json"
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(js_path, "w", encoding="utf-8") as fh:
        fh.write(js)
    return {"markdown": md_path, "json": js_path}
