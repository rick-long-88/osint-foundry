"""Pipeline orchestrator: runs the collector stages against a target.

Renders a report, executes the selected stages in sequence, isolates source
failures, then exposes the finished report and (optionally) GeoJSON output
for the local gods-eye globe.
"""

from __future__ import annotations

from ..model import Finding, Report
from .base import Collector


class Pipeline:
    """Run a set of collectors against one target."""

    def __init__(self, stages: list[str] | None = None, shuffle: bool = True) -> None:
        from ..collectors import build_collector_registry, get_stage_order
        self.registry = build_collector_registry()
        if stages:
            self.stages = [s for s in stages if s in self.registry]
        else:
            self.stages = get_stage_order(shuffle)
        self.report = Report(target="")

    def run(self, target: str) -> Report:
        self.report.target = target
        self.report.started_at = now_iso()

        # Collect findings from each stage (fixed order).
        for name in self.stages:
            collector = self.registry[name]
            try:
                collector.collect(target, self.report)
            except Exception as exc:  # isolate any stage
                self.report.findings.append(
                    Finding(
                        category="pipeline",
                        subtype="error",
                        target=target,
                        summary=f"stage '{name}' failed: {exc}",
                        source="osint-foundry pipeline",
                        confidence=0.0,
                        raw=f"stage {name} raised {exc!r}",
                    )
                )

        self.report.finished_at = now_iso()
        self.report.status = "complete" if self.report.findings else "empty"
        self.report.summary = {
            "target_type": self.report.summary.get("target_type", "unknown"),
            "stage_count": len(self.stages),
            "finding_count": len(self.report.findings),
            "high_confidence": len([f for f in self.report.findings if f.confidence >= 0.8]),
        }
        return self.report

    @property
    def findings(self) -> list[Finding]:
        return self.report.findings


def now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def run_pipeline(target: str, stages: list[str] | None = None, shuffle: bool = True) -> Report:
    """Convenience: run a pipeline and return a finished report."""
    pipe = Pipeline(stages=stages, shuffle=shuffle)
    return pipe.run(target)
