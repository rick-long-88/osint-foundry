"""Spatial layer builder for the local gods-eye 3D globe.

The globe renders points on a sphere, so we emit GeoJSON Point features from
findings that carry coordinates (IP geolocation lookups, plus any manual
``location`` value). We intentionally expose the exact latitude/longitude and
the source finding, so a human can sanity-check a point's provenance before it
is plotted.
"""

from __future__ import annotations

import json
from typing import Any

from .model import Finding, Report

# A couple of globally-known reference points (neutral tooling, not analysis).
_REF = {
    "1.1.1.1": (51.2536, -130.6747, "Cloudflare resolver, Canada"),
    "1.1.1.100": (37.751, -97.0374, "Cloudflare NAT, USA"),
}


def _extract_latlon(value: dict[str, Any]) -> tuple[float, float] | None:
    """Pull lat/lon out of findings produced by ipwho.is / ipinfo."""
    if not isinstance(value, dict):
        return None
    # ipwho.is payload
    if value.get("latitude") is not None:
        try:
            return float(value["latitude"]), float(value["longitude"])
        except (TypeError, ValueError):
            return None
    # ipinfo payload
    if value.get("loc"):
        parts = str(value["loc"]).split(",")
        if len(parts) == 2:
            try:
                return float(parts[0]), float(parts[1])
            except ValueError:
                return None
    return None


def _collect_vectors(report: Report) -> list[dict[str, Any]]:
    features: list[dict[str, Any]] = []
    seen: set[tuple[float, float]] = set()
    for f in report.findings:
        # Collect lat/lon from any finding that carries coordinates,
        # not just the 'recon' category. Web-check and openosint-actors
        # findings may include geo data in their structured values.
        coord = _extract_latlon(f.value)
        if coord is None:
            continue
        if coord in seen:
            continue
        seen.add(coord)
        # Prefer the ipfound in the value; fall back to the finding target.
        entry = f.value.get("ip") or f.target
        note = f.value.get("city") or entry
        features.append(
            {
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [coord[1], coord[0]]},
                "properties": {
                    "label": f"{note} ({f.target})",
                    "source": f.source,
                    "confidence": f.confidence,
                    "id": f"{f.category}:{f.subtype}",
                    "note": note,
                    "category": f.category,
                },
            }
        )
    return features


def to_geojson(report: Report, name: str = "osint-points") -> dict[str, Any]:
    return {
        "type": "FeatureCollection",
        "name": name,
        "features": _collect_vectors(report),
    }


def to_geojson_path(report: Report, out_path: str) -> str:
    import os

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(to_geojson(report), fh, indent=2)
    return out_path


def to_kml(report: Report, name: str = "osint-points") -> str:
    feat = _collect_vectors(report)
    lines = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<kml xmlns=\"http://www.opengis.net/kml/2.2\">"]
    lines.append("<Document><name>osint-points</name>")
    for f in feat:
        p = f["properties"]
        lines.append(
            f"<Placemark><name>{p['label']}</name><description>{p['source']} | conf {p['confidence']:.0%}</description>"
            f"<Point><coordinates>{f['geometry']['coordinates'][0]},{f['geometry']['coordinates'][1]},0</coordinates></Point></Placemark>"
        )
    lines.append("</Document></kml>")
    return "\n".join(lines)


def to_kml_path(report: Report, out_path: str) -> str:
    import os

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(to_kml(report))
    return out_path


def globe_url(report: Report | None = None, local_globe: str = "file:///home/bigdaddy/gods-eye-view") -> str:
    """Return a hint for opening the local 3D globe at the report's findings."""
    if report is None:
        return f"open {local_globe} --geojson"
    return f"open {local_globe} --geojson <(cat {report.target.replace(' ', '_').replace('/', '_')}.geojson)"
