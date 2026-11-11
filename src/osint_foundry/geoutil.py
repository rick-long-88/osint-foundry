"""GeoJSON export for the local gods-eye 3D globe.

Converts osint-foundry report findings into a FeatureCollection of
GeoJSON features the gods-eye viewer can consume directly.
"""

from __future__ import annotations

import json
from typing import Any

from ..model import Finding, Report


def _point(lon: float, lat: float) -> dict:
    return {"type": "Point", "coordinates": [lon, lat]}


def _bbox(xs, ys) -> list:
    return [min(xs), min(ys), max(xs), max(ys)]


def _prop_chain(props: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if isinstance(props, dict) and k in props:
            return props[k]
    return None


def report_to_geojson(report_dict: dict[str, Any], layer: str = "osint-findings") -> dict:
    """Turn a report JSON object into a GeoJSON FeatureCollection."""
    props = report_dict.get("report", report_dict)
    findings = props.get("findings", []) if isinstance(props, dict) else report_dict.get("findings", [])

    features = []
    for f in findings:
        geom = _feature_geometry(f)
        if geom is None:
            # Non-geospatial finding: still emit a feature with a null shape.
            features.append({
                "type": "Feature",
                "geometry": None,
                "properties": {
                    "category": f.get("category", "ungrouped"),
                    "subtype": f.get("subtype", "unknown"),
                    "confidence": f.get("confidence", 0.0),
                    "summary": f.get("summary", ""),
                    "target": f.get("target", ""),
                },
                "id": f.get("source", f.get("target", "")),
            })
            continue
        features.append({
            "type": "Feature",
            "geometry": geom,
            "properties": {
                "category": f.get("category", "ungrouped"),
                "subtype": f.get("subtype", "unknown"),
                "confidence": f.get("confidence", 0.0),
                "summary": f.get("summary", ""),
                "target": f.get("target", ""),
                "source": f.get("source", ""),
                "raw": f.get("raw", ""),
            },
            "id": f.get("source", f.get("target", "")),
        })

    # Bounding sphere for navigation.
    xs, ys = [], []
    for feat in features:
        geom = feat.get("geometry")
        if isinstance(geom, dict) and geom.get("type") == "Point":
            coords = geom.get("coordinates", [])
            if len(coords) >= 2:
                xs.append(coords[0])
                ys.append(coords[1])

    bbox = _bbox(xs, ys) if xs else None

    return {
        "type": "FeatureCollection",
        "layer": layer,
        "crs": {"type": "name", "properties": {"name": "EPSG:4326"}},
        "bbox": bbox,
        "features": features,
    }


def _feature_geometry(finding: dict[str, Any]) -> dict | None:
    """Return a GeoJSON geometry for a finding, or None if non-geospatial."""
    category = finding.get("category", "")
    value = finding.get("value")

    if category == "recon" and isinstance(value, dict):
        # DNS / IP geolocation
        lat = value.get("latitude")
        lon = value.get("longitude")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            return _point(float(lon), float(lat))

    if category == "recon" and isinstance(value, dict):
        # IP location found via ipwho.is
        lat = value.get("lat")
        lon = value.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            return _point(float(lon), float(lat))

    if isinstance(value, dict):
        lat = value.get("latitude") or value.get("lat")
        lon = value.get("longitude") or value.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            return _point(float(lon), float(lat))

    if isinstance(value, (list, tuple)) and len(value) >= 2:
        # [lat, lon] or [lon, lat] guess by magnitude
        a, b = value[0], value[1]
        if abs(a) <= 90 and abs(b) <= 180:
            # [lat, lon]
            return _point(float(b), float(a))
        elif abs(b) <= 90 and abs(a) <= 180:
            # [lon, lat]
            return _point(float(a), float(b))

    # Default: nothing to place on the globe.
    return None


def geojson_to_file(geojson: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(geojson, fh, indent=2)
