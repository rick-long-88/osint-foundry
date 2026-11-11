"""Web UI: serve an OSINT report as an interactive HTML page.

Renders the report's findings in a table and plots any GeoJSON coordinates
on a Leaflet map (OpenStreetMap tiles, no API key). Also exposes the raw
JSON/GeoJSON so downstream tooling (e.g. the local gods-eye 3D globe) can
consume it directly.

Usage:
    osint web example.com
    osint web example.com --port 8484 --open
"""

from __future__ import annotations

import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from ..model import Report
from ..spatial import to_geojson, to_kml

# Neon-red-on-black cyberpunk dashboard theme.
# Replacement for the old light-themed CSS and Batman-staging layout.
_HTML = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSINT Report — $target</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root {
    --bg: #0a0a0f;
    --bg2: #111118;
    --bg3: #1a1a24;
    --fg: #e8e8f0;
    --muted: #8888a0;
    --accent: #ff0055;
    --accent2: #ff3366;
    --accent-glow: #ff1a4a;
    --border: #2a2a3a;
    --card: #111118;
    --globe: #ff0055;
    --globe-glow: #ff3366;
    --red-soft: #ff2a4a;
    --red-bright: #ff4d7a;
    --green: #00ff66;
    --green-glow: #44ff88;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Arial, sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
  }
  /* Neon glow helper */
  .glow {
    text-shadow: 0 0 8px var(--accent-glow), 0 0 16px var(--accent);
  }
  .glow2 {
    text-shadow: 0 0 6px var(--accent2), 0 0 12px var(--accent2);
  }
  header {
    padding: 24px 32px;
    background: linear-gradient(180deg, var(--bg2), var(--bg));
    border-bottom: 1px solid var(--border);
    position: relative;
    overflow: hidden;
  }
  header::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
      45deg,
      transparent,
      transparent 10px,
      var(--accent) 10px,
      var(--accent) 11px
    );
    opacity: 0.04;
    pointer-events: none;
  }
  header .inner {
    max-width: 1400px;
    margin: 0 auto;
    position: relative;
    z-index: 1;
  }
  h1 {
    margin: 0 0 4px;
    font-size: 32px;
    font-weight: 900;
    letter-spacing: -0.03em;
    color: var(--fg);
  }
  h1 .logo {
    color: var(--accent);
    -webkit-text-stroke: 1px var(--accent);
  }
  .sub {
    color: var(--muted);
    font-size: 14px;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    padding: 20px 32px;
    max-width: 1400px;
    margin: 0 auto;
  }
  @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px;
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.6;
  }
  .card h2 {
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin: 0 0 16px;
    font-weight: 700;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 14px;
    margin-bottom: 20px;
  }
  .stat {
    background: var(--bg2);
    border-radius: 8px;
    padding: 14px 16px;
    text-align: center;
    border: 1px solid var(--border);
  }
  .stat .num {
    font-size: 32px;
    font-weight: 900;
    color: var(--accent);
    line-height: 1.1;
  }
  .stat .label {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-top: 4px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th, td {
    text-align: left;
    padding: 11px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  th {
    color: var(--muted);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    background: var(--bg2);
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,0,85,0.04); }
  .cat {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    border: 1px solid var(--border);
  }
  .cat-recon { background: rgba(255,0,85,0.15); color: var(--accent); border-color: rgba(255,0,85,0.4); }
  .cat-web-check { background: rgba(255,51,102,0.12); color: var(--accent2); border-color: rgba(255,51,102,0.3); }
  .cat-openosint-actors { background: rgba(255,51,102,0.12); color: var(--accent2); border-color: rgba(255,51,102,0.3); }
  .cat-digital-footprint { background: rgba(0,255,102,0.1); color: var(--green); border-color: rgba(0,255,102,0.3); }
  .cat-breach { background: rgba(255,42,74,0.15); color: var(--red-soft); border-color: rgba(255,42,74,0.4); }
  .cat-public-record { background: rgba(160,82,255,0.12); color: #b080ff; border-color: rgba(160,82,255,0.3); }
  .cat-web-archive { background: rgba(0,255,119,0.1); color: #2ee6a0; border-color: rgba(0,255,119,0.3); }
  .cat-identity { background: rgba(255,42,74,0.12); color: var(--red-soft); border-color: rgba(255,42,74,0.3); }
  .conf {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .conf-100 { background: rgba(0,255,102,0.2); color: var(--green); }
  .conf-90 { background: rgba(255,51,102,0.2); color: var(--accent2); }
  .conf-80 { background: rgba(255,51,102,0.15); color: var(--accent); }
  .conf-70 { background: rgba(255,85,0,0.2); color: #ff8833; }
  .conf-60 { background: rgba(255,85,0,0.15); color: #ff8833; }
  .conf-50 { background: rgba(255,51,102,0.12); color: var(--accent2); }
  .conf-0 { background: var(--border); color: var(--muted); }
  .src-column {
    font-size: 11px;
    color: var(--muted);
    font-family: ui-monospace, monospace;
    word-break: break-all;
    max-width: 220px;
  }
  .leaflet-wrap {
    height: 360px;
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    position: relative;
    background: var(--bg2);
  }
  .leaflet-wrap::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse at center, rgba(255,0,85,0.08), transparent 70%);
    pointer-events: none;
  }
  .map-toggle {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
  }
  .map-toggle button {
    padding: 8px 16px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--fg);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .map-toggle button.active {
    background: rgba(255,0,85,0.2);
    border-color: var(--accent);
    color: var(--accent);
  }
  .finding-detail {
    display: none;
    margin-top: 10px;
    padding: 14px;
    background: var(--bg2);
    border-left: 3px solid var(--accent);
    border-radius: 0 8px 8px 0;
    animation: slideIn 0.3s ease;
  }
  .finding-detail.visible {
    display: block;
  }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .detail-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .detail-value {
    font-size: 12px;
    color: var(--fg);
    word-break: break-all;
  }
  .confidence-bar {
    height: 6px;
    border-radius: 3px;
    background: var(--bg2);
    overflow: hidden;
    margin-top: 6px;
  }
  .confidence-bar .fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease;
  }
  .filter-hint {
    font-size: 11px;
    color: var(--muted);
    margin-top: 8px;
  }
  .god-eye-toggle {
    display: flex;
    gap: 8px;
    margin-bottom: 12px;
    align-items: center;
  }
  .god-eye-toggle button {
    padding: 6px 14px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--fg);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .god-eye-toggle button.active {
    background: rgba(255,0,85,0.2);
    border-color: var(--accent);
    color: var(--accent);
  }
  .god-eye-link {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 18px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: #fff;
    text-decoration: none;
    border-radius: 8px;
    font-weight: 600;
    font-size: 14px;
    transition: all 0.3s;
    box-shadow: 0 0 20px rgba(255,0,85,0.3);
    border: 1px solid rgba(255,0,85,0.5);
  }
  .god-eye-link:hover {
    transform: translateY(-2px);
    box-shadow: 0 0 30px rgba(255,0,85,0.5);
  }
  .god-eye-link .icon {
    font-size: 18px;
  }
  .god-eye-note {
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
  }

  @media (max-width: 720px) {
    .grid { grid-template-columns: 1fr; }
    .leaflet-wrap { height: 260px; }
  }
  .foot {
    padding: 18px 32px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    max-width: 1400px;
    margin: 0 auto;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code {
    background: var(--bg2);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--accent);
  }
  .footer-note {
    margin-top: 8px;
    font-size: 11px;
    color: var(--muted);
  }

  .search-box {
    width: 100%;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--fg);
    font-size: 14px;
  }
  .btn {
    padding: 8px 14px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg2);
    color: var(--fg);
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn:hover {
    background: rgba(255,0,85,0.1);
    border-color: var(--accent);
  }
  .btn.active {
    background: rgba(255,0,85,0.2);
    border-color: var(--accent);
    color: var(--accent);
  }
  .btn-category {
    padding: 6px 12px;
    font-size: 11px;
  }
  .btn-category.active {
    background: rgba(255,0,85,0.2);
    border-color: var(--accent);
    color: var(--accent);
  }
</style>
</head>
<body>
<header>
  <div class="inner">
    <h1><span class="logo glow">OSINT</span> Report — $target</h1>
    <div class="sub">$count findings across $status · collected $started</div>
  </div>
</header>
<div class="grid">
  <div class="card">
    <h2>Findings by Category</h2>
    <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:14px">
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        <button onclick="toggleCategory('all')" class="btn btn-category active">All ($entries)</button>
        $cat_buttons
      </div>
      <div style="margin-left:auto">
        <span class="filter-hint">Search:</span>
        <input id="search-input" class="search-box" placeholder="Search findings..." oninput="filterFindings()">
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="num" id="filter-count">$count</div><div class="label">Visible</div></div>
      <div class="stat"><div class="num">$count</div><div class="label">Total</div></div>
      <div class="stat"><div class="num">$confidence_avg%</div><div class="label">Avg Confidence</div></div>
    </div>
    <div id="findings-table">
      <table>
        <thead>
          <tr><th>#</th><th>Category</th><th>Summary</th><th>Conf</th><th>Source</th></tr>
        </thead>
        <tbody id="findings-body">
          $end_groups
        </tbody>
      </table>
      <div id="filter-hint" class="filter-hint"></div>
    </div>
  </div>
  <div class="card">
    <h2>Map & Globe</h2>
    <div class="god-eye-toggle">
      <button onclick="toggleView('map')" class="active">2D Map</button>
      <button onclick="toggleView('globe')">3D Globe</button>
    </div>
    <div id="map-view">
      <div class="leaflet-wrap" id="map"></div>
    </div>
    <div id="globe-view" style="display:none">
      <div style="text-align:center;padding:40px;background:var(--card);border:1px solid var(--border);border-radius:12px">
        <div style="font-size:32px;margin-bottom:12px">🌍</div>
        <div style="font-size:14px;color:var(--muted)">God's Eye 3D Globe</div>
        <div class="god-eye-note">Open the full 3D globe in a new tab:</div>
        <a href="https://gods-eye-view.app/" target="_blank" class="god-eye-link">
          <span class="icon">☀</span> Open God's Eye View
        </a>
      </div>
    </div>
    <div style="margin-top:12px">
      <div id="globe-layer-controls" style="display:none;text-align:center;padding:16px;background:var(--card);border:1px solid var(--border);border-radius:12px">
        <div style="color:var(--muted);font-size:12px;margin-bottom:12px">Load findings onto 3D globe</div>
        <button onclick="loadGlobeLayer()" class="btn" style="padding:10px 24px">
          📡 Load Findings
        </button>
      </div>
    </div>
  </div>
</div>
<script>
  (function() {
    var report = $geo_json;
    var findings = [];
    var currentFilter = '';
    var currentCategory = '';

    // Build findings array from GeoJSON
    if (report && report.features) {
      report.features.forEach(function(f) {
        findings.push({
          category: f.properties.category || 'unknown',
          subtype: f.properties.subtype || 'unknown',
          target: f.properties.target || '',
          summary: f.properties.summary || 'No data',
          source: f.properties.source || '',
          confidence: f.properties.confidence || 0,
          raw: f.properties.raw || '',
          id: f.properties.id || ''
        });
      });
    }

    // Get all unique categories sorted
    var categories = [];
    var cats_seen = {};
    findings.forEach(function(f) {
      if (!cats_seen[f.category]) {
        cats_seen[f.category] = true;
        categories.push(f.category);
      }
    });
    categories.sort();

    var map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(map);

    var markersLayer = L.geoJSON(report, {
      pointToLayer: function(feature, latlng) {
        return L.circleMarker(latlng, {
          radius: 8,
          fillColor: '$globe',
          color: '#000',
          weight: 2,
          fillOpacity: 0.85
        });
      },
      onEachFeature: function(feature, layer) {
        var label = feature.properties && feature.properties.summary
          ? feature.properties.summary.replace(/<[^>]+>/g, '')
          : 'No data';
        var popupContent = '<strong style="color:#ff0055">' + label + '</strong><br>' +
          '<span style="color:#8888a0;font-size:12px">' +
          (feature.properties && feature.properties.source ? feature.properties.source : '') + '</span>';
        layer.bindPopup(popupContent);
      }
    }).addTo(map);

    // Filter buttons
    var filterBtnContainer = document.getElementById('category-filters');
    if (filterBtnContainer && categories.length) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-category active';
      btn.textContent = 'All (' + categories.length + ')';
      btn.dataset.category = 'all';
      btn.addEventListener('click', function() {
        document.querySelectorAll('.btn-category').forEach(function(b) { b.classList.remove('active'); });
        this.classList.add('active');
        currentCategory = 'all';
        filterFindings();
      });
      filterBtnContainer.appendChild(btn);

      categories.forEach(function(cat) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-category';
        btn.textContent = cat.replace(/-/g, ' ') + ' (' + (findings.filter(function(f) { return f.category === cat; }).length) + ')';
        btn.dataset.category = cat;
        btn.addEventListener('click', function() {
          document.querySelectorAll('.btn-category').forEach(function(b) { b.classList.remove('active'); });
          this.classList.add('active');
          currentCategory = cat;
          filterFindings();
        });
        filterBtnContainer.appendChild(btn);
      });
    }

    // Search input
    var searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', function() {
        currentFilter = this.value.toLowerCase();
        filterFindings();
      });
    }

    function filterFindings() {
      var filter = currentFilter;
      var category = currentCategory;

      var filtered = findings.filter(function(f) {
        var matchesCategory = category === 'all' || f.category === category;
        var matchesSearch = !filter || f.summary.toLowerCase().includes(filter) || f.subtype.toLowerCase().includes(filter) || f.source.toLowerCase().includes(filter);
        return matchesCategory && matchesSearch;
      });

      // Update table
      var tableBody = document.getElementById('findings-body');
      if (tableBody) {
        var visibleCount = filtered.length;
        document.getElementById('filter-count').textContent = visibleCount;
        if (filtered.length === 0) {
          tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#8888a0">No findings match your filters</td></tr>';
        } else {
          filtered.forEach(function(f, index) {
            var confClass = 'conf conf-' + Math.round(f.confidence * 10);
            tableBody.innerHTML += '<tr>' +
              '<td style="color:var(--muted)">' + (index + 1) + '</td>' +
              '<td style="font-family:ui-monospace,monospace;font-size:11px">[' + f.category + ']</td>' +
              '<td>' + f.summary + '</td>' +
              '<td style="text-align:center"><span class="' + confClass + '">' + Math.round(f.confidence * 100) + '%</span></td>' +
              '<td style="font-size:11px">' + f.source + '</td>' +
            '</tr>';
          });
        }
      }

      // Update map markers
      markersLayer.clearLayers();
      findings.forEach(function(f) {
        var matchesCategory = category === 'all' || f.category === category;
        var matchesSearch = !filter || f.summary.toLowerCase().includes(filter) || f.subtype.toLowerCase().includes(filter) || f.source.toLowerCase().includes(filter);
        if (matchesCategory && matchesSearch) {
          var coords = f.lat && f.lon ? [f.lat, f.lon] : [0, 0];
          var marker = L.circleMarker(coords, {
            radius: 8,
            fillColor: '$globe',
            color: '#000',
            weight: 2,
            fillOpacity: 0.85
          }).bindPopup('<strong style="color:#ff0055">' + f.summary + '</strong><br>' +
            '<span style="color:#8888a0;font-size:12px">' + f.source + '</span>');
          markersLayer.addLayer(marker);
        }
      });
    }

    // Exports section
    var jsonUrl = '$json_url';
    var geoUrl = '$geo_url';
    var kmlUrl = '$kml_url';

    document.getElementById('json-link').onclick = function(e) {
      e.preventDefault();
      window.open(jsonUrl, '_blank');
      return false;
    };
    document.getElementById('geo-link').onclick = function(e) {
      e.preventDefault();
      window.open(geoUrl, '_blank');
      return false;
    };
    document.getElementById('kml-link').onclick = function(e) {
      e.preventDefault();
      window.open(kmlUrl, '_blank');
      return false;
    };

    // Auto-filter on load
    if (searchInput) searchInput.value = '';
    filterFindings();
  })();
</script>

<div class="label">Categories</div>
    </div>
    <div class="stat"><div class="num">$count</div><div class="label">Total Findings</div></div>
    <div class="stat"><div class="num">11</div><div class="label">Sources</div></div>
    <div class="stat"><div class="num">8</div><div class="label">Stages</div></div>
  </div>
  <table>
    <tr><th>Category</th><th>Findings</th></tr>
    $end_groups
  </table>
  </div>
  <div class="card">
    <h2>Map</h2>
    <div class="leaflet-wrap" id="map"></div>
  </div>
</div>
<div class="foot">
  Exports: <a id="json-link" href="$json_url">JSON</a> · <a id="geo-link" href="$geo_url">GeoJSON</a> · <a id="kml-link" href="$kml_url">KML</a><br>
  <span class="footer-note">Generated $started · Target: $target</span>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
  (function() {
    var report = $geo_json;
    var map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(map);
    if (report && report.features && report.features.length) {
      L.geoJSON(report, {
        pointToLayer: function(feature, latlng) {
          return L.circleMarker(latlng, {
            radius: 8,
            fillColor: '$globe',
            color: '#000',
            weight: 2,
            fillOpacity: 0.85
          });
        },
        onEachFeature: function(feature, layer) {
          var label = feature.properties && feature.properties.summary
            ? feature.properties.summary.replace(/<[^>]+>/g, '')
            : 'No data';
          layer.bindPopup('<strong style="color:#ff0055">' + label + '</strong><br><span style="color:#8888a0;font-size:12px">' + (feature.properties && feature.properties.source ? feature.properties.source : '') + '</span>');
        }
      }).addTo(map);
    }
  })();
</script>
</body>
</html>
""")




def _render_groups(report: Report) -> str:
    """Render the category summary rows for the dashboard."""
    counts = {}
    for f in report.findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    rows = []
    for cat in sorted(counts.keys()):
        cls = f"cat-{cat.replace('-', '-')}"
        rows.append(f"<tr><td class='cat {cls}'>{cat}</td><td style='text-align:center'>{counts[cat]}</td></tr>")
    return "\n".join(rows)


def _render_rows(report: Report) -> str:
    rows = []
    for i, f in enumerate(report.findings, 1):
        rows.append(
            f"<tr><td style='color:var(--muted)'>{i}</td>"
            f"<td style='font-family:ui-monospace,monospace;font-size:11px'>[{f.category}]</td>"
            f"<td>{f.summary}</td>"
            f"<td style='text-align:center'>{f.confidence:.0%}</td>"
            f"<td style='font-size:11px'>{f.source}</td></tr>"
        )
    return "\n".join(rows)



class _Handler(BaseHTTPRequestHandler):
    report: Report | None = None
    geo_file: str = "report.geojson"
    kml_file: str = "report.kml"
    json_file: str = "report.json"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/" and self.report:
            body = build_ui_html(self.report).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/report.json" and self.report:
            body = json.dumps(self.report.to_dict()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/report.geojson":
            try:
                with open(self.geo_file, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/geojson")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/report.kml":
            try:
                with open(self.kml_file, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                body = b"<kml/>"
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.google-earth.kml+xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def serve_report(report: Report, host: str = "127.0.0.1", port: int = 8484,
                 open_browser: bool = False, geo_path: str = "report.geojson",
                 kml_path: str = "report.kml", json_path: str = "report.json"):
    """Serve the report on 127.0.0.1:PORT, and optionally open a browser."""
    _prepare_exports(report, geo_path, kml_path, json_path)
    handler = _Handler
    handler.report = report
    handler.geo_file = geo_path
    handler.kml_file = kml_path
    handler.json_file = json_path
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    if open_browser:
        webbrowser.open(url)
    print(f"[web-ui] Serving OSINT report at {url}")
    print(f"[web-ui] Exports: report.json, report.geojson, report.kml")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web-ui] stopped.")
        server.server_close()


def fast_serve(report: Report, host="127.0.0.1", port=8484, open_browser=False):
    """One-shot: write exports and open the UI (no HTTP server loop)."""
    from pathlib import Path

    from ..spatial import to_geojson, to_kml

    _prepare_exports(report, "report.geojson", "report.kml", "report.json")
    if open_browser:
        import webbrowser

        webbrowser.open(f"file://{Path.cwd()/'report.html'}")
        print(f"[web-ui] Exports written to report.json, report.geojson, report.kml")
        print(f"[web-ui] Open: file://{Path.cwd()/'report.html'}")


def _prepare_exports(report: Report, geo_path: str, kml_path: str, json_path: str):
    """Write report artifacts to disk for the UI server and CLI.

    Pre-writes the static exports (JSON, GeoJSON, KML) so the HTTP server
    can serve them with no filesystem lookup at request time.
    """
    import json as _json
    from pathlib import Path

    from ..model import Report
    from ..spatial import to_geojson, to_kml
    from .ui import build_ui_html

    # Write to the current working directory (where the web server runs)
    root = Path.cwd()
    geo_full = root / geo_path
    kml_full = root / kml_path
    json_full = root / json_path

    geo_full.parent.mkdir(parents=True, exist_ok=True)
    # GeoJSON
    _json.dump(to_geojson(report), geo_full.open("w", encoding="utf-8"), indent=2)
    # KML
    _json.dump(to_kml(report), kml_full.open("w", encoding="utf-8"), indent=2)
    # JSON
    _json.dump(report.to_dict(), json_full.open("w", encoding="utf-8"), indent=2)
    # HTML (embedded UI)
    html_full = root / "report.html"
    html_full.write_text(build_ui_html(report), encoding="utf-8")
    print(f"[web-ui] Exports written: {json_full}, {geo_full}, {kml_full}, {html_full}")

def build_ui_html(report: Report) -> str:
    """Render the full HTML dashboard for a report."""
    # Calculate summary statistics
    total_findings = len(report.findings)
    avg_confidence = 0.0
    if total_findings > 0:
        avg_confidence = sum(f.confidence for f in report.findings) / total_findings
    
    # Get category counts
    from collections import Counter
    cat_counts = Counter(f.category for f in report.findings)
    cat_buttons = "".join(
        "<button class='cat-btn' data-cat='" + cat + "'>" + cat + " <span class='count'>(" + str(n) + ")</span></button>"
        for cat, n in sorted(cat_counts.items())
    )
    
    out = {
        "target": report.target,
        "status": report.status,
        "count": total_findings,
        "entries": total_findings,
        "started": report.started_at or "—",
        "recon_stage": len(report.collectors) if report.collectors else 0,
        "end_groups": _render_groups(report),
        "json_url": "report.json",
        "geo_url": "report.geojson",
        "kml_url": "report.kml",
        "geo_path": "report.geojson",
        "geo_json": to_geojson(report),
        "confidence_avg": f"{avg_confidence:.1%}",
        "cat_buttons": cat_buttons,
        "s": "s" if "https://" in getattr(report, "source", "") else "",
        "globe": "#ff0055",
    }
    # Convert out dict to string.Template format
    template_vars = {k: str(v).replace("$", "$$") for k, v in out.items()}
    return _HTML.substitute(template_vars)
