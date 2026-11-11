# osint-foundry

A local, open-source OSINT investigation runner. It replays the agent-style
pipeline used by [osintpilot.com](https://osintpilot.com) (digital footprint,
breach intel, public registry, web archive, identity resolution) and reuses the
passive recon sources from the [osint-map](https://github.com/osint-map/)
toolkit. It emits sourced, confidence-scored intelligence reports in Markdown,
GeoJSON, and KML for the local [god's-eye-view](https://github.com/bilawalsidhu/gods-eye-view)
spatial-intelligence globe.

## Features

- **Six-stage pipeline** — DNS/TCXT recon, digital footprint + email sweeps,
  breach intel (Have I Been Pwned), public registry (SEC EDGAR), web archive
  (Wayback CDX), and identity resolution.
- **Idempotent collect-and-hold** — a failing source keeps its last good payload
  and is retried later instead of aborting the run.
- **Public-only egress** — outbound recon is restricted to public hosts; no
  internal/private/loopback addresses are ever sent outbound.
- **Report exports** — Markdown with per-finding sources + confidence scores,
  plus GeoJSON/KML for the local globe.
- **CLI** — `osint full|--target`, `osint recon`, `osint pipeline`, `osint geojson`,
  `osint digital-footprint`, `osint help`.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt   # or: pip install -e .
```

## Quick start

```bash
osint full --target example.com
osint pipeline --target hacker@example.com --out report.md
osint geojson --target example.com --out sphere.geojson
```

## Project layout

```
src/osint_foundry/
  model.py        Finding / Report dataclasses + `find` helper
  transport.py    idempotent fetch + Retry (collect-and-hold)
  sources.py      public host registry + route table + clean_text
  recon.py        passive DNS/PTR/RDAP/crt.sh sources
  pipeline.py     six-stage investigation workflow
  report.py       Markdown + JSON report export
  spatial.py      GeoJSON / KML builders for the local globe
  cli.py          Click CLI (full, recon, pipeline, geojson, ...)
  collectors/     parallel collector implementations (base + 5 sources)
```

## Security & safety

- Only **public** data sources are queried. No credentials, API keys, or
  private data are required or stored.
- Reverse-direction probes (DNS, RDAP, whois) are passive and read-only.
- Report findings are confidence-scored and always carry their source URL.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src
black --check src
```

## License

MIT
