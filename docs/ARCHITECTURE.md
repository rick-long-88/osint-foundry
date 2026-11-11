# ARCHITECTURE.md

**osint-foundry** — local OSINT investigation runner (modular monolith)
**Architecture methodology:** design-code-architecture (wondelai)

---

## System Context

### What it does

Runs a multi-stage OSINT investigation against a target (domain, email, name, or handle) by:

1. Running passive-recon collectors staged like osintpilot's AI agents — digital footprint, breach intel, public records, web archive, identity resolution, web-check, OpenOSINT actors
2. Scoring every finding with a confidence weight
3. Emitting a sourced report in Markdown, JSON, GeoJSON, and KML

### Integrations (outbound)

| Source | Type | Purpose |
|--------|------|---------|
| web-check (lissy93/web-check) | Express 5 REST API | Security checks: DNS, TLS, WHOIS, subdomains, cookies, trackers, threats |
| OpenOSINT actors (OpenOSINT/OpenOSINT) | Apify SDK local | domain-recon, username-recon, news-monitor |
| Have I Been Pwned | Breach API | Credential breach check |
| CISA KEV | Vulnerability catalog | Known Exploited Vulnerabilities |
| Circl.lu | CVE detail | CVE enrichment |
| SEC EDGAR | Corporate registry | Company filings |
| OpenCorporates | Global company register | Organization records |
| Internet Archive (CDX) | Wayback index | Historical snapshots |
| DNS / RDAP / cert APIs | Passive recon | Domain enumeration |
| Leaflet + OSM | Map provider (client) | GeoJSON globe rendering |

### Data flow

```
CLI / Web UI
   ↓
run_pipeline(target, stages)
   ↓
Report (in-memory) — domain model
   ↓
Findings → Markdown / JSON / GeoJSON / KML
```

---

## Layer Map & Dependency Rule

```
┌─────────────────────────────────────────┐  ← Frameworks (outer)
│  cli.py        Click CLI commands       │
│  web/ui.py     stdlib HTTP server +     │
│                embedded HTML (Leaflet)  │
│  robin_adapter Robin bridge             │
├─────────────────────────────────────────┤
│  Interface Adapters (framework-agnostic)│
│  collectors/  Collector base + registry │
│  web_check.py  web-check HTTP client    │
│  openosint_actors.py  actor subprocess  │
│  runner.py     Pipeline orchestrator    │
├─────────────────────────────────────────┤
│  Use Cases (application logic)          │
│  pipeline.py  stage execution order     │
│  sources.py   passive-recon source list │
│  transport.py fetch() abstraction       │
├─────────────────────────────────────────┤
│  Entities (business rules, no outer)    │
│  model.py     Finding, Report, to_dict  │
│  geoutil.py   GeoJSON point extraction  │
└─────────────────────────────────────────┘
```

### Dependency Rule

**Source-code dependencies point inward:** nothing in the core ring (`model`, `geoutil`) names anything in an outer ring (`cli`, `web`, `robin`, `web_check`, `openosint_actors`, `pipeline`, `sources`, `transport`). Frameworks (Click, stdlib HTTP, Apify SDK) are details at the outer edge.

### Dependency Rule Audit

| Violation | Location | Fix | Status |
|-----------|----------|-----|--------|
| `model.py` references outer types | `model.py` — no violations; is the innermost ring | — | ✅ Done |
| `pipeline.py` imports collector modules | `pipeline.py:21-22` imports `recon.py`, `sources.py`, `transport.py` | All in Use Cases ring; imports only from Interface Adapters / Entities | ✅ Done |
| `cli.py` calls concrete collector classes | `cli.py` imports `from .model import find` and `from .pipeline import run_pipeline` | No direct collector import — via `run_pipeline()` | ✅ Done |
| `web_check.py` imports Express subprocess | `web_check.py` spawns Express server subprocess | Framework detail at outer edge (interface adapter) | ✅ Done |
| `robin_adapter.py` + `robin/` sphere | Robin bridge at adapter layer | Framework/vendor detail | ✅ Done |

No violations — the Dependency Rule is respected.

---

## Monolith vs Services

| Criterion | Decision |
|-----------|----------|
| **Choice** | Modular monolith |
| **Why** | Single-team local tool; no team boundaries yet; a microservice with shared data model is a distributed monolith |
| **Alternatives rejected** | Split into one service per stage; split `robin` into its own repo |
| **When to revisit** | When you have 2+ teams owning 2+ modules, or when vertical scaling per stage is proven necessary |

### Core modules (phases of the monolith)

| Module | Responsibility | Extensibility point |
|--------|---------------|---------------------|
| `model.py` | Finding, Report, serialization | Add new aggregate types |
| `geoutil.py` | GeoJSON point extraction | Add geometry types |
| `sources.py` | Passive-recon source list | Register new sources |
| `transport.py` | HTTP fetch abstraction | Add auth/retry/circuit-breaker |
| `collectors/*` | Stage implementations | Add new OSINT stage |
| `pipeline.py` | Stage orchestration | Add new stage to order |
| `report.py` | Report export (md/json/geojson/kml) | Add new format |
| `web/` | HTML report viewer | Replace with any framework |
| `cli.py` | Command-line entry point | Add new commands |
| `openosint_actors.py` | Apify actor subprocess runner | Add new actor |
| `web_check.py` | web-check Express client | Add new web-check endpoint |
| `robin/` | Dark-web OSINT bridge | Add new Robin adapter |

---

## Decision Log

| Date | Decision | Why | Alternatives rejected |
|------|----------|-----|-----------------------|
| 2026-11-09 | Modular monolith | Single-team local tool; services split along proven bounded contexts only | Split into per-stage services now |
| 2026-11-09 | Dependency Rule respected | Core testable with no DB/web/framework | Let framework become architecture |
| 2026-11-09 | No database for v1 | In-memory `Report` + file exports; no persistence layer needed | SQLite/PostgreSQL before load justifies it |
| 2026-11-09 | stdlib HTTP server for UI | No external web framework needed for report viewer | FastAPI/Flask for less code |
| 2026-11-09 | subprocess for actors | Actors run locally with mock mode; no Apify account needed | In-process actor imports (would couple to Apify SDK) |

---

## Phase 2 — Bounded Contexts & Context Map

### Bounded Contexts (by domain)

| Context | Modules | Purpose |
|---------|---------|---------|
| **Recon** | `recon.py`, `sources.py`, `transport.py` | Passive DNS/RDAP/certificate enumeration; the entry point for the investigation |
| **Breach** | `collectors/breach_intel.py` | Have I Been Pwned + CISA KEV + Circl.lu CVE enrichment |
| **Public Records** | `collectors/public_records.py` | SEC EDGAR, OpenCorporates, WHOIS/RDAP |
| **Web Archive** | `collectors/web_archive.py` | Internet Archive CDX snapshot timeline |
| **Identity** | `collectors/identity_resolution.py` | Identity graph: aliases, email/domain correlation |
| **Web-Check** | `web_check.py` | Express 5 client for lissy93/web-check |
| **OpenOSINT Actors** | `openosint_actors.py` | Apify SDK local actor subprocess runner |
| **Spatial** | `spatial.py` | GeoJSON/KML point extraction |
| **Reporting** | `report.py` | Markdown/JSON/GeoJSON/KML export |

### Context Relationships

```
Recon ──► (feeds) ──► Breach ──► (feeds) ──► Identity
   │                                    ▲
   ├──► Public Records ────────────────┘
   ├──► Web Archive ───────────────────┘
   ├──► Web-Check ──────────────────────┘
   └──► OpenOSINT Actors ───────────────┘
```

### Anti-Corruption Layer

The `Report` (shared entity) is the anti-corruption boundary: all contexts produce `Finding` objects in the shared vocabulary; no context leaks into another's internal types.

---

## Domain Glossary (Ubiquitous Language)

| Term | Meaning | Code name |
|------|---------|-----------|
| Target | The thing being investigated (domain, email, handle) | `target` (Report.target) |
| Finding | A single sourced, confidence-scored intelligence item | `Finding` (model.py) |
| Stage | One phase of recon with a sub-domain | `stage` (e.g. `recon`, `breach`) |
| Collector | The module that implements one stage | `Collector` (collectors/base.py) |
| Report | The finished intelligence product | `Report` (model.py) |
| Confidence | 0.0–1.0 probability the finding is true | `confidence` (float) |
| Collector | The module that implements one stage | `Collector` (collectors/base.py) |
| Pipeline | The orchestrator that runs stages in order | `Pipeline` (collectors/runner.py) |
| GeoJSON | Map export for the gods-eye globe | `to_geojson()`, `to_kml()` (spatial.py) |
| OpenOSINT Actor | Pre-built recon script (domain/username/news) | `OpenOsintActorsCollector` (openosint_actors.py) |

---

## Phase 3 — System Sizing

| Metric | Value |
|---------|-------|
| Average QPS | <0.1 (single-user local tool) |
| Peak QPS | <1 (batch runs, not concurrent API calls) |
| Yearly storage | <10 MB per target (file exports, overwritten per run) |
| First bottleneck | Synchronous network I/O in collectors (outbound calls) |
| Scaling moved | DEFERRED — a single indexed DB + cache would suffice at <100 QPS |
| Trigger to revisit | >50 concurrent pipeline runs or >1,000 findings/day |

---

## Platform

- **Language:** Python 3.13 (venv at `.venv/`)
- **CLI:** Click
- **Web UI:** stdlib `http.server` + embedded HTML (Leaflet + OpenStreetMap)
- **Data:** in-memory `Report` (no DB for v1)
- **Exports:** Markdown, JSON, GeoJSON, KML

---

## Next Phases

| Phase | Skill | Artifact |
|-------|-------|----------|
| 2 | domain-driven-design | Bounded contexts + context map + glossary |
| 3 | system-design | Load sizing + QPS/storage back-of-envelope |
| 4 | ddia-systems | Data model + storage engine + isolation level |
| 5 | software-design-philosophy | Smell inventory + adopted conventions |
| 6 | release-it | Integration-point audit + timeouts/breakers/pagination |
| 7 | pragmatic-programmer | Tracer-bullet slice + CI gates |
| 8 | 37signals-way | v1 appetite + speculative abstraction cuts |
