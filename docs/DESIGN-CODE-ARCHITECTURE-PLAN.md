# DESIGN-CODE-ARCHITECTURE-PLAN.md

**Project:** osint-foundry
**Architecture methodology:** design-code-architecture (wondelai)
**Tracker:** phases 1–8, each `pending | in-progress | awaiting-evidence | done | deferred: reason | skipped: reason`

---

## Phase Status

| Phase | Skill | Status | Key Decision |
|-------|-------|--------|--------------|
| 1 — Boundaries | clean-architecture | done | modular monolith; core testable with no DB/web/framework |
| 2 — Domain | domain-driven-design | in-progress | bounded contexts: recon, breach, identity, web-archive |
| 3 — Sizing | system-design | pending | single indexed DB + cache; <100 QPS year-one |
| 4 — Data | ddia-systems | pending | relational + document; default isolation read-committed |
| 5 — Modularity | software-design-philosophy | pending | deep modules; consolidate shallow pass-throughs |
| 6 — Resilience | release-it | pending | timeouts, breakers, bulkheads on outbound calls |
| 7 — Testing | pragmatic-programmer | pending | tracer-bullet slice + CI gates |
| 8 — Scope | 37signals-way | pending | appetite fixed; speculative abstractions deferred |

---

## Key Decisions

| Date | Decision | Why | Alternatives rejected |
|------|----------|-----|-----------------------|
| 2026-11-09 | Modular monolith | Services split along proven bounded contexts only; a microservice with shared data model = distributed monolith | Split into services now before any team boundary emerges |
| 2026-11-09 | Framework = outer ring | Business rules must stay testable with no DB/web/framework | Let Click/Express become the architecture |
| 2026-11-09 | No database for v1 | Single-user local tool; in-memory `Report` + file exports suffices | PostgreSQL, SQLite before load justifies it |
| 2026-11-09 | stdlib HTTP server for UI | No external web framework needed for report viewer | FastAPI/Flask for less code |
| 2026-11-09 | subprocess for actors | Actors run locally with mock mode; no Apify account needed | In-process actor imports (would couple to Apify SDK) |

---

## Dependency Rule Audit

| Layer | Rule | Status |
|-------|------|--------|
| Entities (outermost) | Nothing inner names anything outer | ✅ `model.py`, `geoutil.py` — no violations |
| Use Cases | Imports only from Entities or lower | ✅ `pipeline.py`, `sources.py`, `transport.py` |
| Interface Adapters | Framework details live here | ✅ `cli.py`, `web/`, `robin/`, `web_check.py`, `openosint_actors.py` |
| Frameworks (innermost) | Endpoint only; no inward calling | ✅ Click, stdlib HTTP, Apify SDK |

## Next Actions

- [ ] Write docs/ARCHITECTURE.md (Phase 1 done)
- [ ] Write docs/TECH-DEBT.md (Phase 5)
- [ ] Write docs/TESTING.md (Phase 7)
- [ ] Write docs/RELIABILITY.md (Phase 6)
- [ ] Run tracer-bullet slice (Phase 7)
- [ ] Fix scope (Phase 8)
