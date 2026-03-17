# SummerPuppy

**Autonomous security operations and remediation platform.**

SummerPuppy pairs central expert agent teams with customer-local agent swarms to detect threats, generate validated remediations, test fixes, and deploy safe response actions — at machine speed, with human oversight where it counts.

---

## What It Does

Modern SOC/NOC teams drown in alerts. SummerPuppy replaces the manual triage-investigate-remediate cycle with a coordinated multi-agent system that operates continuously, learns from every incident, and earns the right to act autonomously over time.

**The core loop:**

1. **Customer-local agent swarms** ingest and normalize security events from endpoints, firewalls, IAM systems, and network telemetry.
2. **Threat research pools** classify events, enrich with graph-backed knowledge, and produce structured `WorkItem` decisions.
3. **Engineering pools** consume work items to generate, test, and validate remediation actions — patches, firewall rules, IAM policy changes, EDR responses.
4. **The trust engine** gates every action against a configurable policy model, escalating to human approvers when confidence or trust thresholds aren't met.
5. **The skills system** captures successful remediations as reusable, promotable skills — the platform gets smarter with each incident.

---

## Architecture

```
trust → events → audit → channel → pipeline
```

| Module | Responsibility |
|---|---|
| `trust` | Trust scoring, phase transitions, auto-approval policies |
| `events` | Security event ingestion and normalization |
| `audit` | Immutable audit trail and compliance logging |
| `channel` | Event bus and communication channel integrations |
| `pipeline` | 8-stage orchestration pipeline for security operations |
| `agents` | LangGraph-based analysis graph with severity-conditional routing |
| `pool` | Inter-agent pool coordination — threat research and engineering pools |
| `work` | `WorkItem` / `Decision` / `Artifact` lingua franca between pools |
| `memory` | Shared knowledge store (Neo4j graph backend) |
| `execution` | Sandboxed action execution with EDR, IAM, firewall, and patch adapters |
| `skills` | Learnable remediation skills: evaluation, training, promotion |
| `tenants` | Multi-tenant isolation, per-tenant policy configuration |
| `notifications` | Slack and extensible notification dispatching |
| `scheduler` | Background job runner for recurring operations |
| `api` | FastAPI REST operator plane (v0.2.0) |

### Agent Pool Design

**Threat research pool** — always-on orchestrators consuming event streams, enriching signals against the Neo4j knowledge graph, classifying incidents, and emitting structured work items.

**Engineering pool** — consumes work items, generates candidate remediations, runs them through sandbox execution and policy gates, and submits verified actions for trust-gated deployment.

**Shared memory** — pools communicate through a typed artifact store. Every decision and artifact is recorded, enabling institutional learning and audit replay.

---

## API Surface

The operator plane is a FastAPI application exposing:

| Group | Endpoints |
|---|---|
| Health | `GET /api/v1/health` |
| Auth | `POST /api/v1/auth/token`, `POST /api/v1/auth/api-key` |
| Customers | `POST /api/v1/customers`, `GET /api/v1/customers/{id}` |
| Events | `POST /api/v1/customers/{id}/events`, `GET /api/v1/customers/{id}/events` |
| Approvals | `POST /api/v1/customers/{id}/events/{eid}/approve` |
| Policies | `GET/PUT /api/v1/customers/{id}/policies` |
| Reporting | `GET /api/v1/customers/{id}/reports` |
| Notifications | `POST /api/v1/customers/{id}/notifications` |
| Scheduler | `GET/POST /api/v1/scheduler/jobs` |

Authentication supports JWT bearer tokens and API key headers.

---

## Technology Stack

- **Python 3.11+** — async-first throughout
- **FastAPI + Uvicorn** — operator REST plane
- **Pydantic v2** — strict data models and settings
- **LangGraph** — stateful multi-agent analysis graphs
- **Anthropic Claude** — LLM backbone for analysis, triage, and recommendation
- **Neo4j** — knowledge graph for threat intelligence and pattern memory
- **Kafka** — event streaming backbone
- **structlog** — structured, machine-readable logging

---

## Development

```bash
make install      # Install package with dev dependencies
make format       # Auto-fix lint and formatting
make lint         # Run ruff check and format check
make typecheck    # Strict mypy type checking
make test         # Unit tests
make check        # Lint + typecheck + unit tests
make test-all     # Full suite including integration tests
make coverage     # Tests with coverage report
```

### Code Standards

- Strict mypy (all flags enabled)
- Ruff linter and formatter, 99-character line length
- `from __future__ import annotations` in every module
- Pydantic v2 `BaseModel` for all data models
- `StrEnum` for all enumerations
- TDD: tests written before implementation
- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`)

---

## Project Status

| Sprint | Scope | Status |
|---|---|---|
| 1 | Trust framework, event models, audit trail, pipeline orchestrator | Complete |
| 2 | LLM client (Claude), LangGraph analysis graph, Neo4j knowledge store | Complete |
| 3 | Inter-agent pool coordination, shared memory, work item protocol | Complete |
| 4 | Autonomous execution engine, predictive monitoring | Complete |
| 5 | Learnable remediation loop, skills system | Complete |
| 6 | FastAPI operator plane, full API surface | Complete |
| 7 | MVP wiring, startup auto-wiring, tenant onboarding, human approval flow | Complete |

**932+ unit tests. End-to-end MVP smoke test passing.**

---

## Collaboration and Licensing

SummerPuppy is proprietary software. See [LICENSE.md](LICENSE.md) for terms.

Commercial licensing, integration partnerships, and co-development arrangements are available. Contact the maintainers to discuss.
