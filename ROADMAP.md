# SummerPuppy Roadmap

**Vision:** An autonomous security operations platform where AI agent swarms replace human SOC analysts. Security threats are detected, analyzed in a sandboxed environment, triaged by severity, and remediated — with the system learning and improving from every incident.

---

## Current State — Sprints 1–7 Complete

**932 unit tests. End-to-end MVP smoke test passing.**

| Sprint | What Was Built |
|--------|---------------|
| 1 | Trust framework (phases, policies, scoring), event models, immutable audit trail, 8-stage pipeline orchestrator |
| 2 | LLM client (Claude), LangGraph analysis graph (triage → analyze → recommend), Neo4j knowledge store |
| 3 | Inter-agent pool coordination (threat research + engineering pools), shared artifact store, WorkItem protocol |
| 4 | Autonomous execution engine (dry-run → policy gate → execute → verify → rollback), mock adapters (EDR, IAM, firewall, patch) |
| 5 | Learnable remediation loop: RunEvaluator, Trainer, PromotionEngine, SkillKnowledgeBase, skill registry |
| 6 | FastAPI operator plane v0.2.0: auth (JWT + API keys), customer management, events, approvals, policies, reporting, notifications, scheduler |
| 7 | MVP wiring: startup auto-wiring, tenant onboarding, human approval flow, end-to-end smoke test |

### What Works Today
- Full 8-stage pipeline: intake → triage → analyze → recommend → approve → execute → verify → close
- Trust-gated execution: actions require meeting trust phase + policy conditions or human approval
- LangGraph-based analysis: conditional routing routes CRITICAL/HIGH events through deep analysis, LOW through fast path
- Skills system: successful remediations captured, evaluated, and promoted to team/global KB
- Multi-tenant isolation with per-tenant policy configuration
- REST API surface covering the entire operator plane

### What Needs Building for MVP
The pipeline skeleton is complete. What's missing is the muscle — real-world threat processing, emergency response, and the self-improvement loop that makes the system smarter over time.

---

## MVP Definition

> **"Deployable to a customer"** means: the platform can ingest real security events from a customer environment, classify them, respond autonomously to severity-1 incidents within seconds, escalate everything else through the appropriate trust gate, and get measurably better with each passing week.

### MVP Acceptance Criteria

1. **Threat intake:** Customer agent can submit events from EDR, SIEM, or network telemetry via REST or event stream
2. **Security sandbox:** Malware samples and vulnerability findings are analyzed in isolation and produce structured `SecurityEvent` findings with MITRE ATT&CK mapping
3. **SEV-1 auto-triage:** CRITICAL events trigger immediate containment actions without waiting for human approval — the system acts first, reports after
4. **Human-in-the-loop:** MEDIUM/HIGH events follow the trust gate, with approval requests pushed to Slack/PagerDuty within 30 seconds
5. **Audit trail:** Every action (autonomous or human-approved) is logged immutably with full reasoning trace
6. **Self-improvement:** Successful remediations are automatically promoted to reusable skills; the KB grows with each incident
7. **Operator plane:** Customer can inspect events, review pipeline decisions, configure trust policies, and view reports via the REST API

---

## Phase Plan

### Phase 8 — Security Sandbox + SEV-1 Auto-Triage (Sprint 8)
*Goal: The system can analyze threats and act immediately on the worst ones.*

**Security Sandbox (`summer_puppy/sandbox/`):**
- `models.py` — `SampleSubmission`, `AnalysisReport`, `Finding`, `SandboxVerdict`
- `analyzer.py` — LLM-powered analysis pipeline: static analysis → behavioral analysis → IOC extraction → MITRE mapping
- `findings_to_events.py` — Convert `AnalysisReport` findings to structured `SecurityEvent` objects with populated `raw_payload`, `tags`, and `mitre_attack_ids`
- REST endpoint: `POST /api/v1/customers/{id}/sandbox/submit`

**SEV-1 Auto-Triage (`summer_puppy/pipeline/`):**
- `AutoTriagePolicy` in trust models — defines conditions under which CRITICAL events skip the approval gate
- Modified `TrustApprovalHandler` — detects CRITICAL severity + autonomous-eligible action classes and routes to immediate execution
- Escalation-after-action: CRITICAL actions notify immediately post-execution rather than waiting for pre-approval
- Configurable per-tenant: customers can enable/disable autonomous SEV-1 response

### Phase 9 — Self-Improving Agent Loop (Sprint 9)
*Goal: Each incident makes the system smarter.*

**Feedback injection:**
- `SkillInjector` — after training cycle, successful playbooks are written back to the Neo4j knowledge graph as enriched threat records
- `PromptEnricher` — pulls top-performing playbooks from KB and includes them as few-shot examples in LLM analysis prompts
- Weekly skill promotion review: skills that reach `GLOBAL_KB` level are surface-rendered as policy suggestions to human operators

**Agent performance tracking:**
- Per-agent skill profiles track success rate, false positive rate, and human override rate
- Agents with degrading performance are flagged for review; patterns that consistently cause overrides are suppressed

### Phase 10 — On-Site LLM Deployment (Sprint 10)
*Goal: Customer gets a local LLM with their security context.*

**Customer-local deployment:**
- Docker Compose or Helm chart: customer-local agent swarm + LLM (Ollama-backed) + local event buffer
- Encrypted context sync: local KB stays in sync with central platform without sending raw events off-site
- Emergency triage mode: if cloud connectivity drops, local LLM handles triage with cached KB

**LLM provider abstraction:**
- `LLMProvider` interface supporting Claude (cloud), Ollama (local), and configurable fallback chain
- Per-tenant LLM configuration: customers can pin to local model, cloud model, or hybrid

### Phase 11 — Dev Bot Integration (Sprint 11)
*Goal: Security findings become code remediations.*

**Finding → User Story pipeline:**
- Sandbox findings with `action_class = PATCH_DEPLOYMENT` trigger user story generation
- `UserStoryGenerator` — produces structured GitHub issues from `AnalysisReport` findings
- Stories include: description, acceptance criteria, affected files/services, severity, CVE references

**Dev bot execution:**
- Engineering pool agents consume user stories and generate candidate patches
- Patches go through: code generation → static analysis → test generation → sandbox validation
- Validated patches submitted as PRs via GitHub integration

### Phase 12 — Production Hardening (Sprint 12)
*Goal: The system can run 24/7 without falling over.*

- Kafka-backed event streaming (replace in-memory event bus)
- Real Neo4j integration with connection pooling and retry
- Horizontal scaling: multiple pipeline workers behind a coordinator
- Observability: Prometheus metrics, structured log export, health dashboards
- Disaster recovery: event replay from Kafka, Neo4j backup/restore
- Secrets management: Vault or AWS Secrets Manager integration

---

## The Self-Improving Agent Loop

```
Incident → Pipeline → [Triage → Analyze → Recommend → Execute] → Outcome

                                     ↑                              ↓
                              PromptEnricher                  RunEvaluator
                              (injects top                   (scores outcome:
                               playbooks as                   quality, safety,
                               few-shots)                     success rate)
                                     ↑                              ↓
                                 Neo4j KB ← SkillInjector ← Trainer (promotes
                                              (writes back    artifacts to KB)
                                               successful
                                               playbooks)
```

1. Every pipeline run is evaluated by `RunEvaluator` (confidence, execution safety, outcome success, QA reliability)
2. `Trainer` updates agent skill profiles and promotes high-quality artifacts to team/global KB
3. `SkillInjector` writes promoted playbooks back to Neo4j as enriched threat records
4. `PromptEnricher` queries the KB for relevant past playbooks and injects them into LLM prompts
5. Agents with better context produce better recommendations — the loop closes

Over time: false positive rate drops, containment speed improves, and human overrides decrease. The trust engine detects this and automatically advances tenant trust phases from MANUAL → SUPERVISED → AUTONOMOUS → FULL_AUTONOMY.

---

## Architecture Evolution

```
Today (Sprint 7):
  REST API → Pipeline Orchestrator → [LangGraph Agents] → [Execution Sandbox]
                                           ↕                      ↕
                                      LLM Client               Mock Adapters
                                      Neo4j KB                 Skills System

Sprint 8+ Target:
  REST API ──────────────────────────────────────────────────────────────┐
  Kafka Event Stream → Pool Coordinator → Threat Research Pool          │
                                        → Engineering Pool              │
                                                │                        │
                                          WorkItem Queue                 │
                                                │                        │
                                       Pipeline Orchestrator             │
                                         ↓           ↓                  │
                                   Security      Auto-Triage             │
                                   Sandbox       (SEV-1 path)            │
                                         ↓           ↓                  │
                                   [LangGraph    [Immediate              │
                                    Analysis]     Execute]               │
                                         ↓           ↓                  │
                                   Trust Gate   Notify-After             │
                                         ↓                               │
                                   Execution Sandbox                     │
                                         ↓                               │
                                   Skills / KB ←──────────────────────── │
                                   PromptEnricher → LLM prompts
```

---

## Key Metrics to Track

| Metric | Target |
|--------|--------|
| Mean time to contain (MTTC) | < 60 seconds for SEV-1 |
| False positive rate | < 5% after 30 days |
| Human override rate | < 20% for AUTONOMOUS phase |
| Skill KB growth | +10 playbooks/week per active customer |
| Pipeline success rate | > 95% (no ERROR stage) |
| Test coverage | > 90% across all modules |
