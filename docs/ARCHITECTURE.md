# Architecture - CyberDome for NAM

How CyberDome is put together, what runs where, and how data and decisions flow through it, step by step. For the
reasoning behind each design choice see [ENGINEERING.md](ENGINEERING.md); for what each screen shows see
[FEATURES.md](FEATURES.md); for the AI and its guardrails see [AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md).

## 1. One view

```text
                          NAM's people (SOC analysts, SOC lead, CISO, engineers, compliance, auditors)
                                              |  HTTPS, Entra ID sign-in (MFA for decisions)
                                              v
   +--------------------------------------------------------------------------------------------------+
   |  CyberDome (NAM's environment or an Indian cloud region)                                          |
   |                                                                                                  |
   |   Console (static SPA, strict CSP)   <-->   API (FastAPI)  ---  Scheduler (jobs, leases)          |
   |                                                 |                    |                            |
   |   Dome Score / CISO view   Dome Comply   Pilot scorecard   Cases & approvals   Audit & access      |
   |        |                       |              |                 |                                 |
   |   intelligence: posture, ciso, crosstool, control_coverage, tool_health, config_snapshots, risk   |
   |   domains:      dlp (triage, investigator, rule changes), incident (SIEM alerts, cross-tool cases) |
   |   core:         context store, entity resolution, controls, cases, decisions (earned autonomy),    |
   |                 actions + autonomy policy, audit chain, access, watch lists, ownership, scope      |
   |   connectors:   directory export | Forcepoint DLP | Silverfort | Trend Micro | Trellix ePO |       |
   |                 generic SIEM webhook | ServiceNow / Jira | ownership CSV                          |
   |                                                 |                                                |
   |   PostgreSQL (all state, encrypted blobs, hash-chained audit)      LLM gateway (optional) -------+--> model in NAM's
   +-------------------------------------------------|------------------------------------------------+    environment or an
                                                     | read (and, in Phase 3, approved writes)              Indian region
                                                     v
        Forcepoint DLP   Silverfort   Trend Micro   Trellix ePO   AD / CMDB export   SIEM   (Phase 2: Arcon, Cloudflare, SOAR)
```

Layering (dependencies point down only): **API → intelligence → domains → core → connectors**. The LLM gateway is a
leaf any layer may call, and everything works without it.

## 2. Components

| Layer | Component | What it does | Code |
|---|---|---|---|
| Presentation | Console | Single-page app: screens per module, click handling through an allow-list (`data-fn` + `ALLOWED`), every value escaped; menu built from the product scope and the person's data scope; collapsible side menu | `api/static/` (`app.js`, `views.js`, `nam.js`, `styles.css`) |
| API | FastAPI app | Middleware (body cap, NUL / rate limit, security headers, access log, scope 404), authentication, permission per route, one DB session per request committed before the reply | `api/app.py` |
| Scheduling | Scheduler + jobs | Database-decided due-ness, leases renewed while a job runs, retries and dead letters, recorded runs | `scheduler.py`, `jobs.py` |
| Intelligence | Dome Score | Posture from computed factors and the approved weights; levers; movement; daily snapshots | `intelligence/posture.py`, `posture_weights.py` |
| | CISO view | One document behind the Dome Score screen, the CyberDome reports and the brief | `intelligence/ciso.py` |
| | Cross-tool cases | Rules X1-X4 over structured facts; one case per person; severity from agreement | `intelligence/crosstool.py` |
| | Coverage and health | Controls per baseline device; findings from the tools' own health reports | `intelligence/control_coverage.py`, `tool_health.py` |
| | Change baseline | Configuration snapshots and their diffs; planned vs unplanned | `intelligence/config_snapshots.py` |
| | Risk, correlation, analyst Q&A | Inherited platform intelligence, still running | `intelligence/risk.py`, `correlation.py`, `analyst.py` |
| Domains | Data protection | DLP intake, facts, computed disposition, cases, the AI's decision | `domains/dlp/service.py`, `models.py` |
| | AI investigator | Read-only look-ups from a fixed menu within a budget | `domains/dlp/investigator.py` |
| | DLP rule changes | Suggestions, classification findings, preview, two leads, engineer, verification | `domains/dlp/tuning.py` |
| | Incident | SIEM alerts → clusters → investigation; holds the cross-tool cases | `domains/incident/service.py` |
| Reporting | Dome Comply | Control catalogue as data, evidence tests, audit pack; breach assessments and clocks | `reporting/regimes.py`, `breach.py` |
| | Pilot scorecard | KPIs, baselines, targets, outage log | `reporting/pilot.py` |
| | Report builder | CyberDome board deck and CISO brief, Word / PowerPoint in the organisation's style | `reporting/builder.py`, `design.py`, `style.py` |
| Core | Context store + resolution | Every record resolved to one device or person across tools | `core/context_store.py`, `entity_resolution.py`, `identity.py` |
| | Controls | Which tool lists which device, control states | `core/controls.py` |
| | Earned autonomy | Decision types, stages, targets, AI decisions, promotion / demotion | `core/decisions.py` |
| | Cases, actions, policy | Cases and evidence; the only execution path; L0-L4 policy, containment, kill switch | `core/cases.py`, `actions.py`, `policy.py` |
| | Governance | Audit chain, access and roles, watch lists, ownership, notifications, scope | `core/audit.py`, `access.py`, `auth.py`, `watchlists.py`, `ownership.py`, `notify.py`, `scope.py` |
| Connectors | NAM's tools | Fake mode on fixtures now; live through `HttpTransport` once each API is confirmed | `connectors/tools/` (`_paged.py` shared) |
| | Capabilities | What each tool provides (record kinds and fields per capability); every workflow asks for capabilities, never products; module readiness (`capabilities --check`) | `connectors/capabilities.py` |
| | Declared connectors | A plain REST tool connected by a definition file (no code): read-only, fixed converters, own host only; loaded with the code connectors | `connectors/declarative.py`, `config/connectors.d/` |
| AI | LLM gateway | Budgets, per-person limits, model per feature, redaction, grounding and citation checks, circuit breaker | `llm/` |

## 3. Processes and deployment units

| Process | Runs | Scales |
|---|---|---|
| `serve` (API + console) | The API, the static console and, by default, the embedded scheduler | Any number of replicas behind a load balancer (stateless) |
| `scheduler` (optional) | The jobs only (`SOC_EMBEDDED_SCHEDULER=0` on the API) | Any number; the database leases decide who runs what |
| `init-db` | Schema creation with the owner's credentials; grants the runtime role | Once per release |
| PostgreSQL | All state, blobs (`SOC_BLOB_STORE=database`), the audit chain | HA per [HIGH_AVAILABILITY.md](HIGH_AVAILABILITY.md) |
| Model endpoint (optional) | NAM's own LLM gateway or a model in an Indian region | Outside the platform |

Packages: `deploy/docker-compose.yml` (production defaults; `SOC_PRODUCT_SCOPE=${SOC_PRODUCT_SCOPE:-nam}`),
`deploy/kubernetes/` (HA package, Azure and on-premises overlays). Details: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md).

## 4. Jobs (NAM scope) and their order

On a first start every job is due at once and they run in this order:

| # | Job | Interval | Does |
|---|---|---|---|
| 1 | `inventory` | 1 h | the device and people baseline (directory export), then the control tools' inventories (EDR agents, DLP agents, encryption) |
| 2 | `incident` | 5 min | SIEM alerts → clusters → investigation (cross-tool cases are left to `crosstool`) |
| 3 | `dlp` | 5 min | DLP intake and context, computed disposition, cases; investigation and the AI's decision after the commit; drift demotion; breach assessments |
| 4 | `crosstool` | 5 min | rules X1-X4, one case per person, recommended actions, deferred narration |
| 5 | `posture` | 1 h | tool health reports; the day's Dome Score snapshot |
| 6 | `config_snapshot` | 24 h | configuration exports, diffs, unplanned changes |
| 7 | `weekly_reports` | 7 days | the CyberDome weekly CISO brief (Word) |
| 8 | `intelligence` | 10 min | risk, correlation, drift, narration |
| 9 | `retention` | 24 h | pruning per policy, legal hold respected |
| 10 | `self_check` | 1 h | cross-surface consistency, audit chain, `audit.anchor` |
| 11 | `notify` | 1 min | Teams / Slack / webhook delivery of findings above the threshold |
| 12 | `actions` | 1 min | approved actions still waiting; stuck ones marked `unverified` |

## 5. Flows, step by step

### 5.1 A DLP incident, from the tool to a decision

1. **Read.** The `dlp` job syncs Forcepoint's `dlp_incidents` stream (resumed from its watermark), and the context
   streams: directory, Silverfort risky sign-ins, agent and encryption inventories, Trend Micro alerts. Each page is
   committed as it is stored.
2. **Resolve.** The sender's account and device resolve to the person and the device of the baseline
   (`core/identity.user_ref`, deterministic keys before scored hints).
3. **Facts.** `DlpService._facts` builds F1, F2 ...: severity, channel, the tool's action, rule, classifiers (type,
   OCR origin), personal-data classes, bulk, destination class (from NAM's partner and sanctioned lists), the person
   (department, privileged), identity risk, the device's controls. The subject and file names go to `untrusted`.
4. **Judge.** `dispose()` - the published decision table - gives escalate / close as benign / needs a person with its
   reasons; severity is raised only by corroboration; the never-automatic list is checked.
5. **Case.** An escalation opens or joins a `dlp` case; personal data opens a breach assessment (Dome Comply).
6. **Commit.** The batch is committed - nothing is held while a model answers.
7. **Investigate.** The investigator runs up to 5 read-only look-ups (model-planned, or the platform's plan) and
   numbers the findings I1 ...
8. **The AI decides (shadow).** The model gets the facts and findings (text fenced), answers close / escalate with
   citations; the answer is stored in `ai_decisions` beside the computed one, or discarded with the reason. Nothing
   acts on it in shadow.
9. **A person rules.** The analyst closes or escalates; at `recommend` the AI's decision is pre-filled and overruling
   it needs a reason. Rulings feed agreement, drift and the rule-change suggestions.

### 5.2 One person, several tools: a cross-tool case

1. The `crosstool` job takes each person with a DLP alert and gathers their signals: identity risk (Silverfort), a
   control off on the sending device (Trellix / Forcepoint agent / Trend Micro agent), an endpoint alert on it
   (Trend Micro `edr_alert`), membership of a privileged group (directory).
2. Rules X1-X4 join them; with two or more distinct tools agreeing a case opens (one per person, domain `incident`):
   high at 2 tools, critical at 3+.
3. Recommended: revoke sessions and require MFA (Silverfort); at 3+ tools, isolate the device (Trend Micro, four-eyes).
   All at L2 - recommended, never run - in Phases 1-2.
4. The case is committed; the model's written account follows (`crosstool.summary`, citing E-numbered evidence).

### 5.3 The Dome Score

1. `posture()` computes each domain's score from its factors (coverage shares, health findings, open cases); domains
   no connected tool measures are left out.
2. The weighted mean uses the **approved** weights document; whole-score penalties follow.
3. The `posture` job stores the day's score with its weights version; the CISO view computes levers (what would raise
   it most) and movement (why it changed since the oldest stored day of 30).
4. The brief is written by rule; the model writes it only on request, citing P-numbered evidence.

### 5.4 An action, from recommendation to tool

1. A module asks `ActionService.request` (never a connector directly). The policy decides the effective level from
   the action's configured level, the tool's stage (`recommend` caps at L2), the kill switch, VIP targets, blast
   radius, destructive and **containment** (always four-eyes, never L4).
2. L2: recommended - a person approves on *Approvals*; four-eyes needs two different people.
3. On approval the request is claimed exactly once; `executing` and its audit record are committed before the tool
   call, the outcome after. A lost outcome becomes `unverified`, never re-run.
4. In Phase 3 the execution backend becomes NAM's SOAR (M9), still behind `ActionService`.

### 5.5 A personal-data incident under DPDP / CERT-In

1. A DLP case with personal data gets a breach assessment (`dlp` job, idempotent).
2. A lead decides reportable or not, in person, with a reason; the decision stands. Reportable copies the clocks from
   the catalogue in force (with source and "to verify").
3. The AI may draft the report from the case's structured facts (cited); a person reviews and sends it outside the
   platform, then records each submission with its reference.

### 5.6 A change to a tool's configuration

1. An engineer records *before change* (reference, note) → the platform snapshots the configuration.
2. The change is made in the tool.
3. *After change* → a new snapshot, the difference field by field, the Dome Score before and after.
4. A difference outside a recorded change window is *unplanned* and shows on tool health.

### 5.7 A request through the API

`BodyLimitMiddleware` (30 MB) → `SecurityMiddleware` (NUL in path / query → 400, Content-Length → 413, token bucket
→ 429, out-of-scope route → 404) → `current_user` (Entra bearer, dev token, `sk_soc_` key, break-glass session;
revocation checked) → `need(Perm.X, "domain")` → the handler with one session, committed **before** the reply →
security headers and the access-log row. Service errors map to 400 / 403 / 404 / 409 / 503, never a database text.

## 6. Data

**Stores.** PostgreSQL holds everything durable: the context store (entities, keys, hints, relations, source
records), cases and evidence, actions, the audit chain, settings documents (policy, AI usage, weights, catalogue,
connector configuration), job runs, and - with `SOC_BLOB_STORE=database` - encrypted blobs (reports, audit packs).

**Tables added by the NAM build:** `dlp_alerts`, `ai_decisions`, `decision_stages` (targets in `system_flags`),
`dlp_rule_proposals`, `config_snapshots`, `posture_snapshots`, `posture_weights`, `crosstool_cases`,
`compliance_catalogues`, `compliance_assessments`, `pilot_outages`. New tables and new nullable columns reach an
existing database at start-up; anything else needs a scripted migration.

**Record kinds** (`core/schema.py`) added: `dlp_incident`, `auth_risk`, `tool_health`, `edr_alert`; dimensions
`data_protection`, `web`.

**What leaves the deployment:** calls to NAM's own tools; the model endpoint (when on: pseudonymised prompts only, to
an approved https endpoint in NAM's environment or an Indian region); notification webhooks (finding title,
severity, link). Nothing else. Details: [client_review/03_DATA_FLOW_AND_PROTECTION.md](client_review/03_DATA_FLOW_AND_PROTECTION.md).

## 7. Screens (NAM scope)

| Group | Screen | Shows |
|---|---|---|
| Operate | Dome Score | the CISO view: score, levers, movement, weights, coverage, health, DLP week, people, AI ladder, cross-tool cases, governance |
| | Pilot scorecard | KPIs against baseline and target, AI agreement, outage log |
| | Intelligence | risk ranking, correlated findings, analyst Q&A |
| | Cases / Approvals | every case (DLP, cross-tool, incident); actions waiting for people |
| Domains | Data protection | the DLP queue, decision types, rule changes and classification findings |
| Insight | Dome Graph · coverage | devices short of a control, tool health |
| | Dome Connect · changes | configuration snapshots and changes |
| Govern | Dome Comply | controls and evidence, deadlines, personal-data incidents, audit pack |
| | Watch lists, Tuning, Integrations, Automation policy, AI usage, Reports, Access, Audit log | the platform essentials |

The inherited screens (Overview, Phishing, Vulnerabilities, Cloud posture, ATT&CK coverage, Shadow IT, Supplier risk)
exist only in the `full` scope.
