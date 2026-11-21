# CLAUDE.md - working on the Agentic SOC platform

Context for anyone (human or AI) changing this repository. Read the **Hard rules** first: they are not negotiable.
Deep detail lives in `docs/`; this file tells you what the project is, how it is put together, how to run and test
it, the conventions the code relies on, and the traps that have already cost time.

---

## 0. This copy is the NAM build ("CyberDome")

This folder is a copy of the Agentic SOC platform that is being turned into **CyberDome for NAM**: an AI-first layer
above an Indian asset manager's eight security tools. "NAM" is the working short name for that client; its full name
is never written here. Sections 1-11 describe the **inherited platform core as it stands** (connectors, domains,
tests, counts): all of it is still true of the code. The first version of M2-M8 and M10-M13 exists, and the rebrand is done, and the product is scoped to NAM (§0.4a) (status column below);
the rest does not. When a NAM module lands, update this section's status column and the matching part of §2 / §4 / §6 in the same change.

Sources (both under `docs/client_deck_nam/`, which is gitignored - never quote them into tracked files beyond what is
here): the deck `CyberDome for NAM v2.pptx` (slides + speaker notes) and the spec `AI_FIRST_DESIGN_NOTE.md`. The
design note wins where the two differ. Every figure in the deck (2,214 endpoints, 91 gaps, Dome Score 81, 1,284
alerts, 40 seconds, 70 %) is **illustrative or a pilot target**: never hard-code one, never present one as measured.

### 0.1 NAM's stack and what is missing

| Tool | Role | Phase | Reads needed | Writes (all via `ActionService`) | Connector today |
|---|---|---|---|---|---|
| Forcepoint DLP | data protection | 1 | incidents, agent check-ins, policies / rules, discovery results, sync and certificate state | none: rule changes stay with an engineer | none - new |
| Silverfort | identity (IAM) | 1 | risky sign-ins, users, auth events | revoke sessions, force MFA (reversible) | none - new |
| Trend Micro EDR | endpoint | 1 | alerts, agent inventory | isolate host (four-eyes) | none - new |
| Trellix (ePO) | disk encryption | 1 | device inventory, encryption state, certificate state | none | none - new |
| AD / CMDB export | device and user baseline | 1 | AD-joined devices, users, DLP policy-group membership | none | partly: `itsm.py` CSV, `core/ownership.py` uploads |
| Arcon | privileged access (PIM) | 2 | credential check-outs, sessions | check in / rotate credential (four-eyes) | none - new (`delinea.py` is the pattern) |
| Cloudflare | WAF | 2 | security events, certificate state | none planned | none - new |
| SIEM (product unknown) | log platform | 2 | alerts in | findings out | `siem.py` (Sentinel, generic webhook) |
| SOAR (product unknown) | execution | 2-3 | run status | executes approved actions | none - new backend |

`connectors/devkit.py:CATEGORIES` has no `dlp`, `encryption`, `waf`, `soar` or `directory` category: add them (with
their `DIMENSIONS`) before scaffolding. Tool versions, editions and licensed APIs are **not yet known**: do not build
a connector from memory of a vendor's API. Read the vendor's documentation for NAM's version first (§10, "Check a
vendor's documentation"); until access exists, build fake mode only and mark every unverified endpoint in the module.

### 0.2 Modules to build

Paths are proposed; keep the layering of §4 (API → intelligence → domains → core → connectors).

| # | Module (deck name) | What it does | Reuses | New code | Status |
|---|---|---|---|---|---|
| M0 | Re-estate and rename | CyberDome branding; a generated Indian asset-manager demo estate (fund-operations users, investor database, PAN / Aadhaar-classified data); no name or data of the earlier client | `scripts/build_estate_variant.py`, `rename_estate.py`, `reporting/style.py` | estate builders and fixtures for the eight tools; a fifth entry in `conftest.ESTATES` | rebrand done (console, favicon, API title, reports, notifications, README; the deck's Dome names on the screens); internal identifiers kept (`soc_platform`, `SOC_*`, `agentic-soc` namespace / webhook source). Asset-manager estate: `build_estate_variant.py --amc` (fictional fund house, Indian names, fund-operations / investor-services departments and DLP groups, investor database, registrar and custodian), the fifth test estate `amc` (with `--messy`); the built-in demo stays Acme |
| M1 | Connectors (Dome Connect) | The tools of §0.1, read-only first | `connector new` scaffold, `test_connector_conformance.py`, `test_live_wire.py`, stages | one module + fixtures + paging test per tool; new categories | partial: `directory_export`, `forcepoint_dlp`, `silverfort`, `trend_micro`, `trellix_epo` in **fake mode only** (placeholder paths and shapes, `_paged.py`); Arcon, Cloudflare, SIEM / SOAR products not started |
| M2 | Tool health watch (Dome Connect) | Agents silent > 24 h, failed or late sync jobs, certificate days left, users unmapped by the AD / LDAP sync, database sync lag; warns ahead, recommends a ticket or an agent re-push | `api/dashboards.connector_freshness`, `core/notify.py`, `itsm.py` ticket action | `intelligence/tool_health.py`, a `tool_health` job, health streams on each connector "wherever the tool reports them" | v1: `intelligence/tool_health.py`, `posture` job reads the `health` streams; screen *Coverage and tool health* |
| M3 | Control coverage (Dome Graph) | Baseline devices × controls (EDR agent, DLP agent reporting, disk encryption): every device missing a control, devices a tool sees that the baseline lacks, users in no DLP policy group; ranked by the sensitive data each holds or reaches | `core/entity_resolution.py`, `context_store`, `core/ownership.py` | `intelligence/control_coverage.py` (not `attack_coverage.py`, which is ATT&CK) + screen + report source | v1: `core/controls.py` (`Snapshot`: what each tool's newest read lists) + `intelligence/control_coverage.py`; `inventory` job runs first |
| M4 | DLP domain (Dome Agents) | Forcepoint incident intake, personal-data flags, computed disposition, case; backlog triage with identity, PAM and endpoint context | `CaseService`, `EnrichmentOrchestrator`, `jobs._isolated`, incident domain as the pattern | `domains/dlp/` (service, models), a `dlp` job, `dlp` in RBAC domains | v1: `domains/dlp/` (computed disposition, never-auto list, cases), `dlp` job, screen *Data protection*; no actions |
| M5 | Earned autonomy (Dome Agents) | Decision-type registry; Shadow → Recommend → Decide per narrow type; AI decision record; shadow evaluator proposes promotion, drift demotes | `core/policy.py` (`PolicyStore` propose / approve), `intelligence/drift.py`, `tuning.QA_RATE` + `guard`, `llm/gateway.py` | `core/decisions.py` (registry, `ai_decisions` table), a `shadow_eval` job, `dlp.disposition` in `KNOWN_WORKFLOWS` | v1: `core/decisions.py` - shadow and recommend; **decide refused in code**; targets, two-lead promotion, drift demotion |
| M6 | AI investigator (Dome Agents) | The model picks read-only look-ups from a fixed menu within a step and time budget; results go through enrichment; every finding cited | `intelligence/analyst.py` (`intelligence.plan` already picks tools), `core/enrichment.py` | menu + budgets for case investigation; `dlp.investigate` workflow | v1: `domains/dlp/investigator.py` - 7 read-only look-ups over the context store, model plans up to 5 in 2 rounds, rules plan without it; I-numbered findings the decision may cite |
| M7 | DLP tuning proposals (Dome Agents) | Groups false positives per Forcepoint rule, proposes a change with its effect on past alerts; an engineer approves and makes it in Forcepoint; overrides at Recommend feed it | `core/tuning.py` (draft, preview, two leads, suggestions) | `dlp` in `tuning.DOMAINS`, DLP rule kinds, classification-quality findings | v1: `domains/dlp/tuning.py` - suggestions from rulings, classification-quality findings (`exclude_ocr`, `use_edm`, `use_fingerprint` from each classifier's type and OCR origin - placeholder fields), 90-day preview, refusals, two leads, engineer records the change, verified from the config snapshot |
| M8 | Cross-tool cases and actions | Rules joining risky sign-in + privileged check-out + DLP exfiltration + encryption off for one person; privileged session outside a change window; computed severity ("N tools agree"); reversible actions by AI, containment by two approvers | `intelligence/correlation.py`, `story.py`, `core/actions.py` | new rules; actions on the Silverfort / Arcon / Trend Micro connectors; `DEFAULT_POLICY` entries | v1: `intelligence/crosstool.py` - rules X1-X4 over structured facts, one case per person (2 tools high, 3+ critical), Trend Micro `alerts` stream (`edr_alert`), Silverfort revoke / require MFA and Trend Micro isolate (placeholders, through `ActionService`, L2; isolate four-eyes); `crosstool` job. Arcon signals not yet |
| M9 | SOAR execution backend | Approved actions are handed to NAM's SOAR and their outcome read back | `ActionService._execute`, idempotency keys, `reconcile_stuck` | a SOAR connector whose actions wrap the playbooks; still behind `ActionService` | blocked: product unknown |
| M10 | Dome Score and CISO view | One posture score from a published, versioned formula over coverage, tool health, open cases and overdue items; five domain scores (identity, privileged access, endpoint, data protection, web); "why did it drop" answered from computed factors; monthly board report | `intelligence/risk.py`, `api/dashboards.py`, `intelligence/analyst.py`, `reporting/builder.py` | `intelligence/posture.py` (formula as a versioned, four-eyes document like the autonomy policy), CISO screen, board report | v1: `intelligence/posture.py` + adjustable weights (`posture_weights.py`: versioned, previewed, two leads), CISO view (`ciso.py`), board report + weekly brief |
| M11 | Change baseline (Dome Score) | Snapshot of a tool's configuration before a change "where the tool can export it"; drift between snapshots; posture before / after | `core/blobstore.py`, `core/connector_config.py` versioning pattern | `config_snapshots` table, snapshot stream per capable connector, diff view | v1: `intelligence/config_snapshots.py` - Forcepoint, Silverfort, Trellix exports (placeholder paths), daily job, before / after change with Dome Score, unplanned changes on tool health |
| M12 | Compliance packs (Dome Comply) | Control catalogue for SEBI CSCRF, DPDP and CERT-In mapped to evidence tests; share of controls with current evidence, the rest named; audit pack; personal-data DLP case opens a breach assessment; 6-hour clock from a person's "reportable"; AI drafts the report; 180-day log retention checked per tool | `reporting/compliance.py` (`build_evidence`, `build_pack`), `core/audit_export.py`, `reporting/builder.py` | `reporting/regimes/` (catalogue as versioned data), `compliance_assessments` table, clock, draft workflow | v1: `reporting/regimes.py` (DRAFT catalogue as versioned data, 11 evidence tests + the platform's, evidence share, audit pack) + `reporting/breach.py` (assessment per personal-data case, a lead's reportability decision, clocks from the catalogue with source and 'to verify', cited AI draft, submissions recorded). NAM's control list and confirmed deadlines not yet |
| M13 | Pilot scorecard | DLP alerts reaching an analyst against the week-2 baseline, outages found by users, AI agreement per decision type; QA re-checks reported separately | `reporting/value.py` (baseline / target / measured) | new KPIs | v1: `reporting/pilot.py` - KPIs measured over the week up to the newest alert, baseline capture, lead-set targets (none preset), outage log, AI agreement per type, QA re-checks apart |

### 0.3 Build order (follows the deck's rollout gates)

1. **Preparation**: a git repository and a `.venv` for this copy (it has neither; §3's commands assume both), M0,
   the new connector categories. Gate for everything else: the inherited suite passes here.
2. **Phase 1, weeks 1-6, "connect and see"** - read-only, nothing written to any tool: M1 for Forcepoint, Silverfort,
   Trend Micro, Trellix, AD export → M3 → M2 → M4 with the computed disposition only → M5 at Shadow (AI decision
   stored beside the analyst's) → M10 v1 → M13 baseline. Also measure alerts per day, the share reaching the model and
   cost per alert (`scripts/measure_llm_usage.py`). Gate: the CISO uses one live view.
3. **Phase 2, weeks 7-14, "triage and correlate"**: M1 for Arcon, Cloudflare, SIEM, SOAR (read) → M8 rules → M6 →
   M5 Recommend stage (pre-filled decision, reason required to override) → M7 → M11. Gate: the agreement target set by
   NAM's SOC lead is met.
4. **Phase 3, weeks 15-20, "act and prove"**: M12 → M5 Decide stage → M8 actions + M9 → board report (M10). Before
   Decide is switched on anywhere: the adversarial DLP-content test set exists and passes. Gate: audit pack accepted.

Order inside a module: fixtures and fake mode → computed behaviour with tests → the model's part with its fallback →
screen → docs. Coverage (M3) comes before score (M10) and compliance (M12): both read it.

### 0.4 Rules that are specific to this build

1. **Who decides what** (replaces hard rule 7's blanket ban, for dispositions only):

   | Decision | Decided by |
   |---|---|
   | Which read-only look-ups to run | AI, from a fixed menu (no free-form tool calls, no URLs) |
   | DLP disposition: close as benign, escalate, merge into a case | AI, once that decision type is promoted |
   | Forcepoint rule change | AI proposes, an engineer approves and makes it |
   | Reversible action (ticket, session revoke, force MFA, tag) | AI at L3 / L4 per action type |
   | Containment (isolate host, disable account, rotate privileged credential) | people, four-eyes, always |
   | DPDP / CERT-In reportability, breach notification | a person; the AI drafts |
   | Dome Score, coverage, severity, every figure on screen | code; the AI explains |

2. **Guardrails that hold at every stage** - each needs a test that fails when it is removed:
   - Never auto-closed: high / critical alerts, privileged users, deception hits, hosts with a known-exploited
     vulnerability, anything on the block watch list (extend `tuning.guard`, do not write a second list).
   - The AI may escalate alone; it may **close only when the computed disposition agrees**. Disagreement → a person.
   - Text an insider can write (message body, subject, file name) is passed fenced as untrusted data; decisions use
     structured facts (user, data class, destination, device state, identity and PAM context); no decision lowers
     severity on content alone.
   - A decision without a valid citation falls back to the computed path.
   - Every AI decision stores model and version, prompt version, evidence hash, structured output and stage.
   - Model off, failing or over budget → computed dispositions, analysts decide; figures identical to model-on.
   - 1 in 10 AI closures is re-checked by a person, permanently (stable hash, as `tuning.qa_sampled`).
3. **The ladder is policy**: a decision type is narrow ("close a Forcepoint e-mail DLP alert as benign") and climbs on
   its own. Promotion is versioned, audited and needs a second lead; demotion on drift (agreement drop on the
   re-checks, or PSI shift in the outcome mix) needs nobody. Targets and minimum samples are settings NAM's SOC lead
   sets - no defaults presented as agreed.
4. **`test_consistency.py`'s "LLM on / off identical"** stays for figures and computed outcomes; split out
   dispositions at the Decide stage. Split the test, never delete it.
5. **Compliance wording**: the platform maps evidence and shows gaps; it never says NAM "is compliant". The control
   mapping is data to be validated by NAM's compliance team, not constants in code. Regulatory facts (dates,
   deadlines, penalties) are written only from the source text, with the source named.
6. **Phase discipline**: Phase 1 and 2 connectors run at stage `read` / `recommend`; a write is requested per action
   in Phase 3 and runs through the SOAR backend behind `ActionService` (hard rule 8 unchanged).
7. **Wording to keep honest**: health and config snapshots exist "wherever / where the tool reports or exports them" -
   a capability matrix per connector, shown on screen, not an assumption.
8. **Data residency**: the model runs in NAM's environment or an Indian cloud region, or is off; `Redactor`
   pseudonymisation stays on. Raw vendor logs stay in the deployment's region.

### 0.4a Product scope: only what NAM asked for

`SOC_PRODUCT_SCOPE` (`core/scope.py`) is `nam` by default in this build: NAM's tools and modules plus the platform
essentials (cases, approvals / actions, autonomy policy, AI gateway and usage policy, watch lists, ownership,
notifications, reports, access, audit). The inherited modules - phishing and its ML engine, vulnerability management,
cloud posture, shadow IT, supplier risk, ATT&CK coverage, the earlier estate's connectors (and Sentinel until NAM's
SIEM is known) - are **switched off, not deleted**: not in the registry, jobs not scheduled, routes 404 (middleware),
screens hidden (`/me` -> `product.hidden_screens`), report sections not offered, the engine never loads. The test
suite runs in `full` (conftest); `test_scope.py` checks `nam`. A new NAM connector goes into `scope.NAM_CONNECTORS`;
a new inherited-only job, route, screen or report source into the matching `FULL_ONLY_*` set. Deleting the inherited
code is a separate decision (it would mean rewriting much of the inherited suite).

### 0.4b What the first version built (read before extending it)

* **Placeholder APIs.** The five new connectors share `connectors/tools/_paged.py`: every endpoint path is a
  `<stream>_path` setting, the page shape `{"items", "next_page_token"}` is a placeholder, `confidence="Unknown"`.
  Only `fetch_page` and `_live` change when a vendor's documentation for the installed version is in hand.
  `test_connector_nam_stack.py` checks that none of them adds a look-up, an action or an alert kind the other
  workflows read.
* **New record kinds** (`core/schema.py`): `dlp_incident`, `auth_risk` (Silverfort - deliberately not `signin`,
  which the incident and risk code read in Entra's shape), `tool_health`. New dimensions: `data_protection`, `web`.
* **Inventory records are dated by the vendor's own last-seen time** (as every existing inventory connector is);
  whether a tool *still lists* a device is read from the sync time (`SourceRecord.fetched_at`) in
  `controls.snapshot`. A device merely named in a tool's event does not count as listed by that tool.
* **Read the baseline first.** The `inventory` job is first in `jobs.JOBS` and `demo` calls the same sync first:
  when the phishing / incident pipelines create a laptop from a DNS event (name and address only) before the
  directory is read, the directory record cannot be matched with confidence, waits in the analyst queue, and the
  device drops out of the baseline (found by running the demo).
* **Facts, not text.** `DlpService._facts` builds the numbered evidence (F1...) every decision cites; no rule reads
  the subject or file names, and `test_dlp.py` proves an injected message changes no outcome, severity or fact.
* **Model decisions** go through `ai_decide_committing` after the job's commit (no write lock across model calls),
  are capped per run (`SOC_DLP_AI_MAX_PER_RUN`), and are stored in `ai_decisions` keyed by (item, evidence hash).
* **Investigation is not disposition.** Investigator findings (I1...) feed only the AI's decision and the analyst;
  they enter `evidence_hash`, so a new investigation makes the AI decide again, but no rule reads them.
* **Rule changes are change requests.** `domains/dlp/tuning.py` never calls the DLP tool; "applied" is recorded by an
  engineer and verified from `config_snapshots` and later alerts.
* **Configuration export is not a sync stream.** `PagedConnector.config_items()` reads in full outside `SyncRunner`;
  nothing of it enters the context store.
* **The CISO view is one document** (`intelligence/ciso.py`): the Dome Score screen, the CyberDome report sections
  and the plain-words brief all read it. "What raises the score" (`posture.levers`) and "why it moved" (`movement`)
  are arithmetic on the formula's own factors; the brief is by rule unless a person asks the model (`posture.explain`).
* **Cross-tool cases read facts, never text** (`intelligence/crosstool.py`): the DLP alert's own facts (identity risk,
  device gaps, privileged) plus the alerts of every `edr.alerts` provider (`edr_alert` or `alert` kind); Trend
  Micro's alerts are their own kind so the incident pipeline is unchanged. "Has an EDR" is `risk.edr_tools()`, read
  from the capability declarations (a hard-coded list once called a Trend Micro laptop "without EDR").
* **Plug-and-play by capability** (`connectors/capabilities.py`): every manifest declares `provides={capability:
  stream}` (a `Provides(stream, {contract_field: own_field})` where the tool's field names differ); workflows ask
  `registry.providers(*caps)` / `capabilities.tools_for(...)` and read fields through `capabilities.read_field`, never
  a product's name. The control catalogue (`core/controls.py`), DLP, cross-tool, posture, tool health, the CISO view,
  incident and vulnerability ingestion all read capabilities; a device covered by either of two EDR products counts
  once with the better state. `MODULE_NEEDS` + `matrix()` give the readiness check (`capabilities --check`, `GET
  /api/v1/capabilities`). Still product-specific by nature: the phishing investigation's vendor look-ups, ATT&CK
  coverage per product, report short names.
* **Declared connectors** (`connectors/declarative.py`): a plain REST tool from a definition file in
  `config/connectors.d/` or `SOC_CONNECTOR_DEFINITIONS` (example: `config/connectors.d/examples/`, not scanned).
  Read-only, fixed converters (`CONVERTERS`), relative paths only, credentials as settings, capped paging; loaded by
  `registry.discover()` after the code connectors (never replacing one), `origin="definition"`, in every product
  scope. `connector validate FILE` checks one. Proof of equivalence: Trellix `systems` as a definition gives the same
  records (`test_declarative.py`).
* **The Dome Score's weights are a document** (`posture_weights.py`): `posture(config=...)` previews; nothing else
  reads `WEIGHTS` (the draft) - use `posture()["weights"]`.
* **Reportability is a person's decision and it stands** (`reporting/breach.py`): deciding again would restart the
  regulatory clocks, so it is refused; clocks come from the catalogue with their source and stay "to verify".
* **Every governed approval is an exactly-once claim** (`core/db.claim`: `UPDATE ... WHERE status IN (...)`); the
  reportability decision and each recorded submission compare-and-swap a `revision`. Checking a status in Python and
  then writing it let two leads both "approve" (round 39). A new approval path must use `claim`.
* **Containment is enforced by the engine** (`policy.CONTAINMENT`: isolate, disable account, reset password, confirm
  compromised, rotate secret): four-eyes and capped at L3 whatever the policy document says; such documents are
  refused; every four-eyes action is capped below L4. Tests that need an autonomous action use a non-containment one.
* **Manual runs hold the job's lease** (`jobs.held`): `POST /dlp/run` and `/crosstool/run` answer 409 while the job runs.
* **The destination domain is a real host name or nothing** (`dlp/service._domain`): sender-written text after `@`
  once became a "fact" in the breach draft and the model's narration.
* **Queries stay flat with history:** the DLP summary is database aggregates, the backfill is judged in committed
  batches (`process_committing`), the noisy-rule list and tool rulings look at the 30 days up to the newest alert.

### 0.5 Not yet decided (ask, do not assume)

SIEM and SOAR products · tool versions and licensed APIs · which Trend Micro product · where the model runs and which
models that region offers · agreement target and minimum sample per decision type · which actions NAM accepts as
reversible · whether NAM's auditors require a named person on every closure (then DLP stays at Recommend) · the Dome
Score weights (agreed with the CISO) · NAM's CSCRF control list · the baseline source (AD, CMDB or Intune export).

---

## 1. Hard rules

1. **Never write the client's name or its abbreviations** (the real client is anonymised) anywhere in the repo: code,
   docs, file names, commit messages, test data. The demo organisation is **Acme** (`acme-demo.com`); variant
   estates are generated names (Veridian Foods, Tidewell Insurance...). Before every push, scan tracked files for the
   banned names. **NAM build:** this covers both clients - the earlier client's names and data must not reach
   anything built for NAM, and NAM's full name is never written (the short name "NAM" is allowed in docs; code, test
   data and fixtures use the generated demo estate). The delivery company's name stays out of tracked files too.
2. **Never commit secrets.** `.env` (holds the Azure AI Foundry key as `SOC_LLM_*`, plus engine keys) is gitignored;
   never print its values. Before every push, check that no `.env` secret value appears in any tracked or staged
   file (§9 has the snippet). Also keep out: `gdrive_credentials.json`, anything under `test_reports/private/` (real
   inbox exports), the internal requirements `.docx` at the repo root, `*.db`, `data/`, `logs/`.
3. **The user commits mid-task.** Before committing, run `git log --oneline -5` and `git status`; if there are new
   commits you did not make, scan them for secrets and banned names, and build on them.
4. **Commit attribution:** end commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
   Commit or push only when asked.
5. **Kill processes only by specific PID** (found via `netstat -ano | findstr :<port>` or the command line), never by
   name - other Python processes on this machine belong to the user.
6. **Do not reproduce detailed attack tradecraft** in test data or docs. Sample data stays at alert-title level
   (e.g. "Suspicious PowerShell download"), never step-by-step techniques.
7. **The LLM never produces a figure, verdict, score or decision.** Everything numeric or decisional is computed in
   code; the model only writes narrative from evidence it is handed, and must cite it. Do not add features that let
   model output change a number, a verdict or an action. **NAM build:** relaxed for **dispositions and reversible
   actions only**, under the earned-autonomy ladder and guardrails of §0.4; figures, scores and severity stay
   computed. Until M5 exists, this rule applies in full.
8. **Nothing executes without approval by default.** Every write to a security tool is an `ActionRequest` through
   `ActionService` and the autonomy policy (default L2 = recommend). Never call a connector's write method directly
   from a domain or the API.
9. **Keep docs true.** When behaviour, numbers, settings or test counts change, update the affected docs in the same
   change (see §8 for which doc owns what). Never write a number in a doc you have not measured or read from code.

---

## 2. What this project is

An **agentic SOC platform**: one investigation and automation layer over an organisation's existing security tools.

- **21 connectors** pull from EDR (CrowdStrike, Defender for Endpoint), e-mail security (Defender for Office 365,
  Avanan), identity (Entra ID, Defender for Identity), DNS (Umbrella), deception (Canary), PAM (Delinea Secret Server / Privilege Manager),
  vulnerability scanners (Rapid7, Wiz, plus Spotlight/TVM via the EDRs), public intel (NVD, EPSS, CISA KEV),
  threat-intel fusion (8 sources), ITSM/CMDB (ServiceNow, Jira, CSV) and SIEM (Sentinel, generic webhook).
- Records from every tool are **resolved to one host / one person** (entity resolution) in a shared context store.
- **Three workflow domains** run on that picture:
  - **Phishing** - user-reported e-mail → verdict → campaign scope → who clicked → endpoint/identity impact → remediation.
  - **Incident** - alerts → clusters → parallel enrichment → deterministic severity → MITRE → recommended actions.
  - **Vulnerability** - 4 scanners → one finding per host+CVE → priority (CVSS/EPSS/KEV/exposure/criticality) →
    owner → campaign → validated fix; cloud misconfigurations share the lifecycle.
- An **intelligence layer** correlates across domains: explainable risk per user/host, 13 correlation rules, the
  **attack story** (cross-tool kill-chain reconstruction), optional LLM deep analysis, analyst Q&A, situation brief,
  ATT&CK coverage, shadow IT, drift monitoring, and a report builder (Word/PowerPoint).
- **Governance**: RBAC + domain scope + step-up MFA, four-eyes, versioned autonomy policy, durable kill switch,
  hash-chained audit log, encryption at rest, retention with legal hold, self-check.
- **Teamwork and alerting**: case owner (take / assign), append-only analyst notes, global search over cases, every
  tool identifier, findings and CVEs, Teams / Slack / webhook notifications for findings above a threshold, and
  block / exception watch lists (uploaded as Excel or CSV by a lead) flagged on every case that involves a listed item,
  and an uploaded ownership mapping (resource / host / subscription -> owning team) for what the CMDB does not hold.
- **Tuning**: a lead asks in words to cut noise, raise attention on hosts / users, label an exercise, set phishing
  auto-close, adjust vulnerability priority weights / SLA days or mark an action analysts keep rejecting; the request becomes a checked draft rule, previewed on past data and approved by a second lead; the
  platform suggests changes from analysts' decisions. High / critical, deception, exercise and KEV-host alerts are never
  suppressed; 1 in 10 suppressions stays open; a threat found pauses the rule; a raise never changes a verdict.
- Every connector has **fake mode** (vendor-shaped fixtures through the same parsing code) so the whole platform runs
  and demos with no tenant access.
- **Phishing ML engine** (`soc_platform/domains/phishing/engine/`, ~24k lines, earlier code base): 7-agent ML swarm
  (a trained model per e-mail component, `artifacts/phishing/models/`) + LangGraph. **On by default when installed**
  (`SOC_PHISHING_ENGINE=auto`), fused with the heuristic analyser (`CompositeAnalyzer.fuse`). The content model is a
  TF-IDF classifier trained on public data (`scripts/train_content_model.py`; attribution in README). The engine is
  strictly offline in-platform (`EngineAnalyzer.enforce_offline`): never add a code path that lets it call out. The test suite pins it
  off (conftest) except `test_phishing_engine.py`. scikit-learn is pinned to 1.8 (the models' version).

Scale: ~16.8k lines platform Python, ~5.6k lines platform tests, ~0.9k lines of vanilla JS UI.

---

## 3. Commands

This is a **Windows** machine. The Bash tool runs Git Bash; PowerShell 5.1 is also available. Use the venv
interpreter: `.venv/Scripts/python` (bash) or `.\.venv\Scripts\python` (PowerShell). The platform reads settings
**only from the environment** - `.env` is not auto-loaded (`. .\scripts\load_env.ps1` loads it into a PowerShell
session; `verify_features.py` reads the `SOC_LLM_*` lines itself).

```bash
# run
python -m soc_platform init-db                 # create tables (idempotent)
python -m soc_platform demo                    # NAM scope: 14 DLP alerts -> 3 DLP cases + 3 cross-tool cases (7 approvals), 3 reportability decisions, coverage 6 of 10, CISO reports; full scope adds 7 phishing + 3 incident cases (43 approvals in all), 6 open vulns
python -m soc_platform reset-demo [--yes]      # server stopped: wipe the demo DB + raw/report files, then init-db + demo
python -m soc_platform serve                   # API + console + built-in scheduler on 127.0.0.1:8080 (SOC_PORT/SOC_HOST)
python -m soc_platform scheduler [--once]      # optional separate scheduler service
python -m soc_platform token lena@acme-demo.com lead   # dev token (needs SOC_DEV_JWT_SECRET)
python -m soc_platform config check [FILE] [--no-env]  # every configuration problem with its fix; exit 1 on errors
python -m soc_platform preflight NAME... | --all       # every check a tool must pass before it goes live
python -m soc_platform capabilities [--check] [--json] [--config F]  # what each tool provides; modules ready? (exit 1 if not)
python -m soc_platform connector new NAME --category CAT --tool "Vendor X"   # scaffold;  connector check NAME
python -m soc_platform connector validate FILE          # check a declared connector (definition file) + its fixtures
python -m soc_platform blobs check | migrate [--delete-files] | reencrypt   # resolve; file store -> database; re-key
python -m soc_platform audit verify [--anchor SEQ:HASH]        # recompute the chain; compare with heads shipped to logs
kubectl kustomize deploy/kubernetes/overlays/azure             # render the HA package (or overlays/onprem)
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml --env-file .env up -d --build  # demo stack
# (the base compose file is PRODUCTION: Entra, TLS-verified PostgreSQL, owner / runtime roles; the demo is the override)
# minimum env for a local run: SOC_DEV_JWT_SECRET=<32+ random chars>, SOC_ORG_DOMAINS=acme-demo.com
# Python 3.11-3.13 (both suites pass on 3.11 and 3.13; pgserver has no 3.13 build - dev.txt skips it there)

# tests (full suite ~25 min SQLite, ~50 min PostgreSQL when both run at once; run the relevant files first)
python -m pytest soc_platform/tests -q -p no:cacheprovider
python -m pytest soc_platform/tests/test_phishing.py -q -p no:cacheprovider -k <name>
SOC_TEST_POSTGRES=<postgresql://...> python -m pytest soc_platform/tests -q -p no:cacheprovider   # same suite on PostgreSQL
python -m pytest soc_platform/domains/phishing/tests/unit soc_platform/domains/phishing/tests/integration -q   # ML engine (~5 min)
SOC_LIVE_LLM=1 python -m pytest soc_platform/tests/test_live_llm.py      # real LLM (costs cents)
SOC_LIVE_TESTS=1 python -m pytest soc_platform/tests/test_live_public_feeds.py   # real NVD / EPSS / CISA KEV

# verification report (writes docs/FEATURE_VERIFICATION.md)
python scripts/verify_features.py                                 # tests mapped to 122 features (14 NAM), NAM-first report
python scripts/verify_features.py --browser --engine --live --llm # + both browser tours (full scope, NAM scope: tour_nam.js), engine, live feeds, real LLM

# quality gates (all must be clean before a commit)
.venv/Scripts/ruff check . --exclude .venv,node_modules
.venv/Scripts/bandit -r soc_platform scripts -ll -x "soc_platform/tests,scripts/ui_tour/node_modules,soc_platform/domains/phishing/tests"
.venv/Scripts/python -m pip_audit
.venv/Scripts/python scripts/supply_chain.py check           # locks match the environment; image locks hashed, in step
.venv/Scripts/python scripts/precommit_scan.py --all         # no .env secret, no confidential name (--install = git hook)
```

CI (`.github/workflows/ci.yml`) runs all of these on every push, plus both test suites, the SBOM and Trivy scans of
both images (platform, engine); a `v*` tag also pushes and signs them. Every action is pinned to a commit SHA and every
image to a digest (`test_deployment_manifests.py` fails otherwise). After adding or upgrading a dependency:
`python scripts/supply_chain.py lock`, then `python scripts/supply_chain.py image-lock` (Docker: the hashed Linux
locks `requirements/image.lock` / `image-engine.lock` the Dockerfile installs with `--require-hashes`), and commit all
three. A new base-image digest goes in the Dockerfile and `supply_chain.BASE_IMAGE` together.

**Embedded PostgreSQL for tests** (no server needed):
`python -c "import pgserver; print(pgserver.get_server('D:/pgtest_soc', cleanup_mode=None).get_uri())"` → use the
printed URI as `SOC_TEST_POSTGRES`.

**Disk space**: the test session removes its own temporary folders at exit (conftest redirects `tempfile` to one
root), and the browser tour removes its folder. A `--basetemp` folder you name is yours to delete, as is an embedded
PostgreSQL data folder: delete both after the run (repeated full runs once filled the disk).

**Running two full suites at once**: give each its own `--basetemp=<dir>`; otherwise they share pytest's numbered
temp folders and the variant-estate builders overwrite each other (seen as "demo names leaked" failures).

**Other scripts** (`scripts/`): `build_fixtures.py` + `fixture_builders.py` (regenerate fake-mode fixtures),
`build_email_corpus.py` (labelled `.eml` corpus), `build_estate_variant.py OUT --seed N [--scale X] [--messy] [--handoff | --amc]` (a
different organisation: fixtures, settings, suppliers, corpus, `estate.json`; `--messy` adds real-tenant disorder and
event volume; `--handoff` builds the data handoff workbook's estate; `--amc` an Indian asset manager), `estate_profile.py FIXTURES ORG` (events, benign
share and replays through the connectors' own parsers), `measure_scale.py --scales 1,20,40 [--db URL]` (time and SQL per stage on growing messy estates),
`load_test.py --users N --seconds S --workers W [--db URL]` (a real multi-process server under concurrent analysts), `rename_estate.py`, `eval_phishing.py`,
`eval_identity_resolution.py`, `eval_resolution_at_scale.py`, `measure_llm_usage.py` (token/cost measurement),
`build_connector_docs.py`, `ui_tour/tour.js` (Playwright browser tour: layout at 4 widths, axe-core accessibility,
stored-XSS probe, screen-vs-API cross-check; needs Node + installed Chrome/Edge), `load_env.ps1`.

---

## 4. Architecture map (where things live)

```text
soc_platform/
  __main__.py            CLI (init-db, demo, serve, scheduler, token, fixtures)
  config.py              Settings from SOC_* env vars; secret() also reads <NAME>_FILE
  jobs.py                JOBS registry + run_job: lease -> re-check due -> run w/ retries -> record -> release
  scheduler.py           Scheduler (embedded in serve by default), heartbeat, status() for /health
  api/app.py             FastAPI: middleware (body cap, NUL/rate limit, headers, access log), auth deps, ALL routes
  api/dashboards.py      read models: overview, ATT&CK coverage, shadow IT, Prometheus text
  api/static/            index.html, app.js (shell/router/auth/click delegation), views.js (screens), theme.js, styles.css
  connectors/base.py     BaseConnector, TokenBucket, with_backoff, SyncRunner (sync, sync_many), Page, LookupResult
  connectors/http.py     Transport protocol, HttpTransport, FixtureTransport (fake mode; `times`, `headers`), auth
                         strategies, raise_for_status (one status -> error mapping for live and fake)
  connectors/recording.py  record-and-sanitise (SOC_RECORD_FIXTURES_DIR): live responses -> sanitised fixtures
  connectors/registry.py discovery (tools/*.py MANIFEST or entry points), ConnectorRegistry (isolation of unusable
                         connectors, stages, StagedAction cap), ConfigField (secret, required, kind)
  connectors/config_schema.py  strict config checking (Problem with fix, "did you mean"), stages, YAML line errors
  connectors/preflight.py      run_preflight: config, start-up, sign-in, every stream (permission, parsing,
                         freshness, clock, volume), write scopes - each failure with its fix
  connectors/devkit.py   `connector new` scaffold + `connector check`
  connectors/capabilities.py  the capability catalogue (contracts: record kinds + fields), Provides, providers /
                         tools_for / read_field, MODULE_NEEDS, matrix() - what workflows read instead of product names
  connectors/declarative.py   declared connectors: a definition file -> DeclarativeConnector (read-only, no code)
  connectors/tools/      one module per tool; _common.py (ToolConnector, parse_ts, ok_lookup), _microsoft.py (Graph/OData)
  core/schema.py         NormalizedRecord / EntityRef - the canonical schema every connector emits
  core/models.py         core ORM tables; utcnow() (THE clock); new_id() (uuid4 hex)
  core/db.py             Database, sessions, UTCDateTime, BoundedText, NUL stripping, SQLite pragmas, add missing
                         nullable columns (both engines), PG column widening; schema creation serialised across
                         processes (PG advisory lock, SQLite retry; WAL switch retried)
  core/context_store.py  ingest(), neighbours, timelines, keys_of
  core/entity_resolution.py  deterministic keys -> scored fuzzy (0.85 auto, 0.1 margin, 0.55 review) -> queue
  core/identity.py       user_ref(): cross-tool user naming -> upn/sam keys; built-in accounts are not people
  core/cases.py          CaseService: cases, evidence, recommendations, decisions, actions_for_case, assign/add_note,
                         deferred narration (narration_request / pending_narration / narrate_pending)
  core/enrichment.py     EnrichmentOrchestrator: parallel lookups (16 workers, 20 s deadline, 30 min cache)
  core/text.py           readable(): evidence text made plain (no ['x'], [], None) - applied on BOTH evidence paths
  core/actions.py        ActionSpec/Registry/Service - the ONLY execution path; idempotency keys; conditional updates;
                         commits `executing` before a tool call and the outcome after; execute_pending, reconcile_stuck
  core/policy.py         L0-L4 levels, PolicyEngine.decide(), PolicyStore (propose/approve), DEFAULT_POLICY
  core/auth.py           roles/permissions, token validation (Entra RS256 / dev HS256, exp+iat required), dev tokens
  core/access.py         role grants, API keys, revocation, break-glass, kill switch
  core/audit.py          hash-chained append-only audit; _lock_chain serialises appends; verify(since=checkpoint),
                         save_checkpoint (self-check) - /health verifies incrementally
  core/crypto.py         Fernet/MultiFernet (strict in prod: unsealed data refused), write_protected, read_protected
  core/blobstore.py      BlobStore: stored e-mails / reports behind one reference - a path (file store) or
                         `db:<key>` (`blobs` table, SOC_BLOB_STORE=database); reads follow the reference;
                         store_generated, migrate_to_database, check_references (`blobs` CLI)
  core/retention.py      retention + legal hold;  core/selfcheck.py  cross-surface consistency proof
  core/connector_config.py  ConfigStore: console connector config + supplier / sanctioned lists over the files;
                         propose / approve (four-eyes) / reject / pause / restore / export / import; preflight gate
  core/observability.py  trace ids (TRACE contextvar, traced(), accept_trace), structured logging (configure_logging,
                         event(), secrets masked) - every request, audit event, model call, outbound call, job, CLI
  core/notify.py         Notification table + Teams/Slack/JSON webhook delivery (notify job); HTTPS-only config
  core/watchlists.py     block / exception lists (users, hosts, IPs, domains, URLs, hashes): .xlsx / CSV upload with
                         preview (own hardened .xlsx reader - no DTD, size caps), case_matches() read when a case /
                         the case list / the investigation record is built; context only, never decisional
  core/ownership.py      the uploaded ownership mapping (`ownership_mappings`, versioned): .xlsx / CSV rows of resource
                         or host name (wildcards) and / or subscription -> team, owner, environment, criticality;
                         match() exact > pattern > subscription; fills the CMDB's gaps in both enrich_ownership()s
  core/tuning.py         tuning (`tuning_rules`): a lead's request -> draft from a fixed menu (suppress, noise threshold,
                         raise attention, exercise, phishing auto-close, vuln priority / SLAs, usually-rejected
                         action), checked against the request and the data;
                         preview on past data; second-lead approval in the rule's domain; revoke / expiry / pause on a
                         threat; applied in IncidentService.cluster / investigate, CaseService.decide / recommend,
                         VulnerabilityService (weights, SLA days), phishing.tuned_auto_close
  core/audit_export.py   audit exports (jsonl / json / csv / xlsx / docx, filtered) + info() for the Audit screen;
                         .xlsx written without a library (text cells only), CSV cells formula-guarded
  domains/phishing/      service.py (pipeline), models.py, supplier.py, agents/{decompose,analyzer,investigation}.py, engine/
  domains/dlp/           service.py (DLP triage: facts, computed disposition, cases, the AI's decision), models.py (DlpAlert),
                         investigator.py (read-only look-up menu), tuning.py (rule-change proposals)
  core/scope.py          the product scope (nam / full): which tools, jobs, routes, screens, report sections exist
  core/controls.py       which tool lists which device, control states (missing / silent / off / unknown)
  core/decisions.py      earned autonomy: decision types, stages, targets, ai_decisions, promotion / demotion
  domains/incident/service.py
  domains/vulnerability/ service.py, misconfig.py, models.py
  intelligence/          risk.py, correlation.py, story.py, deep_analysis.py, analyst.py, attack_coverage.py, shadow_it.py, drift.py,
                         control_coverage.py, tool_health.py, posture.py, posture_weights.py, config_snapshots.py,
                         ciso.py, crosstool.py (NAM build)
  llm/gateway.py         LLMGateway, providers, grounding, numeric guardrail, breaker, timeouts, llm_concurrency();
                         enforces the usage policy (refusal -> BudgetExceeded / UserLimitExceeded, gateway.notice)
  llm/usage_policy.py    AI usage policy (budgets, per-person limits, per-feature tier / answer cap / on-off), its
                         store (admin-only, versioned, audited) and usage_report (cost, quality, tier advice)
  llm/redaction.py       pseudonymisation before any prompt leaves; restore after
  llm/providers/         openai_compatible (also azure_foundry), anthropic_provider
  reporting/             builder.py (17 sources, 7 standard reports, planner), reports.py, compliance.py,
                         style.py (the organisation's report style: templates, logo, brand, writing guide; uploads
                         validated; use_style() sets design.STYLE around every render - render inside it),
                         value.py (value scorecard: benefit KPIs vs baseline / target; ValueInput in models.py),
                         pilot.py, regimes.py, breach.py (NAM build: pilot scorecard, Dome Comply)
                         design.py (house style for every .docx / .pptx: cover, tiles, tables, charts, header /
                         footer with page X of Y), charts.py (PNG donut / stacked / columns / bars, nice axis steps)
  fixtures/              fake-mode vendor fixtures per connector
  tests/                 platform tests (conftest.py has PG mode, PG-rules enforcement, estates)
config/                  connectors.yaml, suppliers.yaml, sanctioned_services.yaml
artifacts/phishing/      labelled corpus (corpus/*.eml + labels.json), engine models/data
deploy/                  Dockerfile (digest-pinned, hash-locked, non-root, prod defaults), docker-compose.yml (production:
                         db-certs, postgres with TLS + roles, platform-migrate, api, scheduler; tls / backup / engine
                         profiles), docker-compose.demo.yml (dev override), postgres/init-roles.sh, tls/Caddyfile,
                         kubernetes/ (Kustomize base + overlays/azure, overlays/onprem: the HA package; monitoring/:
                         ServiceMonitor + alert rules; policy/: image-signature admission), azure/main.bicep (resources)
docs/                    see §8
```

**Layering** (dependencies point down only): API → intelligence → domains → core → connectors. The LLM gateway is a
leaf any layer may call; everything must work without it.

**Request path**: BodyLimitMiddleware (30 MB) → SecurityMiddleware (NUL in path/query → 400, Content-Length → 413,
token bucket 20/s burst 120 → 429; `SOC_TRUSTED_PROXIES` takes CIDRs) → `current_user` (Bearer: Entra / dev / `sk_soc_` key /
`bg.` break-glass session; X-API-Key; revocation) →
`need(Perm.X, "domain")` → handler with one DB session (commit/rollback **before** the response - always
`Depends(db_session, scope="function")`) → security headers + queued access-log row.
`DataError` → 400, service `KeyError` → 404, `PermissionError` → 403. Out-of-scope records answer **404**.

---

## 5. Conventions the code relies on

**Time and ids**
- Always `soc_platform.core.models.utcnow()` - never `datetime.now()` / `utcnow()` from datetime. It honours the
  test-only `SOC_CLOCK_OFFSET_SECONDS` (time travel) and `SOC_CLOCK_FREEZE` (stop the clock); both are ignored when
  `SOC_ENVIRONMENT=prod`.
- Timestamp columns use `UTCDateTime` (always aware UTC). API timestamps carry explicit offsets.
- Ids are `uuid4().hex` (`new_id()`).

**Persistence**
- Services take a `Session` and **never commit**; the API request or job run owns the transaction. The one exception
  is `ActionService._execute`: it commits `executing` + audit before the tool call and the outcome after, so no lock is
  held while a vendor answers and an executed action is always on record. Inside a savepoint it cannot commit: the
  action stays `approved` and the caller runs `execute_pending()` after its commit (the jobs do; the `actions` job is
  the safety net). Never wrap a request that may approve an action in `begin_nested()`.
- Free text from vendors/people → `BoundedText(n)` (kept to width with "…", NUL stripped). **Identifiers** stay strict
  `String(n)` so a mismatch fails loudly. NUL is stripped from every text column by a `before_flush` listener.
- Schema changes: `create_all` creates tables; `_add_missing_columns` then adds **nullable** columns the model defines
  but an existing table lacks (SQLite and PG); on PostgreSQL start-up also **widens** VARCHARs the model made longer.
  So a new table or a new *nullable* column reaches existing databases automatically. There is **no migration
  framework**: a NOT NULL column, a rename or a drop needs a scripted migration (Alembic) first. A new model module
  must be imported in `Database.create_all` (see the `# noqa: F401` imports) or its table is never created.
- `system_flags` holds durable cross-replica state (kill switch, `job_lease:*`, `scheduler:*` heartbeats,
  `audit_chain_head`). Its key column is 64 chars - hash long keys.
- Exactly-once transitions use conditional `UPDATE ... WHERE status IN (...)` and check `rowcount`.

**Idempotency everywhere** (re-runs must change nothing - a test runs every pipeline twice on 3 estates):
unique `ph_submissions.source_ref` (one case per reported message), unique action `idempotency_key`
(`type:` + sha256 of type/params/targets/case), one active campaign per CVE, insight `dedupe_key` upserts, connector
cursors, DB-decided job due-ness + lease.

**Determinism**: same inputs → same outputs. Sort anything built from a set before slicing or numbering
(an unsorted set of indicators once made verdicts vary between runs). QA sampling uses a stable hash. Story
fingerprints hash the evidence.

**Concurrency (parallel I/O, sequential database)**
- The SQLAlchemy session is not thread-safe. Only **network** work runs in threads; database reads/writes stay on
  the calling thread, and parallel results are merged **in a fixed order**.
- Patterns in use: `SyncRunner.sync_many` (all streams download at once, pages ingested in order),
  `ThreadPoolExecutor.map` for lookups (order-preserving), the LLM gateway's `_lock` around its session use so
  model calls can overlap (`SOC_LLM_CONCURRENCY`, default 4), `ConnectorRegistry` builds connectors under a lock.
- Every outbound call goes through the connector's `TokenBucket` (thread-safe), so parallelism never exceeds a
  vendor's rate budget. `Retry-After` is honoured but capped at 120 s. 401 -> the token is renewed once
  (`transport.reauthenticate()`), 403 -> `PermissionDenied`, never retried.

**Connector sync semantics** (a new connector must follow them; `test_connector_conformance.py` checks every one)
- `fetch_page` returns `Page(records, next_cursor, has_more=...)`. On the **last** page of a stream set `reset=True`:
  `next_cursor` is then where the NEXT sync starts - a watermark (`Watermark.of(self, key)`: `start(cursor)` gives the
  time to ask from, `see(records, field)`, `finish()`) for event streams, or `None` to read an inventory in full. Never
  leave a continuation token (next link, page token, offset, page number) as the resume point.
- Normalisers tolerate any missing or null optional field; a record without its identifier raises `ValueError` via
  `need(rec, "id")` (not a KeyError) - the message must say "identifier".
- Fields of the wrong type are handled before your parser runs: `BaseConnector.__init_subclass__` wraps `normalize`
  so each record is first conformed to the stream's shape learned from the connector's fixtures
  (`connectors/conform.py`), and coercions are reported per sync (`connector.data_quality`). So the fixtures must show
  each stream's real shape. `parse_ts` never raises (placeholder dates and odd epochs read as None).
- Add the stream to the paging table in `test_connector_conformance.py` (or `NO_PAGING` with the reason), or put
  `PAGING_TESTED = {(name, stream)}` in its own `test_connector_<name>.py` (what `connector new` generates).
- Declare **every** setting a connector reads as a `ConfigField` with its `kind` (url, bool, int, choice, map, list,
  email, path): the strict checker rejects undeclared settings and the console draws its form from them.
- Declare what the connector provides (`provides=`, capabilities from `connectors/capabilities.py`), mapping its own
  field names onto the contract's where they differ. `test_capabilities.py` checks every declaration on the
  connector's own fixtures (stream exists, only the contract's record kinds, mapped fields present). A workflow must
  never name a product: ask for a capability.

**Connector configuration in force** = `config/connectors.yaml` + the active `ConnectorConfigVersion` (console).
- The API's `registry()` is a `_Registry` object (still has `cache_clear()`): it re-reads the active version every
  `SOC_CONFIG_RELOAD_SECONDS` (5) and rebuilds on a change or another database. Approve / pause routes clear it.
- Stages: `fake` (fixtures) / `record` / `read` (no actions) / `recommend` (actions capped at L2 via
  `PolicyEngine.decide(ceiling=)`) / `automate`. `mode: live` = `automate`.
- `enabled_names()` = switched on **and** usable; `configured_names()` = switched on. Use `enabled_names()` before
  `get(name)`; a broken connector raises `ConfigError` from `get` and is skipped by `enabled()` / `action_registry()`.
- Never store a secret value in a config version: only `${VAR}` references (enforced; tests check exports and rows).
- `SyncRunner` commits after every page (one savepoint per page). Do not wrap a sync in a caller's savepoint or rely
  on rolling a sync back.

**LLM use**
- Call through `LLMGateway` only (`grounded()` / `complete_json()`), passing computed figures as evidence with ids.
- Citations are validated; uncited claims and figures not in the cited evidence are dropped (numeric-fidelity
  guardrail). Internal identities are pseudonymised by `Redactor` and restored.
- Always provide a deterministic fallback path - the platform must behave identically (figures, verdicts, actions)
  with the LLM off. Catch `BudgetExceeded` around `complete_json` (the usage policy raises it for every refusal).
- Model JSON is untrusted input: read lists with `model_list`, enumerated words with `model_choice`, citations with
  `model_ids` (`llm/gateway.py`). `x in {..}` on a model value raises when the model sends a list.
- A route that calls the model on a person's behalf builds its gateway with `llm(s, p)` (their limits apply) and
  returns `_with_notice(out, gw)`; scheduled work uses `llm(s)`. A new feature name goes into
  `usage_policy.KNOWN_WORKFLOWS` (tier, who triggers it, description) or it cannot be configured.
- Providers implement `complete(system, user, *, tier, max_tokens=None, model=None)`; the gateway passes the cap and
  the chosen model only to providers whose signature accepts them. Code asks for a size (small for routine narrative,
  large for summaries / deep analysis / reports); the AI usage policy maps each feature to a model by name
  (`usage_policy.models()`: `SOC_LLM_MODELS`, default gpt-4.1-nano / gpt-4.1-mini / gpt-4.1).

**Diagnostics and audit**
- Every request / job run / CLI command runs under a trace id (`core/observability.TRACE`); audit events, access-log
  rows, model calls and job runs store it. Code that starts work outside a request (a new background thread, a new
  job type) wraps it in `traced(new_trace("..."))`.
- Log through `observability.event("name", **fields)` (structured, trace-stamped, secrets masked) for anything an
  operator would want to see; never log a secret, a query string or a request body.
- Every successful write request is audited: `db_session` appends a generic `api.<method>` event when the route's code
  wrote none (it counts `session.info["soc_audited"]`). Prefer a specific `AuditLog.append` in the service anyway.

**Security**
- Routes declare `Depends(need(Perm.X, "domain"))`; record-level scope checks in handlers (`_case_in_scope`).
- **Scope is per role**: `p.in_domain(d)` is *visibility* (union of roles); what `p` may *do* in `d` is
  `p.acting_in(d).can(perm)`. `need(perm, domain)` already returns the acting principal; a handler that writes to a
  case/action of a domain not fixed by its route must pass `p.acting_in(case.domain)` to the service. Actions requested
  on a case carry the case's domain; `ActionService` re-judges every decision in the action's domain.
- Human-only permissions (approvals, policy, access management, rollback) never go to API-key principals.
- Separation of duties compares identities with `auth.same_person` (case-insensitive), never `==`.
- Routes answer a service's exception through `_err`: it never returns a database error's text (SQL and parameters)
  and maps busy / invalid / conflict to 503 / 400 / 409. Don't write `HTTPException(400, str(exc))` for a bare
  `Exception`. Every free-text field of a request body has a `max_length` (it is stored and audited).
- UI: interpolate with `esc()`; clicks go through `data-fn` + the `ALLOWED` map (no inline handlers, strict CSP).
- Nothing fetches URLs taken from e-mail content (no SSRF surface) - keep it that way. The only configurable
  outbound destinations are connector endpoints and `SOC_NOTIFY_WEBHOOKS` (HTTPS only, from settings); never store,
  log or return a webhook URL (it holds a credential) - use `Channel.label` (`kind:host`).
- Error handling: no silent `except: pass` anywhere (ruff enforces). A catch-all must log or record the failure and,
  outside the resilience-boundary folders listed in `pyproject.toml`, carry `# noqa: BLE001 - <reason>`.

**Style**: ruff with the project config in `pyproject.toml` (line length 120). Match the surrounding code's density
of comments: short, explaining *why*. Tests read like specifications (`test_<behaviour_in_words>`).

---

## 6. Testing: how it is organised and what not to break

- **Fixtures** (`tests/conftest.py`): `db`/`session` (fresh in-memory DB), `ESTATES = ["demo", "seed7", "seed23", "handoff", "amc"]` (`amc`: an Indian asset manager, `--amc --messy`),
  `estate_configs` (builds variant estates once per session), `estate_env` (points fixtures, suppliers, org domain at
  an estate and resets caches). Tests default to `SOC_EMBEDDED_SCHEDULER=0` and temporary raw/report dirs - tests
  must never write into the project folder.
- **PostgreSQL parity**: `SOC_TEST_POSTGRES` maps every SQLite URL to a fresh PG database. Plain SQLite runs enforce
  PG rules via listeners (over-long strings except `BoundedText`, 32-bit Integer overflow, NUL in query params) -
  a `PostgresRuleViolation` in a test means production would fail.
- **Test files by concern**: `test_demo_rehearsal.py` (defects found by rehearsing the demo as written: no write lock across model calls, a failing model reads like no model, plain words on screen), `test_consistency.py` (same figure on every surface; re-runs change nothing; LLM on/off
  identical; every GET route × 7 roles; write-route fuzzing; references resolve), `test_time.py` (clock travel),
  `test_pentest.py` (24 attack tests incl. round 2: per-role scope, ReDoS), `test_properties.py` (Hypothesis), `test_scheduler.py`,
  `test_audit_concurrency.py`, `test_generalisation.py`/`test_variants.py` (no demo names leak on other orgs),
  `test_story.py`, `test_phishing.py` (incl. a latency test that fails if lookups become sequential),
  `test_incident.py`, `test_vulnerability.py`, `test_intelligence.py`, `test_report_builder.py`, `test_api.py`,
  `test_access_security.py`, `test_resilience_security.py`, `test_connectors.py`, `test_core_*.py`, `test_jobs.py`,
  `test_notify.py` (webhooks), `test_schema.py` (column addition on both engines), `test_cli.py` (`reset-demo`),
  `test_connector_conformance.py` (every connector: vendor paging, resume, 429 / 401 / 403, missing and null fields,
  Sentinel / Jira / SIEM-push content), `test_volume.py` (cost per record and per new host stays flat; savepoints per
  page; interrupted backfill resumes), `test_traffic.py` (pool, 503 under saturation, a real multi-process server
  under concurrent analysts), `test_recording.py` (record-and-sanitise leaves no identity and replays),
  `test_real_world.py` (an empty tenant; every tool down at once - every pipeline, screen, report still works),
  `test_observability.py` (trace ids, write-audit guarantee, model-call diagnosis, job traces, log lines, masking),
  `test_llm_usage.py` (budgets, per-person limits, per-feature model by name, model list and pins, answer caps,
  model advice, the model check, the admin API),
  `test_connector_admin.py` (isolation, strict config, stages, preflight, propose / approve / pause / restore /
  export / import through the store and the API, hot reload, supplier / sanctioned lists, the scaffold),
  `test_data_tolerance.py` (malformed vendor fields and times, SIEM batches, ownership CSVs, unreadable e-mail, settings, policy documents),
  `test_commit_before_response.py` (commit before reply, real server),
  `test_handoff_scenarios.py` (the data handoff's acceptance scenarios and correlation rules - see
  docs/DATA_HANDOFF_RECONCILIATION.md), `test_handoff_estate.py` (the workbook estate: volume, benign share, replays,
  reserved addresses only, every scenario's ground truth on the real pipelines), `test_connector_defender_identity.py` / `test_connector_rapid7.py`
  (per-connector paging and behaviour),
  `test_high_availability.py` (database blob store, migration, lease renewal / takeover / stuck release, poison items,
  schema race, liveness / readiness, Entra key outage, one sync per stream, raw payload opt-in),
  `test_deployment_manifests.py` (the Kubernetes package: replicas, probes, pod security, secrets, overlays render;
  digests / commit SHAs everywhere; schema rights only in init-db; Compose production defaults),
  `test_go_live_hardening.py` (fail-closed settings, dev sign-in never with live tools, LLM allow-list, credential
  origin, Bearer service keys, alert metrics, audit anchors),
  `test_value_scorecard.py` (benefit KPIs, baselines, capacity, permissions),
  `test_watchlists.py` (Excel / CSV parsing incl. an openpyxl-written workbook in `tests/data/`, hostile files,
  matching on every case kind, no outside-address match, lead-only + audited changes, nothing decisional moves),
  `test_tuning.py` (draft keeps only what the request says and the data holds, preview, two leads, per-domain
  rights, guardrails, QA sample, pause on a threat, revoke / expiry, noise threshold, raise without a verdict change,
  exercises out of the noise statistics, auto-close effect and suggestion, no stacked boosts, vulnerability weights /
  SLAs as previewed with KEV + exposed kept P1, usually-rejected actions suggested / capped / labelled, the API),
  `test_ownership.py` (forgiving headers, unusable rows named, exact > pattern > subscription, cloud / type narrowing,
  versions and audit, permissions, fills the CMDB's gaps without overriding it, the console API),
  `test_audit_export.py` (every format, re-verifying an export outside the platform, filters, formula guard, scope),
  `test_report_style.py` (brand, Word / PowerPoint templates incl. .dotx / .potx, logo, writing guide in prompts only,
  style packs, hostile files, permissions, preview), `test_tool_onboarding.py` (vendor API behaviour found by checking
  every connector against its documentation: MDE findbyip form, Entra devices / partial lookups / Graph limits, RTR
  async output and read-only commands only, NVD date windows, Avanan token expiry and token-less answers, quotes in
  names escaped in every OData / FQL query and URL path), `test_report_design.py` (house style:
  header / footer / page fields, charts, no 'None' / 'n/a', 16:9 decks),
  `test_live_wire.py` (every connector built as a live tool - `manifest.live_transport`, real `HttpTransport`, real
  sign-in code - answered over HTTP from the fixtures: same records as fake mode, credentials on every request; a
  sign-in that cannot complete is a connector error; next links only to the tool's own hosts),
  `test_live_llm.py` / `test_live_public_feeds.py` (opt-in).
  `test_capabilities.py` (every declaration holds on the connector's own data; providers only switched-on tools; the
  EDR control measured from whichever EDR product is connected, and from two at once; field maps; the DLP workflow
  syncs by capability; the product-name constants are gone; the matrix and `capabilities --check`),
  `test_declarative.py` (a definition re-expressing Trellix gives the same records; the example across pages; a
  declared tool used end to end through its capability; every refusal; next link to another host; paging cap; bad
  definitions left out; `connector validate`).
  NAM build: `test_connector_nam_stack.py` (paging and resume of the five new connectors, one device across four
  tools, nothing added to the other workflows), `test_dlp.py` (decision table, destinations, the pipeline on every
  estate, never-automatic list, injected message text, model decisions stored / discarded / off, analyst rulings,
  batches), `test_dlp_investigator.py` (menu only, budget, rules fallback, read-only, citations), `test_dlp_tuning.py`
  (suggestions, preview, refusals, two leads, engineer, verification), `test_config_snapshots.py` (export, drift,
  planned / unplanned, before / after with the score), `test_scope.py` (the NAM scope offers no inherited tool, job,
  route, screen or report section; typos still caught), `test_ciso.py` (levers and movement from the factors, DLP week,
  people, audit chain as verified, brief states only computed figures, the CyberDome reports), `test_crosstool.py`
  (one case per person, severity from agreement, actions recommended, text changes nothing, every estate, EDR
  regression), `test_posture_weights.py` (document checks, recomputable score, two leads, API), `test_comply_pilot.py`
  (catalogue checks, evidence never 'compliant', two-person catalogue, reportability and clocks, cited draft, audit
  pack, pilot KPIs, baseline / targets / outages), `test_decisions.py` (targets, two-lead promotion, decide refused, demotion on agreement drop and on
  outcome shift), `test_controls_posture.py` (coverage, silent / stale measured from the tools' own times, tool
  health, the score recomputed from its factors, daily trend), `test_dlp_api.py` (routes, scopes, CISO view = the
  screens behind it, jobs), `test_pentest_nam.py` (round 39: who decides with MFA, service keys, racing approvals
  decided once, strict regulatory input, hostile documents, sender text never a fact, manual vs scheduled runs, audit
  pack readers, cross-domain screens). The NAM browser tour is `scripts/ui_tour/tour_nam.js`.
- **Comparing two runs figure-for-figure**: freeze the clock (`frozen_clock` fixture sets `SOC_CLOCK_FREEZE`) - risk
  decays with time, so a slower run otherwise rounds differently.
- **New behaviour needs a test**; a bug fix needs a regression test that failed before the fix. Don't hard-code
  demo-specific values in new tests - derive from settings/data or run over `ESTATES`.
- Current counts (keep docs in sync when they change): NAM build round 39: 1,181 passing on SQLite (18 skipped) and 1,178 on PostgreSQL
  (21 skipped), 1,199 collected; 118 of 122 features verified with `--browser` (the 4 others are opt-in: network / LLM). Inherited figures before it: 945 platform tests passing on SQLite and 942 on PostgreSQL (963 collected; skips: 14 opt-in live tests, 3 per-estate repeats of input fuzzing, and database-specific checks - 1 on SQLite, 4 on PostgreSQL), 205
  engine tests, 108/108 features verified with `--browser --engine --live --llm` (round 25); the go-live round's
  offline run: 104/108 (the 4 opt-in live features need `--live --llm`, which calls the real model).

---

## 7. How to extend

- **A tool with a plain REST / JSON API**: a definition file in `config/connectors.d/` (see
  `connectors/declarative.py` and the example), `connector validate FILE`, then switch it on - no code. Anything it
  cannot express (actions, look-ups, unusual sign-in or paging) needs a code connector:
- **A connector**: start with `python -m soc_platform connector new <name> --category <cat>` (writes the module,
  fixtures, paging test and a switched-off config entry) and finish with `connector check <name>`. By hand: add
  `soc_platform/connectors/tools/<tool>.py` exporting `MANIFEST` (name, kind, config fields with
  `secret=True` / `kind` where relevant, factory, `fake_settings`, fixture file, action factory). Implement `streams`,
  `fetch_page`, `normalize` → `NormalizedRecord`s (entities with strong `keys` + weak `hints`, events with `refs`),
  optional `lookup`. Add `soc_platform/fixtures/<tool>.json` routes (`FixtureTransport`: method, path regex, listed
  params only, `~` regex / `*` any, optional `body_contains`). Add it to `config/connectors.yaml`, a test in
  `test_connectors.py`, its `provides=` declaration (every workflow that reads that capability then uses it with no
  other change); regenerate `docs/CONNECTORS.md` (`scripts/build_connector_docs.py`) and, for a NAM tool, add it to
  `scope.NAM_CONNECTORS` and a section in `docs/DEPLOYMENT_GUIDE.md` §5.
- **An action**: a `ConnectorAction` in the connector's action factory (with `preconditions` and `reverse_type` if
  reversible), a policy entry in `core/policy.py:DEFAULT_POLICY` if it needs a non-default level/limit/four-eyes,
  and a test that it is recommended (not executed) by default.
- **A correlation rule**: a method in `intelligence/correlation.py` returning `Insight` with evidence, `dedupe_key`,
  severity, next steps; register it in `run()`; test the positive and negative case.
- **A report data source**: a `src_<name>(ctx)` in `reporting/builder.py` returning facts (label, value), optional
  table and a deterministic writer; add it to `SOURCES`. Figures come only from here, never from the model.
- **A job**: add to `jobs.JOBS` (env var + default interval) and `_body`; it must be idempotent.
- **A setting**: read it in `config.py` (or `os.environ` where it's operational), document it in
  `docs/OPERATIONS.md`, add it to `deploy/docker-compose.yml` if production-relevant.

---

## 8. Documentation map (who owns what)

The docs are **NAM-specific** (round 39): the inherited platform's docs were rewritten for NAM or removed (they stay in
git history). Keep them about NAM's product; the inherited modules appear only as "switched off in the NAM scope".
`docs/README.md` is the index.

| Doc | Owns |
|---|---|
| `README.md` | overview of CyberDome for NAM, quick start, doc index, third-party data attribution |
| `docs/ARCHITECTURE.md` | what runs where, components, jobs and their order, every flow step by step, data stores, screens - update when a module, route, job or connector changes |
| `docs/ENGINEERING.md` | every engineering choice: the platform core and the NAM modules (§9A), security, reliability, testing, the decision log (§25.1 NAM, §25.2 core) |
| `docs/FEATURES.md` | screens and features, with the NAM tour's screenshots (`docs/screenshots/n*.png`) |
| `docs/AI_AND_AUTONOMY.md` | the model's features, who decides what, the ladder, guardrails, residency, budgets, cost measurement (no unmeasured cost figures) |
| `docs/CONNECTORS.md` | generated by `scripts/build_connector_docs.py` (NAM-scope connectors only) - regenerate after changing a connector |
| `docs/DEPLOYMENT_GUIDE.md` | deploying into NAM's environment: hosting / residency, database, secrets, Entra, each NAM tool, the LLM gateway, rollout by phase, first syncs, go-live checklist, open decisions |
| `docs/OPERATIONS.md` | settings, jobs, monitoring, access, backups, every module's operation |
| `docs/HIGH_AVAILABILITY.md` | no single point of failure, the Kubernetes package, backups, failover drill |
| `docs/SECURITY.md` | threat model, NAM's decision rules, penetration tests (round 39 in full), supply chain, operator responsibilities |
| `docs/FAILURE_MODES.md` | failure → detection → behaviour → status, NAM's tools first |
| `docs/RUN_GUIDE.md` | running, accounts, sample data, driving each module, reset, Docker, troubleshooting |
| `docs/PRESENTER_GUIDE.md` | the walkthrough, every formula (Dome Score, coverage, the DLP decision table), hard Q&A, numbers to remember |
| `docs/REQUIREMENTS_TRACEABILITY.md` | NAM requirement → implementation → test |
| `docs/TEST_REPORT.md` | test rounds, newest first ("Round N" at the top); NAM rounds in full, the core's history summarised |
| `docs/FEATURE_VERIFICATION.md` | generated by `scripts/verify_features.py` - don't hand-edit |
| `docs/client_review/` | the review pack for NAM (9 documents, `diagrams/` generated by the SVG script in the round-39 notes; Word edition via `scripts/build_review_pack.py`) |

Not in git: `docs/client_deck_nam/` (NAM's sources), `docs/client_review/word/` and `deck/` (generated / old),
`docs/DATA_HANDOFF_RECONCILIATION.md` and `docs/TEAM_STRUCTURE_PLAN.docx` (the earlier project's, left on disk).
`scripts/build_component_diagram.py` draws the full-scope platform and is not part of the NAM docs.

---

## 9. Before committing (checklist)

1. Relevant test files pass; for core/cross-cutting changes run the full suite (and on PostgreSQL for DB-touching
   changes).
2. `ruff check . --exclude .venv,node_modules` → "All checks passed!"; bandit clean; JS: `node --check` on changed files.
3. Docs updated (§8), including test counts and any measured numbers you changed.
4. `git log --oneline -5` / `git status` - account for the user's own commits (rule 3).
5. Secret scan of staged files against `.env` values, without printing them (`python scripts/precommit_scan.py` does
   this and the banned-name scan; the snippet below is the same check):
   ```python
   import subprocess; from pathlib import Path
   vals=[l.split("=",1)[1].strip().strip('"') for l in Path(".env").read_text().splitlines()
         if "=" in l and not l.startswith("#") and any(k in l.split("=")[0] for k in ("KEY","SECRET","TOKEN","PASSWORD"))]
   staged=subprocess.run(["git","diff","--cached","--name-only"],capture_output=True,text=True).stdout.split()
   print([f for f in staged if Path(f).is_file() and any(v in Path(f).read_text(errors="ignore") for v in vals if len(v)>=12)])
   ```
6. Banned-name scan (rule 1): `git grep -n -I -i -E "<banned names>" -- .`.
7. Commit message with the attribution line (rule 4).

---

## 10. Gotchas that have already bitten

- **Shell escaping on Windows**: heredocs in Git Bash turned `"\n"` inside Python strings into real newlines and once
  wrote a literal NUL byte into `app.py`. For multi-line patches write a `.py` file with the Write tool and run it;
  after editing, `ruff check` catches broken strings.
- **PowerShell 5.1**: no `&&`, no `Invoke-RestMethod -Form` (use `curl.exe -F` for uploads), `Set-Content` defaults
  to ANSI (pass `-Encoding utf8`).
- **Git Bash paths**: `mktemp -d` gives `/tmp/...` which Windows Python cannot open in a SQLite URL - use the
  scratchpad's `C:/Users/...` path.
- **SQLite vs PostgreSQL**: SQLite accepts over-long text, NUL and 64-bit ints in Integer columns; PostgreSQL rejects
  them. The test listeners catch this - don't disable them.
- **Narrow ruff runs**: `ruff --select RUF100 --fix` with only a few rules enabled deletes `noqa` comments that are
  still needed. Always check RUF100 with the full rule set.
- **Module-level caches in tests**: `get_settings`, `app.registry`, `db._default`, the rate limiter and the LLM
  breaker are process-global; fixtures that change env must reset them and restore on teardown (register the
  finalizer *before* setup so a failed setup can't leak its environment).
- **Sweeping every route in a test with one token** hits `/auth/logout` and revokes it - use a fresh token per route.
- **Background writers bind to a database when the work is queued**, not when flushed (the access log once wrote rows
  into the wrong database).
- **Leases are released only after the run is recorded**, due-ness is re-checked after taking the lease, and taking a
  lease is a compare-and-swap whose insert race returns "not acquired" - each closed a real race.
- **A compare-and-swap version must change on every write.** `updated_at = utcnow()` repeats within one Windows
  clock tick, so a stale writer still matches (ABA). Write `jobs.next_version(seen)` (always later than what was read).
- **The engine reads the project's `.env` itself**, so anything there that changes behaviour makes a laptop and a
  container disagree (QR decoding on in `.env`, off in Docker: 0.82 vs 0.92 for one e-mail). Pin verdict-relevant
  engine settings in `EngineAnalyzer.OFFLINE_SETTINGS`.
- **Job order matters on a first start**: everything is due at once and runs in `jobs.JOBS` order - vulnerability
  first, or incidents are scored without exposure data. Open incidents are reassessed when new KEV exposure appears
  (`IncidentService.reassess_open`); evidence creation is idempotent so reassessments never duplicate rows.
- **A control the docs claim must exist in code.** Writing the client review found three: no action was marked
  `destructive` (so "never autonomous" was not enforced), Microsoft apps could not use certificate credentials, and
  internal IPs / the organisation's own domains went to outside threat-intel services. Check the code before writing a
  security claim; mark new irreversible actions `destructive=True`.
- **Connector setting descriptions are shown by the API** (`/api/v1/connectors`, the console form): an example
  value with a demo name (`adm-jane`) leaked into every generated estate and failed the no-demo-names test. Use
  neutral placeholders (`first.last@example.com`).
- **Learned record shapes are cached per process** (`connectors/conform.py`): a test that switches estates must call
  `reset_shapes()` (`estate_env` does) - a shape learned against another estate's fixtures (a renamed mailbox route)
  was "unknown" and silently disabled type coercion for later tests.
- **Scheduled syncs read alerts, inventory and Entra directory audits only**; activity (sign-ins, DNS, PAM audits,
  domain logons) arrives through investigation look-ups. A rule that needs another stream must get it synced
  (`IncidentService` `AUDIT_STREAMS`) - the consent rule never fired in production until directory audits were.
- **Fixture data is dated; processing stamps the wall clock.** Risk's "now" is the latest observation, so the gap to
  the fixtures' day grows with the calendar: a test comparing two points in time must allow activity to leave the
  window (`test_time.py` broke 23 days after the fixture date).
- **The dependency lock is resolved on Windows**; CI runs on Linux. `supply_chain.py check` compares versions of the
  packages both have (colorama / uvloop exist on one side only) - never compare the lock text across platforms.
- **Never put the confidential-name pattern in a tracked file** (a workflow, a test, a script): it is itself the
  banned text. It lives in `.git/info/banned-names` locally and in the `BANNED_NAMES_REGEX` secret in CI.
- **The kill switch stops autonomous execution only** (caps the policy at L3); a human-approved action still runs. To
  stop every write to a tool, pause the tool. Describe it that way.
- **Wall-clock windows over vendor data age out.** "Newly KEV-listed" once meant "last 14 days of real time", so the
  demo's finding vanished a week later; anchor such windows to the data (the catalogue's latest addition, capped at
  today), as risk does.
- **`time.monotonic()` is uptime on Windows**: a cache initialised to 0 and "refreshed after 300 s" skipped the first
  check after a reboot (`/health` audit_chain null). Start caches as "never refreshed" (None).
- **"First insert" of a `system_flags` row races** (two threads both see no row): catch `IntegrityError` and treat
  it as lost / retry onto the existing row (`jobs._lease`, `Scheduler._beat`, `audit._lock_chain`). Two writers of
  one row must not read-modify-write: use a compare-and-swap on `updated_at` (`_lease`, `_write_beat`).
- **FastAPI runs a `yield` dependency's cleanup after the response by default.** For `db_session` that meant the
  commit came after the reply (an upload's case was missing from the next list in 28 of 40 tries). Every new route
  must use `Depends(db_session, scope="function")`; `test_commit_before_response.py` fails otherwise. TestClient
  cannot show this race - only a real server can.
- **SQLite blocks all writers during a long transaction** (an LLM call inside a request): background writes such as the
  heartbeat wait or fail. Commit before slow model calls (jobs and bulk endpoints do), and never infer "dead" from
  one missed write - `/health` asks the in-process scheduler (`Scheduler.alive_here`).
- **Rehearse the demo as written, with the model on and the scheduler running** (`test_demo_rehearsal.py`). The tour holds the
  jobs back and has no model, so it could not see the intelligence job holding SQLite's write lock across 64 s of model calls: the
  Intelligence screen answered 503 and the job lost its own lease. Narrate through `IntelligenceService.narrate_committing` after
  committing the findings. A model *failure* must read like no model at all: `deterministic_grounded`'s "N evidence item(s)" text is
  a fallback for claims, not something to show as a summary.
- **Thread exceptions only warn in pytest** (`PytestUnhandledThreadExceptionWarning`) - a crashed background thread
  can hide behind a green test. `test_scheduler.py` turns them into errors; do the same in new concurrency tests.
- **No randomness or speed in tests.** Generated data must be byte-identical for the same seed (never `make_msgid()`,
  random boundaries, `uuid4()` or wall-clock time in generated content: the auto-close QA sample is keyed on content
  hashes, and random Message-IDs once made a retention test fail at random). Prove parallelism by counting calls in
  flight, not by elapsed time; give waits long deadlines that end as soon as the condition holds.
  `SOC_TEST_POSTGRES` set but empty now aborts the run - a silent SQLite fallback looked like a PostgreSQL pass.
- **Environment settings are strings.** `bool("false")` is True and `**"{...}"` crashes: parse booleans and JSON
  settings explicitly (a Rapid7 `verify_tls` and the SIEM `field_map` both had this bug).
- **Never name the client's in-house LLM platform** in the repo - its name contains the client's abbreviation. Call it
  "the client's in-house LLM (gateway)".
- **Check a vendor's documentation, not only its happy path, before calling an integration done.** The onboarding
  review found calls that fixtures happily answered but a tenant would refuse: Graph's per-user device lists reject
  application permissions (and one refused read failed the whole identity lookup), MDE's `findbyip` is an OData
  function call, CrowdStrike RTR commands are asynchronous (output is read back by `cloud_request_id`), NVD needs both
  `lastModStartDate` and `lastModEndDate` within 120 days. A fixture must answer only the request the vendor accepts.
- **Escape every investigation value that enters a vendor query.** Host, user and indicator names were put straight
  into OData / FQL filters and URL paths: `o'brien@...` broke the Graph look-ups, and a crafted name could rewrite the
  filter. Use `odata_str` (Graph, MDE), `fql_str` (CrowdStrike) and `path_part` (URL segments) from
  `connectors/tools/_common.py`. Uploaded XML is checked with `core/text.unsafe_xml` (DTD / entity, or a UTF-16 / 32
  encoding that would hide one from a byte check).
- **Equal timestamps on Windows**: the clock advances in ~15 ms steps, so "newest first" by time alone is random
  within a tick - make times strictly increasing (case notes, `JobRun.ordinal`, `decisions._after`: a stage change
  is later than every ruling before it, and every ruling after it later still - drift once counted earlier rulings).
- **A case the incident pipeline did not cluster is not its to reassess**: cross-tool cases live in `incident` but
  `reassess_open` and `/incidents/{id}/investigate` leave them alone (a re-run once added unrelated actions).
- **`demo` expectations** in the guides (NAM scope: 3 DLP + 3 cross-tool cases, 7 approvals, 3 personal-data assessments; full scope: 7 phishing + 6 incident (3 cross-tool) + 3 DLP cases, 43 approvals, 6 open vulnerabilities, 14 DLP alerts, 6 of 10 devices fully covered; the same with or without the ML engine) are real; if you change fixtures or
  pipelines, re-count and update RUN_GUIDE (§4.1 quotes the demo's output) / PRESENTER_GUIDE (§4).
- **Browser tour** runs the real scheduler with `SOC_SCHEDULER_START_DELAY=86400`: the heartbeat is live (no
  "Scheduler stopped" banner in screenshots) but no job runs to move figures under the screen-vs-API check. It gives
  the server a local webhook receiver so the Notifications card has a channel, and uploads the stored-XSS probe only
  after the screenshots. It fails on `undefined` / `NaN` / `[native code]` in any screenshot. `docs/screenshots` is
  refreshed only deliberately: `run_browser_tour(with_llm=True, shots=<tmp>)`, then copy the PNGs.
- **Job bodies may commit mid-way.** The incident and phishing jobs commit the investigated cases, then call
  `narrate_pending` (parallel model calls). Anything that reads a case must cope with
  `assessment["narration_pending"]` (deterministic explanation in place, model text still to come). Pass
  `narrate=False` only where a later `narrate_pending` is guaranteed (job or bulk endpoint).
- **Notifications are deduplicated by (`dedupe_key`, `severity`, `channel`)**: don't delete `notifications` rows in
  retention, or every open finding is sent again.
- **PostgreSQL rejects what SQLite accepts, again**: `SELECT DISTINCT ... ORDER BY <column not selected>` is an
  error on PostgreSQL only (it once failed every DNS record of a sync there). Run the relevant tests on PostgreSQL
  for any new query with DISTINCT, GROUP BY or window functions.
- **A savepoint per record** ran PostgreSQL out of lock memory on a large sync ("out of shared memory - increase
  max_locks_per_transaction"): each savepoint holds a lock until the transaction ends. Batch (one per page) and
  commit per page; never loop thousands of `begin_nested()` in one transaction.
- **A query that grows with the estate** is the scale bug to look for: per-candidate queries (each new host loaded
  every host behind the NAT address), `LIKE 'x%'` with no usable index, SQLite picking a low-selectivity index.
  `test_volume.py` counts statements per record and per new host; `measure_scale.py` shows the stage.
- **Risk is cached** (`RiskEngine.top`): reuse is keyed on a data fingerprint plus `_GENERATION`, which every flush
  touching Entity / Relation / CaseEntity / Case / ConsolidatedFinding / VulnIntel bumps. A new input to risk must be
  added to both, or the brief and Intelligence screen show stale figures.
- **uvicorn workers on Windows**: terminating the master leaves its worker processes running (they keep the port and
  the database open). Stop the process tree (`taskkill /PID <pid> /T /F`, the specific PID) - `load_test.py` does.
- **Shell heredocs turn `\b` into a backspace** (and `\n` into a newline) inside Python strings: write patch files
  with the Write tool.
- **ReDoS in e-mail parsing**: patterns like `<[^>]+>`, `<a…>(.*?)</a>`, `[\w.+-]+@…` or `\d+[.,]?\d*` are
  quadratic on hostile input (one 240 KB message took 16 s; 25 MB would take hours). Bound every run (`{1,64}`), stop
  scans at the next tag (`<[^<>]*>`), anchor with a look-behind; `test_hostile_email_content_costs_linear_time` guards it.
- **`X-Forwarded-For`**: proxies append, so only the right-most untrusted hop is the client (`_client_ip`). uvicorn's
  own proxy-header handling is off (`serve` passes `proxy_headers=False`) so only the app's tested rule applies.
- **Settings are validated as a whole** (`settings_check.py` SPEC): a new `SOC_*` setting must be added there, or
  `config check` reports it as unknown and a typo in it is never caught.
- **One malformed item must not fail a batch**: the SIEM push once refused a whole batch for one alert without an id
  (the sender would retry forever). Route pushed records through `SyncRunner.ingest_records`.
- **Vendor paging caps**: Falcon's query APIs refuse offset + limit past 10,000 (hosts use the scroll query, alerts
  restart from their watermark). Check a new vendor's documented maximum offset before using offset paging.
- **An outage must degrade, not fail**: a job, screen or report that reads a tool live catches `ConnectorError`
  and says "unavailable"; a feed outage keeps the last known values (an empty KEV answer once would have cleared
  every KEV flag). `test_real_world.py` runs everything with every tool down.
- **A test that runs `python -m soc_platform serve` must fail before uvicorn starts** (the config refusal does): never
  start a real server from a test without the `load_test` / commit-before-response pattern of stopping it by PID.
- **The trace id is stamped by `event()` itself**, not only by the platform's log handler: a host's or a test's
  handler (caplog) sees it too. Tests run with `SOC_LOG_CONFIGURE=0` so the app does not reconfigure Python logging.
- **Event retention** (`SOC_EVENT_RETENTION_DAYS`, 400) deletes old telemetry entities with their keys, hints,
  relations and source records. A new table that points at entities must be added to its "held" set in
  `core/retention.py`, or pruning leaves a dangling reference.
- **Risk "now"** is the latest *event* in the data (`risk.EVENT_KINDS`), not wall time and not a state record: a person,
  host, indicator, finding or ticket is "seen" at every sync, which made "now" the wall clock and aged dated
  activity out 30 days later. Event times must be the event's (a reported e-mail: its Date header / the mailbox's
  received time; a click: its click time) - never the processing time. Incident clustering's 30-day window ends at
  the newest alert. `test_time.py` travels 0 / 45 / 400 days to prove none of it ages out. Open exposures/incidents never decay
  (`STANDING_SIGNALS`); amplifiers fade with their triggers.
- **Nothing durable on a host's disk or in one process.** A path saved by one replica could not be read by another
  (a report built by the scheduler, downloaded via the API). New stored files go through `BlobStore`
  (`core/blobstore.py`), never `write_protected` directly; new state goes in the database.
- **Every process creates the schema on first use, and replicas start together.** Eight SQLite connections opening a
  new file failed on the WAL switch ("database is locked" - busy_timeout does not cover it); both that and
  `create_all` now retry / serialise. A test that builds `Database` objects in threads must construct them first
  (the PostgreSQL test mapping in conftest is not thread-safe), then race only the work under test.
- **Job leases are short and renewed** (`SOC_JOB_LEASE_SECONDS`, 120; `_LeaseKeeper`); "stuck" is a separate
  threshold (`SOC_SCHEDULER_STUCK_SECONDS`, 1800) after which renewal stops so a hung job can be retried. The lease
  holder includes the thread id: a renewal from another thread must pass the job thread's holder.
- **One sync per stream at a time.** Job leases do not cover a manual sync, a refresh or `demo` against a scheduled
  sync: `SyncRunner.sync` takes a per-(connector, stream) lease (`sync_lease:<hash>`), renews it per page, waits up
  to `SOC_SYNC_LOCK_WAIT_SECONDS` for another holder. The first checkpoint insert tolerates a lost race. Callers
  with `commit_pages=False` (tests, pushes inside a request) take no lease. Found by the Docker check, not a test.
- **One item must not fail a job.** The incident and phishing jobs run each item in a savepoint (`jobs._isolated`):
  failures are recorded on the item, retried `ITEM_ATTEMPTS` (3) runs, then left to an analyst.
- **Liveness must not depend on the database** (`/health/live`); readiness does (`/health/ready`). Pointing a
  liveness probe at `/health` restarts every pod during a database outage.
- **Variable names in `submit_raw`**: `ref` is the de-duplication key (`source_ref`); the blob reference is
  `blob_ref`. Reusing `ref` made every replayed report a new submission (caught by `test_phishing.py`).
- **Evidence is written in two places** (`CaseService.add_evidence` and `EnrichmentOrchestrator.enrich`): anything
  that must hold for all evidence (text normalisation, de-duplication) goes in both.
- **Look a host up by the vendor's device id when the platform has it** (`Target.context`): host names differ between
  tools (short name, FQDN, case), and a name-prefix search matches other machines (`web01` → `web010`).
- **Judge outputs against intent, not "no error"**: a functional review found an internet-facing Log4Shell server's
  alert rated medium with no action, an EDR "not finding" the host it alerted on, and "CVSS None" in evidence - all
  with green tests. Run the demo and read what it says.
- **Never call a vendor inside the open transaction.** `_execute` once called the tool after `action.approved` had
  taken the audit chain's row lock: every audited write on the platform waited for the vendor, and a failed commit
  lost the record of an executed containment. The same applies to any new code that calls out while holding writes.
- **`async def` routes run on the event loop.** The upload route did parsing, look-ups, the ML engine and the model
  there and froze its whole process (liveness included). Routes are plain `def` unless they truly await.
- **A setting the deploy files use must work as written there.** `SOC_TRUSTED_PROXIES` was a CIDR in both overlays
  while the code compared strings: nothing matched, and every analyst behind the gateway shared one rate-limit bucket.
- **One `Redactor` per model call.** Its token map is mutated while redacting; a shared one across parallel
  narrations could give two people the same token and restore the wrong name into a case.
- **Dev sign-in mints any role** (`/api/v1/dev/token`): the registry isolates every live tool while it is on
  (outside `SOC_ENVIRONMENT=test`, which the suite's conftest sets). Don't add a way around it.
- **Fake mode never runs the live transport.** The sign-in, URL joining, query encoding and the origin check exist
  only in `HttpTransport` / the auth classes: a token endpoint blocked by the firewall raised httpx's own error
  (the preflight called it a connector defect), and `arm_base` sent Entra's Azure calls to a host its own transport
  refused. A new connector or auth class must pass `test_live_wire.py`; a sign-in goes through `http.token_request`
  / `token_from`, never a bare `httpx.post`.
- **A verifier is not a signing secret.** Break-glass sessions were signed with a key derived from the configured
  *hash* of the sealed secret, so the setting operators are told is safe to hand over could mint an admin session.
  A session now counts only if its id was recorded at the audited exchange (`bg_session:<jti>` in `system_flags`).
  Anything derived only from configuration proves nothing about who holds the secret.
- **A word an analyst sends is checked against the vocabulary** (`cases.ANALYST_VERDICTS`): free text was stored as
  the ruling and counted as "suspicious" by `_bucket`, which feeds agreement, noise and tuning-pause logic.
- **Default-deny applies to the database pods too** (on-prem CloudNativePG in the same namespace): their own network
  policy lets replication, the operator, DNS and backups through. AGIC (Azure) sends from the gateway's subnet, not
  from a namespace: the ingress policy uses an `ipBlock`.
- **Upstream tags move or vanish.** The CI image-scan action's tag was deleted upstream (that step could no longer
  run). Pin actions by commit SHA and images by digest; resolve them with `git ls-remote` / `docker buildx imagetools
  inspect`, never by guessing.
- **The scheduler container has no HTTP server**: it needs the liveness-file health check, not the image's HTTP one
  (Compose had it unhealthy for ever).
- **Patch files, not heredocs, for multi-line edits** - the Bash tool also mangled quotes in long Python heredocs
  (`unexpected EOF`); the Write tool + a `.py` patch is reliable. The Write tool drops trailing spaces, so a patch
  whose search text ends in a space will not match.

---

## 11. Glossary

Estate (a sample organisation's fixtures + corpus + settings) · fake/live mode · canonical schema / NormalizedRecord
· context store · entity resolution (keys vs hints, unresolved queue) · evidence ids (E#, S#/G#/H#/B#/P#/X#, F#, R#)
· L0-L4 autonomy · four-eyes · idempotency key · lease · standing signal · attack story / fingerprint · deep
analysis · grounding / numeric-fidelity guardrail · pseudonymisation · legal hold · self-check · shadow mode · drift
(PSI) · blind spot (ATT&CK stage no enabled tool can see).
