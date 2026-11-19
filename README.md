# CyberDome for NAM

An AI-first layer above NAM's security tools - Forcepoint DLP, Silverfort, Trend Micro, Trellix ePO and the AD / CMDB
export, with Arcon, Cloudflare and NAM's SIEM and SOAR to follow. It runs inside NAM's environment (or an Indian
cloud region), reads the tools through their APIs, resolves every record to one device or one person, and on that
picture:

| Module | What it does |
|---|---|
| **Dome Connect** | Connects the tools (read-only first) and watches their health: agents silent for more than 24 hours, failed or late sync jobs, certificates close to expiry, people the directory import left out; configuration snapshots, before / after a change |
| **Dome Graph** | Checks every device of the AD baseline against each control (EDR agent, DLP agent reporting, disk encryption) and ranks the gaps by the personal data at stake |
| **Dome Agents** | Triages DLP incidents on structured facts with a published decision table; an AI investigator runs read-only look-ups; the AI's own decision is stored beside the analyst's and earns authority per decision type (shadow → recommend → decide), never on text an insider wrote; DLP rule changes and classification-quality findings (OCR, EDM, fingerprints) proposed, approved by a second lead, made by an engineer |
| **Cross-tool cases** | One case per person when two or more tools agree (risky sign-in, data leaving, a control off, an endpoint alert, a privileged account); severity from how many agree; containment always needs two people |
| **Dome Score** | One posture score from a published formula with weights the CISO agrees (two leads approve a change); what would raise it most and why it moved, from its own factors; a monthly board deck and a weekly CISO brief |
| **Dome Comply** | SEBI CSCRF, DPDP and CERT-In control areas mapped to computed evidence (never "compliant"); a breach assessment for every personal-data incident, a person's reportability decision, deadlines from the catalogue, an AI draft; the audit pack |
| **Pilot scorecard** | The pilot's KPIs against NAM's own baseline and the targets NAM sets |

It recommends actions; **a person approves them by default and containment always needs two people**. Every figure,
score and severity is computed in code; the optional AI model - in NAM's environment or an Indian region - explains,
investigates and decides DLP dispositions only as far as each decision type has earned.

The platform core it runs on (connectors, entity resolution, cases, actions, the autonomy policy, the LLM gateway,
audit and access) also contains modules NAM did not ask for; in NAM's deployment (`SOC_PRODUCT_SCOPE=nam`, the
default) they are switched off - not listed, not scheduled, not reachable.

**State:** the NAM connectors run on vendor-shaped sample data with placeholder API paths until each tool's version
and API are confirmed; every figure in the demo is sample data.

## Quick start (local, no credentials needed)

You need Python 3.11-3.13.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements/platform.txt -r requirements/dev.txt
$env:SOC_DEV_JWT_SECRET = "<32+ random characters>"; $env:SOC_ORG_DOMAINS = "acme-demo.com"
python -m soc_platform init-db
python -m soc_platform demo        # the sample estate: 14 DLP alerts, 3 DLP + 3 cross-tool cases, coverage, the Dome Score
python -m soc_platform serve       # http://127.0.0.1:8080 - sign in as lena@acme-demo.com, Lead
```

Full guide: [docs/RUN_GUIDE.md](docs/RUN_GUIDE.md). What to show: [docs/PRESENTER_GUIDE.md](docs/PRESENTER_GUIDE.md).

### Docker

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml --env-file .env up -d --build
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml --env-file .env exec platform-api python -m soc_platform demo
```

The base Compose file is production (Entra sign-in, TLS-verified PostgreSQL, owner / runtime roles); the demo file is
the override. Kubernetes (HA, Azure and on-premises overlays): `deploy/kubernetes/`.

## Console

| Group | Screens |
|---|---|
| Operate | Dome Score (CISO view) · Pilot scorecard · Intelligence · Cases · Approvals |
| Domains | Data protection |
| Insight | Dome Graph · coverage · Dome Connect · changes |
| Govern | Dome Comply · Watch lists · Tuning · Integrations · Automation policy · AI usage · Reports · Access · Audit log |

Light and dark themes; a side menu that folds to icons; every screen checked at five widths and for accessibility.
Screenshots: [docs/FEATURES.md](docs/FEATURES.md).

## Connecting NAM's tools

Each tool is configured on *Integrations* (or `config/connectors.yaml`), checked by a preflight (sign-in, every
stream and its permission, parsing, freshness), approved by a lead, and moved one stage at a time: fixtures →
recording → read-only → recommend → automate. Phases 1-2 run read-only. Per-tool permissions and what is still to
confirm with NAM: [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) and [docs/CONNECTORS.md](docs/CONNECTORS.md).

## Security

| Control | Summary |
|---|---|
| Identity | Entra ID SSO; step-up MFA for every decision; service-account keys that can never approve; sealed break-glass; revocation |
| Authorisation | roles (analyst, lead, admin, automation admin, auditor) + data scope (dlp, incident, all) + separation of duties everywhere |
| Decisions | containment four-eyes always (engine-enforced); weights, catalogue, rule changes and AI promotions by two leads; reportability by a person; exactly-once approvals |
| AI | facts not text; close only where the computed disposition agrees; never-automatic list; citations required; every AI decision recorded; model in NAM's environment or an Indian region, pseudonymised prompts, budgets |
| Data | stored files encrypted (Fernet, rotation); TLS everywhere; retention with legal hold; residency in India |
| Audit | append-only hash-chained audit log, verified hourly, anchored; exports; audit pack |
| Testing | NAM penetration test (round 39), the inherited attack suite, route sweeps, browser XSS probe, bandit, pip-audit, Trivy |

Details: [docs/SECURITY.md](docs/SECURITY.md), [docs/AI_AND_AUTONOMY.md](docs/AI_AND_AUTONOMY.md).

## Tests

```bash
pytest soc_platform/tests -q -p no:cacheprovider                     # the full suite (SQLite)
SOC_TEST_POSTGRES=<postgresql://...> pytest soc_platform/tests -q    # the same on PostgreSQL
python scripts/verify_features.py --browser                          # every feature -> its tests, + both browser tours
```

Results: [docs/TEST_REPORT.md](docs/TEST_REPORT.md), [docs/FEATURE_VERIFICATION.md](docs/FEATURE_VERIFICATION.md).

## Documentation

[docs/README.md](docs/README.md) is the index. In short:

| Document | For |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | what runs where, every flow step by step |
| [FEATURES.md](docs/FEATURES.md) | every screen and feature, with screenshots |
| [ENGINEERING.md](docs/ENGINEERING.md) | how it is built and why, the decision log |
| [AI_AND_AUTONOMY.md](docs/AI_AND_AUTONOMY.md) | what the AI does and may decide, guardrails, limits, cost |
| [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | deploying into NAM's environment, tool by tool |
| [client_review/](docs/client_review/) | the security and architecture review pack for NAM |

## Repository layout

```
soc_platform/
  core/          schema, context store, entity + identity resolution, controls, decisions (earned autonomy), policy,
                 actions, audit, auth, access, scope, crypto, retention, cases
  connectors/    SDK (rate limits, backoff, checkpoints), registry, tools/ (NAM's tools in _paged.py style + the core's)
  llm/           governed LLM gateway (usage policy, redaction, grounding)
  domains/       dlp/ (triage, investigator, rule changes) · incident/ (+ the inherited modules, off in the NAM scope)
  intelligence/  posture, posture_weights, ciso, crosstool, control_coverage, tool_health, config_snapshots, risk, correlation
  reporting/     regimes (Dome Comply), breach, pilot, report builder (docx / pptx)
  api/           FastAPI service, console (static/)
  jobs.py        durable scheduled jobs
  fixtures/      vendor-shaped fixture data for every connector
  tests/         the test suite
config/   deploy/   scripts/   docs/
```

## Third-party data

The inherited phishing content model (`artifacts/phishing/models/content_agent/`, not used in the NAM scope but
still in the repository) was trained with `scripts/train_content_model.py` on public data: the phishing corpus by Jose
Nazario (https://monkey.org/~jose/phishing/, CC BY 4.0), the SpamAssassin public corpus
(https://spamassassin.apache.org/old/publiccorpus/, non-live testing terms) and the "Safe Email" rows of
zefang-liu/phishing-email-dataset (LGPL-3.0). The data itself is not in this repository.
