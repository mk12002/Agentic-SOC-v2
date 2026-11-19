# Run guide - starting CyberDome, loading the sample estate and showing it

How to run CyberDome for NAM on a laptop or in Docker, what the sample data contains, how to sign in as each kind of
person, how to drive each module live, reset between demos, and fix what goes wrong. Deploying into NAM's
environment is [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md); what to say in a demo is [PRESENTER_GUIDE.md](PRESENTER_GUIDE.md).

## Contents

1. [The 5-minute start](#1-the-5-minute-start)
2. [One-time setup](#2-one-time-setup)
3. [Configure `.env`](#3-configure-env)
4. [Start the platform and sign in](#4-start-the-platform-and-sign-in)
5. [What the sample data contains](#5-what-the-sample-data-contains)
6. [Driving each module live](#6-driving-each-module-live)
7. [Using the API directly](#7-using-the-api-directly)
8. [With and without the model](#8-with-and-without-the-model)
9. [A different organisation](#9-a-different-organisation)
10. [Resetting between demos](#10-resetting-between-demos)
11. [Running with Docker and PostgreSQL](#11-running-with-docker-and-postgresql)
12. [Proving it works](#12-proving-it-works)
13. [Troubleshooting](#13-troubleshooting)
14. [Quick reference card](#14-quick-reference-card)

---

## 1. The 5-minute start

If setup (§2) and `.env` (§3) are done:

```powershell
cd "D:\Code_stuff\Agentic SOC NAM"
.\.venv\Scripts\Activate.ps1
. .\scripts\load_env.ps1                  # note the leading dot
python -m soc_platform init-db
python -m soc_platform demo              # loads the sample estate (about a minute without the model)
python -m soc_platform serve             # the whole platform, jobs included - leave this window open
```

Open **http://127.0.0.1:8080**. Sign in with work email `lena@acme-demo.com`, role **Lead**, scope *All domains*:
you land on the **Dome Score**.

---

## 2. One-time setup

**You need:** Python 3.11, 3.12 or 3.13; Git; optionally Node.js 18+ and Chrome or Edge for the browser tours (§12).

```powershell
cd "D:\Code_stuff\Agentic SOC NAM"
python -m venv .venv                      # skip if .venv already exists
.\.venv\Scripts\Activate.ps1
pip install -r requirements\platform.txt
pip install -r requirements\dev.txt       # only for running the tests (§12)
```

If PowerShell refuses `Activate.ps1`: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, once.

The NAM scope does not use the inherited phishing ML engine; do not install `requirements\phishing.txt` for it.

---

## 3. Configure `.env`

The platform reads its settings **from the environment only**; `scripts\load_env.ps1` loads `.env` into the current
PowerShell window (it skips comments, strips quotes, prints only the names it set). The minimum:

```ini
SOC_DEV_JWT_SECRET=<a long random string, 32+ characters>
SOC_ORG_DOMAINS=acme-demo.com
```

Generate the secret with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

| Optional setting | Default | When |
|---|---|---|
| `SOC_PRODUCT_SCOPE` | `nam` | `full` shows the inherited modules too (phishing, vulnerabilities...) - not part of NAM's product |
| `SOC_LLM_PROVIDER`, `SOC_LLM_ENDPOINT`, `SOC_LLM_API_KEY`, `SOC_LLM_DEPLOYMENT`, `SOC_LLM_APPROVED_ENDPOINTS` | none (computed paths only) | to show the model's text and the AI's shadow decisions (§8) |
| `SOC_PORT` / `SOC_HOST` | 8080 / 127.0.0.1 | another port; `0.0.0.0` to open it from another machine (dev sign-in stays local-only) |
| `SOC_DATABASE_URL` | `sqlite:///./soc_platform.db` | a separate database per demo, or PostgreSQL |
| `SOC_RAW_PAYLOAD_DIR`, `SOC_REPORT_OUTPUT_DIR` | `.\data\raw`, `.\data\reports` | where stored files and reports go |

**Don't set** `SOC_ENVIRONMENT=prod` for a laptop demo: production requires Entra sign-in, an encryption key and MFA,
and turns off the dev sign-in.

---

## 4. Start the platform and sign in

### 4.1 Start

```powershell
python -m soc_platform init-db            # creates the tables (safe to repeat)
python -m soc_platform demo               # loads the sample estate (a second run changes nothing)
python -m soc_platform serve              # http://127.0.0.1:8080 - Ctrl+C stops it
```

`demo` prints what it loaded (model off, measured on this build):

```text
[INVENTORY] 41 device / person record(s) from the baseline and control tools
[DLP] 14 alert(s) judged: close benign 8, escalate 3, review 3; 3 escalated into 3 case(s); 10 await a person
[DLP] 14 alert(s) investigated with read-only look-ups (the platform standard checks, no model)
[CROSS]     high Possible data theft: 2 tools agree (bob.lee@acme-demo.com) - rules X4
[CROSS] critical Possible data theft: 4 tools agree (jane.doe@acme-demo.com) - rules X1, X2, X3
[CROSS]     high Possible data theft: 2 tools agree (arun.k@acme-demo.com) - rules X2
[COMPLY] 3 personal-data incident(s) await a person's reportability decision
[TUNE] suggested: Stop 'Card-like numbers in outbound mail' firing for data sent to krishna-logistics.com - ...
[CONFIG] configuration snapshot of 3 tool(s) that export it: forcepoint_dlp, silverfort, trellix_epo
[COVERAGE] 6 of 10 devices have every expected control (60.0%); 4 short
[HEALTH] 2 critical and 1 warning finding(s) on the tools themselves
[POSTURE] score 65 (weights: draft - to be agreed with the CISO)
[INTEL]     high arun-lt05.acme-demo.com shows attack activity but has no EDR telemetry
[REPORT] CyberDome weekly CISO brief (docx, 7 sections, deterministic templates)
[REPORT] CyberDome monthly report to the board (pptx, 6 sections, deterministic templates)
[AUDIT] {'ok': True, ...}
```

The 3 cross-tool cases recommend 7 actions in all (revoke sessions and require MFA for each person, isolation of
jane's laptop - four-eyes). **These are sample-data figures**: the deck's figures (endpoint counts, gaps, the score)
are illustrative or pilot targets and never shown as measured.

### 4.2 The scheduler runs inside the server

`serve` also runs the jobs ([OPERATIONS.md](OPERATIONS.md), *Jobs*), on their intervals, as in production:
inventory first, then incident, dlp, crosstool, posture, config_snapshot, weekly_reports, intelligence, retention,
self_check, notify, actions. Jobs start 5 seconds after the server; only due jobs run; `/health` shows
`"scheduler": {"state": "running", ...}`; a job running more than 30 minutes shows "Scheduler stuck (job)" on every
screen. To keep every figure still while you present: `$env:SOC_EMBEDDED_SCHEDULER = "0"` before `serve` (the
buttons in §6 still run any job on demand).

### 4.3 Signing in

In a demo there are no passwords: the **development sign-in** asks who you are, the role and the data scope (only
with `SOC_AUTH_MODE=dev`, only from this machine, never in production, never with a live tool).

| Field | What to enter |
|---|---|
| Work email | any address at the organisation's domain, e.g. `lena@acme-demo.com` - the name in approvals, notes, the audit log |
| Role | Lead, Analyst, Auditor, Automation admin or Admin |
| Data scope | *All domains*, or *Data protection only* / *Incident only* |

A sign-in lasts 8 hours and includes MFA. **Two people at once** (four-eyes, two-lead approvals): use a private
window or a second browser profile - tabs of one browser share the sign-in.

| Sign in as | Role | Scope | Use it to show |
|---|---|---|---|
| `lena@acme-demo.com` | Lead | All domains | the CISO view, DLP rulings, proposing weights, reportability decisions, approvals |
| `lars@acme-demo.com` | Lead | All domains | the second lead: approve Lena's weights, catalogue, rule change, promotion, the second approval of an isolation |
| `dana@acme-demo.com` | Analyst | All domains | DLP triage, rulings, case notes, outage log |
| `dee@acme-demo.com` | Analyst | Data protection only | data scope: lands on Data protection; the Dome Score, Comply and Pilot explain they need all-domain access |
| `ada@acme-demo.com` | Admin | All domains | access management, service-account keys, AI usage limits |
| `otto@acme-demo.com` | Automation admin | All domains | connectors, jobs (*Run now*), recording a tool change |
| `audrey@acme-demo.com` | Auditor | All domains | the audit log, verification, the audit pack |

Tokens for scripts: `python -m soc_platform token lena@acme-demo.com lead`, or
`/api/v1/dev/token?user=dee@acme-demo.com&roles=analyst&domains=dlp`.

---

## 5. What the sample data contains

A fictional organisation (`acme-demo.com`) on one day, with vendor-shaped data for the five NAM tools:

* **The baseline:** 10 devices and their people in the directory export, with DLP policy-group membership and
  privileged groups.
* **The storyline (alert-title level):** jane.doe's account is phished at 09:02 and signs in from an unmanaged device
  (Silverfort risk); minutes later an e-mail with investor PAN records to a personal address is quarantined
  (Forcepoint); the sending laptop has disk encryption off (Trellix) and Trend Micro reports an archive utility
  compressing many documents on it. Four tools agree → one critical cross-tool case.
* **Around it:** bob.lee (privileged) sending personal data (X4); arun.k sending customer contacts from a laptop with
  no EDR agent (X2); a noisy card-number rule that a partner's scanned remittance PDFs trip (analysts closed 4 of 6 as
  false positives in Forcepoint - the source of the rule-change and OCR / EDM suggestions); a few alerts that need a
  person; four devices missing a control; a certificate close to expiry; a directory import that left two people out
  of every DLP policy group.

**The 2-minute health check before you present:** `/health` (signed in) shows the audit chain `true` and the
scheduler `running`; Dome Score shows a score with "draft weights"; Data protection shows 14 alerts; Cases shows 6
cases; Approvals shows 7 actions waiting; Dome Comply shows 3 personal-data incidents.

---

## 6. Driving each module live

| Module | On screen | API |
|---|---|---|
| DLP triage | *Data protection* → *Pull DLP alerts* (reads and judges new incidents); open an alert → *Close as benign* / *Escalate* with a reason; *Investigate again* | `POST /api/v1/dlp/run`, `POST /api/v1/dlp/alerts/{id}/decision` |
| Earned autonomy | *Data protection* → decision types: set a target (lead), propose a stage (lead), approve (second lead) | `PUT /api/v1/decisions/{type}/target`, `POST .../stage`, `POST /api/v1/decisions/proposals/{id}/approve` |
| DLP rule changes | *Data protection* → *Rule changes*: *Propose* a suggestion or a classification finding (lead) → *Approve* (second lead) → *Made in the tool* with a reference (engineer) | `POST /api/v1/dlp/tuning`, `.../{id}/approve`, `.../{id}/applied` |
| Cross-tool cases | *Cases* → a "tools agree" case; *Approvals* → revoke / require MFA / isolate (isolate needs two leads) | `POST /api/v1/crosstool/run` |
| Coverage and health | *Dome Graph · coverage* | `GET /api/v1/dashboard/control-coverage`, `/tool-health` |
| A tool change | *Dome Connect · changes* → *Before change* (reference) → *After change*: the diff and the score before / after | `POST /api/v1/config-snapshots/{tool}/before-change`, `.../after-change` |
| Dome Score weights | *Dome Score* → *Score formula* → *Change the weights* → *Preview* → *Propose* (lead) → *Approve* (second lead) | `POST /api/v1/posture/weights/preview`, `/posture/weights`, `.../{id}/approve` |
| The brief | *Dome Score* → *Explain with AI* (the model, when on) | `POST /api/v1/dashboard/ciso/explain` |
| Reportability | *Dome Comply* → a personal-data incident → reason → *Reportable* / *Not reportable* (lead) → *Draft report* → *Reported* with the reference | `POST /api/v1/comply/assessments/{id}/decide`, `.../draft`, `.../report` |
| Audit pack | *Dome Comply* → *Audit pack* (evidence exporter) | `POST /api/v1/comply/pack` |
| Pilot | *Pilot scorecard* → *Use as baseline*, *Set* a target (lead), *Log outage* | `POST /api/v1/pilot/baseline/{kpi}`, `/pilot/figures`, `/pilot/outages` |
| SIEM alert | push one (below), then *Cases* → *Run incident pipeline* | `POST /api/v1/ingest/alerts` |

**Push an alert as NAM's SIEM would** (an API key with the analyst role, from *Access*):

```powershell
$h = @{ "X-API-Key" = "<key>" }
$b = '{"alerts": [{"id": "siem-demo-1", "title": "Suspicious PowerShell download", "severity": "high",
       "timestamp": "2026-09-20T10:00:00Z", "host": "JANE-LT01", "user": "jane.doe@acme-demo.com"}]}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/api/v1/ingest/alerts -Headers $h -Body $b -ContentType application/json
```

**Notifications to Teams or Slack** (optional): `SOC_NOTIFY_WEBHOOKS=teams|https://...` before `serve`; then
*Integrations → Notifications → Send test message*.

---

## 7. Using the API directly

Every screen is an API call: `GET /api/v1/dashboard/ciso`, `/api/v1/dlp/summary`, `/api/v1/comply`, `/api/v1/pilot`,
`/api/v1/crosstool`, `/api/v1/posture/weights`, `/api/v1/config-snapshots`. Take a token
(`python -m soc_platform token lena@acme-demo.com lead`) and send `Authorization: Bearer <token>`. The OpenAPI
description is at `/docs` in dev.

## 8. With and without the model

Without a model every module runs on its computed path: dispositions, severities, scores, coverage and every figure
are the same; the text is written by rule and cited. With a model (`SOC_LLM_*` in `.env`, approved endpoint set):

* the `dlp` job stores the AI's own decision per alert (shadow: nothing happens) and plans the investigations;
* cross-tool cases get a written account; *Explain with AI* and *Draft report* use the model;
* the *AI usage* screen shows calls, tokens and cost per feature.

Check with `GET /api/v1/llm/status`. For NAM the model runs in NAM's environment or an Indian region
([AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md)).

## 9. A different organisation

```powershell
python scripts\build_estate_variant.py out\veridian --seed 7      # names, devices, addresses, volumes - NAM tools included
$env:SOC_FIXTURES_DIR = "out\veridian\fixtures"; $env:SOC_SUPPLIERS_FILE = "out\veridian\suppliers.yaml"
$env:SOC_ORG_DOMAINS = "<the estate's domain from out\veridian\estate.json>"
$env:SOC_DATABASE_URL = "sqlite:///./veridian.db"; python -m soc_platform init-db; python -m soc_platform demo
```

`--messy` adds real-tenant disorder and volume; `--scale N` grows it. The DLP, cross-tool and coverage results follow
the estate's own data.

## 10. Resetting between demos

**Stop the server first** (Ctrl+C). Then:

```powershell
python -m soc_platform reset-demo          # asks you to type RESET; --yes skips the question
python -m soc_platform serve
```

It empties the database in `SOC_DATABASE_URL`, deletes the stored files and reports, and runs `init-db` + `demo`. It
refuses while the server runs on `SOC_PORT`, refuses with `SOC_ENVIRONMENT=prod`, deletes folders only inside the
project, and works on SQLite and PostgreSQL. Only on a demo database: the audit log goes too. Or keep a database per
audience (`$env:SOC_DATABASE_URL = "sqlite:///./demo_<date>.db"`).

## 11. Running with Docker and PostgreSQL

Add to `.env`: `POSTGRES_PASSWORD`, `SOC_APP_DB_PASSWORD` (strong passwords), `SOC_ORG_DOMAINS`, `SOC_DEV_JWT_SECRET`
(and `RABBITMQ_PASSWORD`, `REDIS_PASSWORD`, `ENGINE_APP_SECRET_KEY`, `ENGINE_API_KEY`, which Compose checks for every
service although only the inherited engine profile uses them). The base file is **production**; the demo adds an
override (dev sign-in, fixtures only):

```powershell
docker compose -f deploy\docker-compose.yml -f deploy\docker-compose.demo.yml --env-file .env up -d --build
docker compose -f deploy\docker-compose.yml -f deploy\docker-compose.demo.yml --env-file .env exec platform-api python -m soc_platform demo
docker compose -f deploy\docker-compose.yml logs -f platform-api
docker compose -f deploy\docker-compose.yml down        # stop (data kept); add -v to delete the database volume
```

`SOC_PRODUCT_SCOPE` defaults to `nam` in the Compose file. Start-up: `db-certs` writes the database's CA and
certificate, `postgres` requires TLS, `platform-migrate` creates the schema as its owner and grants the runtime role,
then the API and the scheduler start as that role over `sslmode=verify-full`; reports are stored in PostgreSQL
(`SOC_BLOB_STORE=database`). Profiles: `--profile tls` (a TLS proxy), `--profile backup` (nightly dumps).

## 12. Proving it works

```powershell
python -m pytest soc_platform\tests -q -p no:cacheprovider          # the full suite (about 45 min on SQLite)
python -m pytest soc_platform\tests\test_dlp.py soc_platform\tests\test_pentest_nam.py -q   # a module first
python scripts\verify_features.py                                    # feature-by-feature report -> docs\FEATURE_VERIFICATION.md
python scripts\verify_features.py --browser                          # + both browser tours (full scope and NAM scope)
```

On PostgreSQL (`pip install pgserver` for an embedded server):

```powershell
python -c "import pgserver; print(pgserver.get_server('D:/pgtest_soc', cleanup_mode=None).get_uri())"
$env:SOC_TEST_POSTGRES = "<that URI>"; python -m pytest soc_platform\tests -q -p no:cacheprovider
```

The NAM tour alone (a server must run in the NAM scope): `cd scripts\ui_tour; npm install; $env:SOC_BASE =
"http://127.0.0.1:8080"; node tour_nam.js` (screenshots go to `docs\screenshots` unless `SOC_SHOTS` is set).

## 13. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Sign-in does nothing / "Development sign-in is disabled" | `serve` prints why at start-up. Usually `SOC_DEV_JWT_SECRET` is missing or shorter than 32 characters, or `.env` was not loaded in this window (`. .\scripts\load_env.ps1`) |
| You land on Data protection, not the Dome Score | You signed in with *Data protection only*; the Dome Score needs *All domains* |
| A screen says it needs all-domain access | Dome Score, Dome Comply and the Pilot scorecard span every domain. Sign in with *All domains* |
| No Approve button on your own proposal | By design: weights, catalogue, rule changes and promotions are approved by a *second* lead (`lars@acme-demo.com`) |
| "decided by someone else at the same moment" | Another person decided it first; reload. Only one decision is made |
| Isolate stays "awaiting second approval" | Containment always needs two different leads, whatever the policy says |
| "the DLP run is in progress" (409) | The scheduled `dlp` (or `crosstool`) job is running; try again in a moment |
| Screens empty | `demo` was not run on *this* database: check `SOC_DATABASE_URL`, run `init-db` and `demo` |
| The score shows "draft weights" | No weights version approved yet: propose and approve one (two leads), or leave the draft for the demo |
| "Scheduler stopped" / "Scheduler stuck" banner | Started with `SOC_EMBEDDED_SCHEDULER=0` and no separate scheduler, or a job hangs (see *Integrations*, job history) |
| Port in use | `netstat -ano \| findstr :8080`, then stop that one process by its PID; or set `SOC_PORT` |
| "database is locked" | Two processes writing one SQLite file; stop one, or use PostgreSQL (§11) |
| The server refuses to start: connector configuration errors | A typo in `config\connectors.yaml`; the message names each with its fix; `python -m soc_platform config check` |
| An inherited screen (Phishing, Vulnerabilities) is missing | Expected in the NAM scope; `SOC_PRODUCT_SCOPE=full` shows them |
| Numbers differ from screenshots | A fresh database or another day; the figures are computed from the data, correctly |

## 14. Quick reference card

```text
START        . .\scripts\load_env.ps1 ; python -m soc_platform init-db ; python -m soc_platform demo ; python -m soc_platform serve
OPEN         http://127.0.0.1:8080   lena@acme-demo.com, Lead (home: Dome Score)   second lead: lars@acme-demo.com
USERS        dana Analyst · dee Analyst + "Data protection only" · ada Admin · otto Automation admin · audrey Auditor
HEALTH       http://127.0.0.1:8080/health
DLP          Data protection > Pull DLP alerts ; open an alert > Close as benign / Escalate (reason)
WEIGHTS      Dome Score > Score formula > Change the weights > Preview > Propose ; second lead approves
COMPLY       Dome Comply > incident > reason > Reportable > Draft report > Reported (reference) ; Audit pack
PILOT        Pilot scorecard > Use as baseline ; Set target ; Log outage
SIEM PUSH    POST /api/v1/ingest/alerts (X-API-Key) then Cases > Run incident pipeline
TOKEN        python -m soc_platform token lena@acme-demo.com lead
CONFIG       python -m soc_platform config check | preflight --all
RESET        stop server ; python -m soc_platform reset-demo --yes ; serve
TESTS        python -m pytest soc_platform\tests -q ; python scripts\verify_features.py --browser
```
