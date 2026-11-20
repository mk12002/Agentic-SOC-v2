# Test report - CyberDome for NAM

Date: 2026-11-19 · Environment: Windows 11, Python 3.11.9, CPU only · Branch: `main`

What was tested, on what data, what was found, what was fixed, and what can **not** be claimed yet - newest round
first. Every figure comes from sample data (the generated estates); none is a measurement of NAM's estate. Accuracy
of the AI on NAM's data is measured in shadow mode against NAM's analysts' rulings from the first pilot week.

## Round 39 (2026-11-19) - latest results: hardening, penetration test of the NAM surface, NAM-specific docs

**Scope.** Everything the NAM build added was attacked and hardened; the build was run on PostgreSQL for the first
time; the browser tour got a NAM version; feature verification got the NAM features; DLP rule changes got
classification-quality findings; the documentation was rewritten for NAM.

**Results.**

| Run | Result |
|---|---|
| Full suite, SQLite (1,199 collected) | **1,181 passed, 18 skipped, 0 failed** (46 min) |
| Full suite, PostgreSQL 16 (embedded) - the first run of the NAM build there | **1,178 passed, 21 skipped, 0 failed** (2 h 6 min; the extra skips are database-specific checks) |
| NAM test files alone on PostgreSQL (15 files) | 193 passed, 0 failed |
| NAM browser tour | 0 problems, 0 accessibility notes (24 screenshots; 1440 / 1280 / 1024 / 768 / 390 px, light and dark) |
| Full-scope browser tour | 0 problems after the policy-table fix |
| ruff, bandit (medium+), JavaScript syntax, secret scan | clean (the confidential-name pattern is not configured on this machine) |

**Penetration test of the NAM surface** (SECURITY.md section 4; `test_pentest_nam.py`, 8 tests). Found and fixed:

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | Racing approvals: two leads approving the same weights both succeeded (two audit events); three leads deciding one reportability all succeeded (clocks restarted). The same check-then-write was in every approval path | High | `core/db.claim` (exactly-once), revision compare-and-swap for reportability and submissions |
| 2 | Containment could be made autonomous by a policy version (four-eyes did not cap the level) | High | `policy.CONTAINMENT` enforced in the engine; such documents refused; four-eyes capped below L4 |
| 3 | Sender-written text after `@` became the "destination domain" fact, reaching the facts, the breach draft and the model | Medium | only a real host name is kept; otherwise `unknown` (judged as outside) |
| 4 | A manual DLP / cross-tool run beside the scheduled job could duplicate cases | Medium | the routes hold the job's lease (`jobs.held`), 409 while busy |
| 5 | `"reportable": "yes"` read as true | Low | strict boolean |
| 6 | Unbounded catalogue texts and ids with markup; outages for any "tool", dated 1900 | Low | bounds and fixed id character set; known tools within 400 days |

Inherited tests changed by finding 2 (they assumed isolation could be made autonomous):
`test_lead_approval_executes_and_audits` and `test_l4_executes_autonomously_and_rollback_uses_reverse` now use a
reversible non-containment action; `test_irreversible_actions_are_never_autonomous_whatever_the_policy_says` expects
containment to stay with people. New: `test_containment_stays_with_two_people_whatever_a_policy_document_says`.

**NAM browser tour** (`scripts/ui_tour/tour_nam.js`, run by `verify_features.py --browser` beside the full-scope tour,
which now pins `SOC_PRODUCT_SCOPE=full`): every CyberDome screen, every KPI cross-checked against the API, the
weights / reportability / baseline flows in the UI, a stored-XSS probe through every field a person writes, a
DLP-only analyst, layout at 1440 / 1280 / 1024 / 768 / 390 px in both themes, axe-core on every screen. It found:
lever and "hot" text below WCAG contrast; links inside text distinguishable by colour only; the Cases screen offering
the inherited Phishing / Vulnerability tabs (and overflowing a phone); a clipped input on AI usage at 390 px; the
weights proposer's flow needing the fold opened. All fixed; final run: **0 problems, 0 accessibility notes**. The
full-scope tour found the policy table 21 px too wide at 1280 px since isolation gained a third tool: fixed (the tool
cell wraps).

**Found by the feature verification** (which runs a sorted subset of the suite): `test_dlp_api.py`'s queue test assumed
it ran first in its module; in sorted order the CISO-view test had already pulled the DLP alerts, so "new alerts" was 0.
The test now reads the queue before and after its run. The NAM racing-approval test now also accepts 503 (SQLite busy)
for the losers - the invariants are one success and one audit event. The verification's evaluations now run in the
full scope with the package on the path (they measure the inherited modules).

**Also:** the dev sign-in form offered "Phishing only" / "Vulnerability only" in the NAM scope - it now reads the
product scope from the public sign-in config.

**DLP rule changes: classification quality.** `exclude_ocr`, `use_edm`, `use_fingerprint` (domains/dlp/tuning.py),
suggested from each classifier's type and OCR origin as Forcepoint reports them (placeholder fields), previewed,
refused when unsafe, verified from the configuration snapshot. 4 new tests in `test_dlp_tuning.py`.

**Feature verification:** 14 NAM features mapped to their tests (`scripts/verify_features.py`), 2 NAM items under
"what automated verification cannot prove".

**Documentation:** the docs were rewritten for NAM (ARCHITECTURE, ENGINEERING, FEATURES, CONNECTORS, OPERATIONS,
RUN_GUIDE, PRESENTER_GUIDE, AI_AND_AUTONOMY, DEPLOYMENT_GUIDE, SECURITY, FAILURE_MODES, HIGH_AVAILABILITY,
REQUIREMENTS_TRACEABILITY, this report and the review pack); the inherited documents were removed.

**Not claimed:** nothing here was run against NAM's tools; the NAM jobs were not measured at NAM's volume.

## Round 38 (2026-11-19): cross-tool cases, adjustable Dome Score, Dome Comply, pilot scorecard

Aim: M8 (cross-tool cases with recommended actions), M12 (Dome Comply: evidence per control, reportability, audit
pack), M13 (pilot scorecard), adjustable Dome Score weights, and a collapsible side menu.

**Method.** New code with 37 new tests in `test_crosstool.py`, `test_posture_weights.py`, `test_comply_pilot.py` and
additions to `test_decisions.py`, `test_scope.py`, `test_connector_nam_stack.py`; `demo` in both scopes, read line by
line; every new screen and flow driven in a real browser (desktop and 390 px): weights proposed in the UI and approved
by a second lead (the proposer cannot approve), baseline captured, reportability decided, report drafted, the
cross-tool case opened, the side menu folded / reloaded / toggled from the keyboard; ruff, bandit, `node --check`,
the secret scan.

**Results (SQLite, Windows 11, Python 3.11.9).** 1,186 collected: **1,168 passed, 18 skipped, 0 failed** (44 min). PostgreSQL not run. `demo` (NAM scope): 3
cross-tool cases - jane.doe critical (Forcepoint DLP, Silverfort, Trellix ePO and Trend Micro agree; rules X1, X2,
X3), bob.lee and arun.k high (2 tools) - 7 actions awaiting approval, 3 personal-data incidents for a reportability
decision; full scope: 7 phishing + 6 incident + 3 DLP cases, 43 approvals.

**Found and fixed while testing:**
* The risk engine knew only the earlier estate's EDRs, so a Trend Micro-protected laptop in a cross-tool case was
  reported "without EDR telemetry" (`risk.EDR_TOOLS`; regression test).
* The incident pipeline re-investigated cross-tool cases on a second run (they live in `incident`), adding look-ups
  and unrelated actions - the re-run test caught it on all four estates (`reassess_open` and the investigate route
  now leave them alone).
* A reportable incident could be decided again, which would restart its regulatory clock (refused now).
* Two earned-autonomy orderings depended on Windows' ~15 ms clock tick (rulings just before a promotion counted as
  after it; the newer of two decisions in one tick not always "newest") - each failed once in a full run only; both
  now strictly ordered, each with a frozen-clock regression test that fails on the old code.
* The figure-consistency test loaded incidents before the device baseline, unlike the scheduler; a laptop known only
  from DNS then stayed a second record of the same name (the test now reads the baseline first, as the platform does).
* The CISO view said "draft weights" after weights were approved; cross-tool cases had no model narration.

**Not claimed:** the Silverfort and Trend Micro action calls and the alerts stream are placeholders (fake mode only);
the control catalogue is a draft for NAM's compliance team and two of its three deadlines are not set; CERT-In's 6 h
is as stated in the proposal, marked "to verify".

## Round 37 (2026-11-19): NAM product scope and the CISO view

`SOC_PRODUCT_SCOPE` (`nam` by default) switches the inherited modules off; the Dome Score screen became the CISO view
(gauge, domain tiles, what raises the score, why it moved, DLP week, people, AI ladder, governance, changes, plain-words
brief, board report and weekly brief). Full suite: 1,128 passed, 18 skipped, 0 failed. Screens checked in a browser
at 1,440 and 390 px.

## Round 36 (2026-11-16): CyberDome rebrand, AI investigator, rule changes, configuration snapshots

Aim: rebrand what people see as CyberDome; build the AI investigator (M6), DLP rule-change proposals (M7) and
configuration snapshots (M11).

**Results (SQLite, Windows 11, Python 3.11.9).** 1,133 collected: **1,115 passed, 18 skipped, 0 failed**; 33 new tests
in `test_dlp_investigator.py`, `test_dlp_tuning.py`, `test_config_snapshots.py`. PostgreSQL not run. ruff clean,
bandit no issues, JavaScript parses. `demo`: 14 alerts investigated by the platform's standard checks (no model), one
rule change suggested (hides 6 alerts of a rule: 4 closed as benign, 0 escalated), configuration snapshots of the 3
tools that export one; earlier figures unchanged.

**Found while building:** a rule with an open proposal still received a second, different suggestion (now no other
suggestion until the first is settled).

**Not claimed:** the configuration export paths and shapes (placeholders, as for the rest of these connectors); the
screens were not opened in a browser in this round.

## Round 35 (2026-11-16): data protection, control coverage and posture (first version)

Aim: the first version of the data-protection build: five new connectors in fake mode (directory export, Forcepoint
DLP, Silverfort, Trend Micro, Trellix ePO), DLP triage with a computed disposition, earned autonomy for the AI's own
decision (shadow and recommend; decide refused in code), control coverage, tool health, a draft posture score and a
CISO view. Every pipeline stays unchanged; the platform behaves identically with the model off.

**Method.** The inherited suite on an untouched copy first (it stopped at a missing engine dependency, which was then
installed); the new code; 70 new tests in five files plus the existing parametrised suites, which pick up the new
connectors and routes by themselves (conformance, live wire, every GET route x 7 roles on four estates); `demo` on a
fresh database, read line by line; ruff, bandit, `node --check`, the secret scan.

**Results (SQLite, Windows 11, Python 3.11.9).** 1,100 collected (989 before): **1,082 passed, 18 skipped, 0
failed**. PostgreSQL was **not** run this round. Feature verification (`verify_features.py`) was not re-run and does
not yet map the new features. ruff clean, bandit no issues, JavaScript parses, no `.env` secret in tracked files.
The banned-name scan could not run: its pattern file is not in this copy of the repository.

**Demo (no model).** 14 DLP alerts: 8 closeable as benign, 3 escalated (3 data-protection cases), 3 for a person; the
bulk personal-data alert after a high-risk sign-in from a laptop with encryption off is critical with three tools
agreeing. Coverage: 6 of 10 devices have every expected control; 4 short (EDR missing, DLP agent missing, DLP agent
silent, encryption off), 1 device seen by the EDR but not in the baseline. Tool health: 2 critical, 1 warning.
Existing figures unchanged: 7 phishing + 3 incident cases, 37 actions awaiting approval, asset match rate 1.0.

**Found and fixed while building:**

| Defect | Seen as | Fix |
|---|---|---|
| A device named in a DLP incident counted as listed by the DLP tool | The demo reported a laptop with no DLP agent as "unknown" instead of "missing" | A tool lists a device only through its own inventory record, still present in its newest read (`controls.snapshot`) |
| The baseline lost a device on a first start | Demo: 9 of 10 devices; the directory record waited in the analyst queue | The phishing job had created the laptop from a DNS event first; an `inventory` job now runs first, and `demo` reads the baseline first |
| Dating inventory "as read" broke an existing figure | Asset match rate 1.0 -> 0.98 (a Wiz record no longer matched its server) | Inventory records are dated by the vendor's own time, as every other inventory connector; "still listed" is read from the sync time |
| Estate builders wrote the new tools' fixtures into the first estate only | Variant estates had no fixtures for the five tools | The builder writes through the fixture module loaded for the current estate |
| A real mailbox domain in sample data | The handoff estate's reserved-address test | Personal mail in the sample data uses a reserved domain; providers are matched by name in any country domain |
| Queries that grow with history | Code review: summary and rule history read every alert | Database aggregates; backfill judged in committed batches of 500; 30-day windows anchored to the newest alert |

**Not claimed:** any behaviour against a real tool (the five connectors' paths and shapes are placeholders), the
posture score's weights (a draft), the AI's agreement with analysts (needs the client's past decisions), PostgreSQL
parity for the new tables (not run).


## Before the NAM build: the platform core (rounds 1-34, 2026-09-24 to 2026-11-15)

The NAM modules run on a platform core that was built and tested over 34 earlier rounds. In short: connector
conformance (paging, resume, throttling, malformed fields) for every connector; entity resolution measured at 0 false
merges on synthetic estates of 400 devices and 300 people; PostgreSQL parity (the suite on both engines, PostgreSQL's
rules enforced on SQLite); high availability (leases, renewals, blob store in the database, a real multi-process
server under concurrent analysts); two penetration test rounds and a go-live security review; the commit-before-reply
guarantee; time travel (0 / 45 / 400 days); supply chain (hashed locks, signed images, SBOM, Trivy). Those suites run
on every build: their tests are part of the counts above. The detailed history of those rounds concerned the earlier
deployment's modules and is kept in the repository's history, not here.
