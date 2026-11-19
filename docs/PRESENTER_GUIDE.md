# Presenter guide - showing CyberDome to NAM

What to show, in what order, what to say, how every figure is computed, the hard questions and their honest
answers. Setup is in [RUN_GUIDE.md](RUN_GUIDE.md) (§1 to start, §4.3 for the accounts, §10 to reset).

**Ground rules for every demo:**

* Every figure on screen is **sample data** about a fictional organisation, computed by the platform. Never present
  a figure as a measurement of NAM's estate; the deck's figures (endpoint counts, gap counts, the Dome Score, alert
  volumes, response times, percentages) are illustrative or pilot targets.
* The five NAM connectors run in **fake mode** on placeholder APIs until each tool's version and API are confirmed.
  Say so if asked; it is a strength (nothing was built from guesses), not a gap to hide.
* The platform never says NAM "is compliant"; it shows evidence and gaps.

## 1. The 20-minute walkthrough

Sign in as `lena@acme-demo.com`, Lead, All domains (window 1). Keep `lars@acme-demo.com`, Lead, ready in a private
window (window 2) for the second approvals.

| # | Minutes | Screen | Show | Say |
|---|---|---|---|---|
| 1 | 2 | Dome Score (lands there) | the gauge, band and trend; the five domain tiles - privileged access and web "not measured" | "One number for the CISO, computed from what the tools report. Two domains say 'not measured' rather than inventing a figure - Arcon and Cloudflare come in Phase 2." |
| 2 | 2 | Dome Score → *What would raise the score most* | the levers with points and where to fix each | "Not an AI opinion: arithmetic on the formula's own factors. Each lever links to the screen where it is fixed." |
| 3 | 2 | Dome Score → *Score formula* | the weights; open *Change the weights*, set web to 10, *Preview*, *Propose* | "The weights are the CISO's call. A lead proposes, the preview shows the score under both, a second lead approves. Every surface says 'draft' until then." |
| 4 | 1 | window 2 → Dome Score | *Approve* as Lars; back in window 1 the subtitle says the version agreed | "Two people, audited. The proposer cannot approve their own." |
| 5 | 3 | Dome Graph · coverage | 6 of 10 devices fully covered; the 4 short and why (missing, silent, off); devices ranked by personal-data alerts; tool health: certificate, failed job, people outside every DLP policy group | "Coverage against the AD baseline, per control. Silent is measured from the tool's own newest report, not the clock. A tool that reports no health is 'not reported', never 'healthy'." |
| 6 | 3 | Data protection | 14 alerts: escalate 3, close benign 8, review 3; open the jane.doe alert: facts F1..., the computed disposition with its rule (E1, E2, E3), the subject shown as untrusted | "The decision reads structured facts - who, what data, where, which device. The subject line says 'approved transfer per manager'; no rule reads it. That is how an insider cannot talk the system out of an alert." |
| 7 | 2 | Data protection → decision types | all at shadow; target not set | "The AI decides alongside the analyst from day one, in shadow - nothing happens. It moves up only when NAM's SOC lead sets a target, it meets it, and a second lead approves. If its agreement slips, it drops back by itself." |
| 8 | 2 | Cases → the critical "4 tools agree" case | jane.doe: DLP + Silverfort + Trellix + Trend Micro; the recommended actions | "Four tools, one person, one case - severity from how many tools agree. Revoke sessions and require MFA are recommended; isolating her laptop needs two people, always, whatever the policy says." |
| 9 | 1 | Data protection → *Rule changes* | the partner-remittance suggestion; the classification findings (OCR, EDM) | "The noisy card rule: analysts closed 4 of 4 decided as benign; the scans are read by OCR and the card pattern matches invoice numbers. The platform proposes; an engineer makes the change in Forcepoint; it is verified from the configuration afterwards." |
| 10 | 2 | Dome Comply | evidence share, controls passing / failing / no evidence; 3 personal-data incidents; decide one *Reportable* with a reason; the clocks with source and "to verify"; *Draft report* | "Evidence and gaps, never 'compliant'. Reportability is a person's decision and it stands. The AI drafts from the facts; NAM sends it." |
| 11 | 1 | Pilot scorecard | KPIs; *Use as baseline* on one | "How the pilot is judged: against NAM's own week-2 baseline and targets NAM's SOC lead sets - none preset." |
| 12 | 1 | Audit log | the chain verified; a trace | "Every decision, by a person or the AI, is in a tamper-evident chain." |

**Short version (8 minutes):** steps 1, 5, 6, 8, 10.

## 2. How every figure is computed

### 2.1 The Dome Score

* **Domains** (each 0-100):
  * *Endpoint* = the share of baseline devices with a reporting EDR agent.
  * *Data protection* = the mean of the coverage shares of the DLP agent and disk encryption, less the tool-health
    penalty of the DLP / encryption tools (critical 5 points each, warning 2, capped at 20) and 3 points per open DLP
    case (capped at 15).
  * *Identity* = 100 × (1 - people with a high- or critical-risk sign-in in the last 7 days of data / people in the
    directory).
  * *Privileged access*, *Web*: not measured until Arcon / Cloudflare are connected.
* **Score** = the weighted mean of the measured domains with weight > 0 (default weights: identity 20, privileged
  access 20, endpoint 20, data protection 25, web 15), less 4 points per open critical case (cap 20) and 2 per critical
  tool-health finding (cap 10), rounded and kept within 0-100. Bands (draft): strong ≥ 85, fair ≥ 70, weak ≥ 50, poor
  below.
* **Every response carries the factors**, so the score can be recomputed by hand; the default weights and penalties
  are a draft until two leads approve a version.
* **Levers**: for a domain factor, its effect × the domain's share of the measured weight; for a penalty, its points
  in full. An upper bound (a domain at 0 or 100 regains less).
* **Movement**: today's score against the oldest stored day of the last 30, per domain; a change of weights is named.

### 2.2 Coverage

Covered = every expected control in place and reporting. Expected: EDR agent on every device; DLP agent reporting and
disk encryption on workstations. States: missing, silent (no report for 24 h, measured from the newest check-in the
tool reported), off, unknown. A control whose tool is not connected is not measured. Coverage % = covered / baseline
devices.

### 2.3 The DLP decision table (`domains/dlp/service.py:dispose`)

| Rule | Escalate when |
|---|---|
| E1 | personal data in bulk (≥ 100 matches of a classifier) is going outside the organisation or to removable media |
| E2 | the sender had a high-risk sign-in within 24 hours and the data is going outside or to removable media |
| E3 | personal data is going outside from a device missing a control, or after a risky sign-in |
| E4 | the tool rated the alert high or critical and the data is going outside or to removable media |
| C1 | **close as benign** when the destination is internal, a known partner or a sanctioned service, no personal data moved in bulk, no high-risk sign-in, and the tool's severity is medium or lower |
| R1 | **needs a person** otherwise |

Severity: the tool's own, raised to at least high for E1, and one level higher when two or more other tools
corroborate. Only escalations are raised.

### 2.4 Cross-tool severity

Two distinct tools agreeing about one person → high; three or more → critical; one tool alone → no case.

### 2.5 AI agreement and drift

Agreement = AI decisions matching the analyst's ruling / AI decisions with a ruling, over the newest decided items
since the stage began. Drift = agreement below the target, or a population stability index above 0.25 between the
AI's outcome mix at promotion and now.

### 2.6 Compliance evidence share

Controls with current evidence (every one of the control's tests produced a result, pass or fail) / controls in the
catalogue; the rest are named. A control fails when any of its tests fails, passes when all pass, and otherwise has
no evidence.

## 3. Hard questions, honest answers

| Question | Answer |
|---|---|
| "Is this connected to our tools?" | Not yet. The connectors run on vendor-shaped sample data through the same code a live tool uses. Each needs your installed version's API documentation and a read-only account; then preflight checks every call before it goes live. |
| "Will the AI close our DLP alerts?" | Not in this version. It decides in shadow - stored beside your analyst's decision. It can move to recommend (pre-filled, your analyst confirms) only when your SOC lead's target is met and a second lead approves. The decide stage is refused in code. |
| "Can a clever insider talk the AI into closing an alert?" | Decisions read structured facts. The message text, subject and file names are shown fenced as data and read by no rule; a test injects such text and proves nothing changes. |
| "Could someone change a policy to isolate machines automatically?" | No. Isolation, disabling accounts and rotating privileged credentials always need two people; the engine enforces it whatever a policy says, and a policy that tries is refused. |
| "Where does our data go?" | To your tools (reads) and, if the model is on, to a model in your environment or an Indian region, pseudonymised. Nothing else. |
| "What does the AI cost?" | Not estimated in advance: it depends on your alert volume and the model your region offers. Phase 1 measures alerts per day, the share reaching the model and the cost per alert; budgets and per-person limits cap it. |
| "Are we compliant with CSCRF / DPDP?" | The platform does not say so. It shows evidence per control and names the gaps; the control mapping is a draft your compliance team validates. |
| "Who decides whether a breach is reportable?" | A person - one of your leads, with a reason. The decision starts the clocks and stands. The AI drafts the report; you send it. |
| "Where do the deadlines come from?" | From the catalogue, each with its source. Only CERT-In's 6 hours is in the draft, marked "to verify"; the others are "not set" until your team confirms them. |
| "What if a tool goes down?" | That tool's figures keep their last read and show stale; nothing invents a value; every other tool and screen keeps working. |
| "Why is the score 65?" | Open the factors: every point is accounted for; the weights are a draft until your CISO agrees them. |
| "Why not show privileged access?" | No privileged-access tool is connected yet; the domain says "not measured" rather than a made-up number. |

## 4. Numbers to remember (sample data, this build)

| Figure | Value |
|---|---|
| DLP alerts in the sample | 14 (escalate 3, close benign 8, review 3) |
| DLP cases / cross-tool cases | 3 / 3 (jane.doe critical - 4 tools; bob.lee, arun.k high - 2 tools) |
| Actions awaiting approval | 7 |
| Personal-data incidents | 3 |
| Devices fully covered | 6 of 10 |
| Tool-health findings | 2 critical, 1 warning |
| Dome Score (draft weights, model off) | 65 |
| Configuration snapshots | 3 tools (Forcepoint, Silverfort, Trellix) |

## 5. Components to point at (if the audience is technical)

| Ask | Show |
|---|---|
| "Show me the code that decides" | `domains/dlp/service.py:dispose` (the table above) |
| "Show me the guardrails" | `core/decisions.py` (decide refused, targets, drift), `core/policy.py:CONTAINMENT` |
| "Show me the score" | `intelligence/posture.py` (+ `GET /api/v1/dashboard/posture`, factors in the response) |
| "Show me the audit" | *Audit log* → verify; `python -m soc_platform audit verify` |
| "Show me the tests" | `test_dlp.py`, `test_decisions.py`, `test_pentest_nam.py`; [FEATURE_VERIFICATION.md](FEATURE_VERIFICATION.md) |

## 6. Before you present

* `reset-demo --yes` on a fresh database; `serve`; the 2-minute health check (RUN_GUIDE §5).
* Two windows signed in (Lena, Lars). Decide whether the model is on; with it off, say the text is written by rule.
* Close every other window that shows names or data of anything else.
