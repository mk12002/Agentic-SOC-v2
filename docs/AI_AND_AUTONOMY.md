# The AI in CyberDome for NAM: what it does, what it may decide, and its limits

CyberDome is AI-first, but not AI-unbounded. This document says what the model does in each module, what it may
decide and under which conditions, what it never decides, how its use is limited and costed, where it may run for
NAM, and how to measure it. The code is the source of truth: `llm/gateway.py`, `llm/usage_policy.py`,
`llm/redaction.py`, `core/decisions.py`, `domains/dlp/`.

## 1. Who decides what (CLAUDE.md §0.4)

| Decision | Decided by | Where enforced |
|---|---|---|
| Which read-only look-ups an investigation runs | the AI, from a fixed menu of seven (no free-form tool calls, no URLs) | `domains/dlp/investigator.py` |
| DLP disposition: close as benign, escalate | the AI, **once that decision type is promoted** - and a close only where the computed disposition agrees | `core/decisions.py`, `domains/dlp/service.py` |
| A Forcepoint rule change | the AI (or the platform) proposes, a second lead approves, an engineer makes it | `domains/dlp/tuning.py` |
| Reversible action (ticket, session revoke, require MFA) | recommended (L2) by default; L3 / L4 per action type only by an approved policy | `core/policy.py` |
| Containment (isolate, disable account, rotate a privileged credential) | people, four-eyes, always | `policy.CONTAINMENT` |
| DPDP / CERT-In reportability, breach notification | a person; the AI drafts | `reporting/breach.py` |
| The Dome Score, coverage, severity, every figure on screen | code; the AI explains | `intelligence/posture.py`, `ciso.py` |

**In this version the AI decides nothing that acts.** Every decision type is at `shadow` or `recommend`; the `decide`
stage is refused in code until the adversarial DLP-content test set exists and passes.

## 2. What the model does, feature by feature

Every feature has a name the AI usage policy knows (`usage_policy.KNOWN_WORKFLOWS`), a default size (small for
routine text, large for summaries), and who triggers it. Each can be switched off, capped or given another model on
*Govern -> AI usage*.

| Feature | Size | Triggered by | What the model does | Without the model |
|---|---|---|---|---|
| `dlp.disposition` | small | the `dlp` job | its own close / escalate decision on a DLP alert, citing the facts (F#) and findings (I#); stored beside the computed one | no AI decision stored; the computed disposition and every figure identical |
| `dlp.investigate` | small | the `dlp` job, or a person (*Investigate again*) | chooses read-only look-ups from the menu, up to 5 in 2 rounds | the platform's own standard checks |
| `crosstool.summary` | large | the `crosstool` job | the written account of a cross-tool case, from the tools' cited facts | a cited account written by rule |
| `posture.explain` | small | a person (*Explain with AI* on the Dome Score) | the Dome Score in plain words from the P-numbered factors | the brief by rule (shown on every load) |
| `compliance.draft` | large | a lead (*Draft report*) | a regulator's incident report from the case's structured facts, every sentence cited | the facts written out by rule |
| `incident.summary` | large | the `incident` job | an incident's summary over its evidence | the cited deterministic summary |
| `intelligence.narrate` / `intelligence.brief` | small / large | the `intelligence` job | correlated-finding narrative; the situation brief | deterministic text |
| `intelligence.plan` / `intelligence.answer` | small / large | a person (Intelligence Q&A) | chooses read-only tools for a question; the cited answer | the answer from the tools' results |
| `report.plan` / `report.section.*` | small / large | a person (Reports) | plans a report from words (NAM sources only); writes section commentary citing figures | a fixed plan; deterministic commentary |
| `tuning.draft` | small | a lead (Tuning) | turns a request in words into a draft rule from the fixed menu, checked by the platform | the platform's own parser |

## 3. Guardrails that hold at every stage

Each has a test that fails when it is removed.

1. **Never closed automatically:** high / critical alerts, privileged users, deception hits, hosts with a
   known-exploited vulnerability, anything on the block watch list (`tuning.guard`, one list).
2. **The AI may escalate alone; it may close only when the computed disposition agrees.** Disagreement → a person.
3. **Insider-written text is data.** Message body, subject and file names are passed fenced as untrusted data;
   decisions use structured facts (user, data class, destination, device state, identity and privileged-access
   context); no decision lowers severity on content alone. A destination is kept only when it is a real host name.
4. **Citations or nothing.** A decision or statement without a valid citation is dropped; statements stating a
   figure absent from their cited evidence are dropped (numeric fidelity).
5. **Everything recorded.** Every AI decision stores model and version, prompt version, the evidence hash, the
   structured output and the stage (`ai_decisions`); every model call is logged with prompt (pseudonymised), answer,
   tokens and what the evidence check removed and why.
6. **Model off, failing or over budget → the computed path**, analysts decide, figures identical to model-on
   (`test_consistency.py`, "LLM on / off identical").
7. **1 in 10 AI closures is re-checked by a person, permanently** (a stable hash).
8. **Model JSON is untrusted input:** lists, choices and citations are type-checked (`model_list`, `model_choice`,
   `model_ids`); a malformed item is dropped and counted.

## 4. The ladder: how a decision type earns trust

* **Narrow types:** `dlp.email`, `dlp.web`, `dlp.removable_media`, `dlp.other`. Each climbs on its own.
* **Stages:** `shadow` (the AI decides, nothing happens, its decision is stored beside the computed one and the
  analyst's) → `recommend` (pre-filled for the analyst; overruling needs a reason, which feeds rule-change suggestions)
  → `decide` (refused in this version).
* **Targets** - an agreement percentage (50-100) and a minimum sample (≥ 20 decided items) - are set by NAM's SOC lead
  per type. **There is no default presented as agreed:** until a target is set, nothing can be promoted.
* **Promotion** is proposed by one lead, refused unless the measured agreement meets the target over the sample,
  and approved by a **second lead** - agreement is measured again at approval. Versioned and audited.
* **Demotion needs nobody:** on each `dlp` run, over the newest decided items since the promotion, agreement below
  target or a shift in the mix of the AI's outcomes (PSI > 0.25) sends the type back down. A lead may also demote at
  once, alone.
* **Measurement** is shown on the Data protection screen (stage, AI decisions, decided by analysts, AI agreement,
  computed agreement, target, what blocks promotion) and per type on the Pilot scorecard.

## 5. Where the model runs for NAM, and what it sees

* **Residency (CLAUDE.md §0.4 rule 8):** the model runs in NAM's environment or an Indian cloud region, or is off.
  Which models that region offers is still to be decided with NAM. Raw vendor logs stay in the deployment's region.
* **Only approved endpoints:** `SOC_LLM_APPROVED_ENDPOINTS` (mandatory and https-only in production); any other
  endpoint is refused and the platform runs without the model.
* **Pseudonymisation before every prompt** (`llm/redaction.py`, `SOC_LLM_REDACT_PII=1`): internal users (addresses in
  NAM's domains, `DOMAIN\user`), names, internal host names, internal IP addresses, phone numbers, card numbers and
  national ids are replaced by tokens and restored after; one map per call.
* **What a prompt holds:** the numbered evidence of the item (facts, findings, factors) and, fenced, the untrusted
  text. Never a secret, never a whole mailbox or log.
* **NAM's own LLM gateway** is configuration, not code: `SOC_LLM_PROVIDER=openai_compatible` (or `anthropic`),
  `SOC_LLM_ENDPOINT`, `SOC_LLM_AUTH_HEADER` / `SOC_LLM_AUTH_PREFIX`, `SOC_LLM_EXTRA_HEADERS`, `SOC_LLM_CA_BUNDLE`,
  `SOC_LLM_JSON_MODE`, `SOC_LLM_MAX_TOKENS_FIELD` ([DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) section 6).

## 6. Budgets and limits - set by administrators in the console

Everything below is set on *Govern -> AI usage* by an administrator (`manage_access`, step-up MFA in production); a
change is a new version, audited, in force for the next call.

| Limit | Default | Effect |
|---|---|---|
| Monthly tokens | `SOC_LLM_MONTHLY_TOKEN_BUDGET` (50,000,000) | hard cap; a finding at 80 % and 100 %; after the cap the computed / rule-written path |
| Daily tokens | a tenth of the month | no day may use more |
| Per person, per hour / day | 100,000 / 400,000 | for what a person asks (questions, explanations, drafts); overrides per role and person; 0 = no model text |
| Per feature: model | the configured default for the feature's size | any model on `SOC_LLM_MODELS`, by name |
| Per feature: longest answer | small 1,500 / large 3,000 tokens | sent to the provider as the answer cap |
| Per feature: on / off | on | off = the platform's own text always |
| `SOC_DLP_AI_MAX_PER_RUN` (setting) | 200 | DLP alerts investigated and decided by the model per job run; the rest wait |
| `SOC_DLP_INVESTIGATION_SECONDS` (setting) | 20 | one alert's investigation budget |

**Over any limit nothing fails:** the call is not sent, the caller uses its cited fallback, the refusal is logged
with its reason, and a person sees why ("Written by the platform without the model: ...").

**Choosing the model per feature:** the *By feature* table shows calls, tokens, cost, the usable rate and the share
of statements the evidence check removed, and advises *try a smaller model*, *use a larger one* or *keep* - from
figures computed in code. Change one feature at a time and compare.

Other settings: `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` (30 / 120), `SOC_LLM_BREAKER_FAILURES` /
`SOC_LLM_BREAKER_SECONDS` (3 / 60: after 3 failures the model is skipped for 60 s), `SOC_LLM_CONCURRENCY` (4),
`SOC_LLM_MODEL_VERSION` (pins), `SOC_LLM_LOG_RETENTION_DAYS` (180).

## 7. Cost: what is known and what is to be measured

The model's cost for NAM depends on NAM's DLP alert volume, the share of alerts reaching the model (capped per run),
the models NAM's region offers and their prices. **None of these is known yet, and no cost per alert is stated in
advance.** Phase 1 measures them (CLAUDE.md §0.3):

1. Alerts per day - the pilot scorecard measures it from the first week.
2. The share reaching the model and the tokens per alert - `scripts/measure_llm_usage.py` runs every feature on an
   estate and reports tokens per call; the *AI usage* screen shows the same per feature in production.
3. Cost per alert - tokens × the price of the model NAM's region offers (entered per model on *AI usage*).

The pilot scorecard then shows the model's share of decisions and its cost per alert week by week, and the monthly
budget is sized from that measurement plus headroom.

## 8. Testing the AI

| Test | Proves |
|---|---|
| `test_dlp.py` | decisions stored, discarded without citation / outcome, off / failing identical; an injected instruction cannot close what the rules escalate; sender text changes no outcome, severity or fact |
| `test_dlp_investigator.py` | menu only, budget, rules fallback, read-only, citations, the sender's text reaches the planner only inside the fence |
| `test_decisions.py` | targets, two-lead promotion, decide refused, demotion on agreement drop and on outcome shift, strict time order |
| `test_consistency.py` | figures and computed outcomes identical with the model on and off |
| `test_ciso.py`, `test_comply_pilot.py` | the brief states only computed figures; the draft cites the facts and falls back |
| `test_live_llm.py` (opt-in, costs tokens) | the gateway against a real endpoint |

Before `decide` is switched on anywhere: an adversarial DLP-content test set (messages written to talk the AI into
closing) must exist and pass, and NAM's auditors must confirm whether a named person is required on every closure (if
so, DLP stays at `recommend`).
