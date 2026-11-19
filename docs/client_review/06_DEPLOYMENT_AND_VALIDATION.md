# 6. Deployment and validation

| | |
|---|---|
| **Document** | CyberDome for NAM - review pack, document 6 of 9 |
| **Answers** | The controlled, phased pilot; integration prerequisites; how it is tested; success criteria; rollback; decisions requested from NAM |

## 6.1 The phased pilot

| Phase | Weeks | What is connected | What the AI does | Gate to the next phase |
|---|---|---|---|---|
| 1 - connect and see | 1-6 | Forcepoint DLP, Silverfort, Trend Micro, Trellix ePO, the AD / CMDB export - **read-only** | investigates; decides in **shadow** (beside the analyst; nothing happens) | the CISO uses one live view; baselines captured (alerts per day, share reaching the model, cost per alert) |
| 2 - triage and correlate | 7-14 | + Arcon, Cloudflare, the SIEM and SOAR (read) | a decision type may move to **recommend** when its target (set by NAM's SOC lead) is met and a second lead approves; DLP rule-change proposals | the agreement target set by NAM's SOC lead is met |
| 3 - act and prove | 15-20 | write scopes per action NAM accepts; execution through NAM's SOAR | reversible actions per type if NAM approves; **decide** only after the adversarial DLP-content test set exists and passes | the audit pack accepted |

Throughout: containment (isolate, disable, rotate) needs two people; reportability is a person's decision; every
figure is computed.

## 6.2 Integration prerequisites

| # | Prerequisite | Owner | Needed for |
|---|---|---|---|
| P1 | The hosting environment in NAM's data centre or an Indian region; a Kubernetes cluster (or Docker host) and PostgreSQL 16 | NAM infrastructure | Phase 1 |
| P2 | An Entra ID app registration with app roles; Conditional Access requiring MFA | NAM identity | Phase 1 |
| P3 | A vault for secrets, mounted as files | NAM infrastructure | Phase 1 |
| P4 | For each Phase 1 tool: the vendor's API documentation for NAM's installed version, and a read-only service account | NAM security engineering + vendors | Phase 1 |
| P5 | The baseline source (AD, CMDB or endpoint-management export) and how it is served | NAM IT | Phase 1 |
| P6 | Egress from the platform to each tool's API host (443) | NAM network | Phase 1 |
| P7 | The model decision: NAM's gateway or an Indian-region model, or none | NAM CISO / architecture | Phase 1 (optional) |
| P8 | NAM's partner domains and sanctioned services (DLP destination classes) | NAM SOC | Phase 1 |
| P9 | NAM's SIEM and SOAR products; Arcon and Cloudflare documentation | NAM security engineering | Phase 2 |
| P10 | The actions NAM accepts and their write scopes | NAM CISO | Phase 3 |

## 6.3 How it is tested

| Layer | What | Status |
|---|---|---|
| Automated suite | every module, guardrail and route; on SQLite and PostgreSQL; the NAM files also run on PostgreSQL | Implemented |
| Conformance | every connector: paging, resume, throttling, malformed fields; built as a live tool over HTTP from fixtures | Implemented |
| Browser tours | every screen in a real browser: KPIs cross-checked with the API, the lead's flows, a stored-XSS probe, a scoped analyst, 5 widths, 2 themes, accessibility | Implemented |
| Feature verification | each feature mapped to the tests that prove it (`docs/FEATURE_VERIFICATION.md`) | Implemented |
| Preflight per tool | in NAM's environment before each tool goes live | To validate in NAM's environment |
| Record and sanitise | the first live responses become sanitised fixtures, so tests run on NAM's real shapes | To validate in NAM's environment |
| Shadow mode | the AI's agreement with NAM's analysts measured from week 1 | To validate in NAM's environment |
| Load test | NAM's number of analysts against the target environment | To validate in NAM's environment |
| Failover drill | before go-live, then twice a year | To validate in NAM's environment |

## 6.4 Success criteria

Set by NAM, measured by the platform (the pilot scorecard) - **no target is preset**:

| KPI | Measured as | Target |
|---|---|---|
| DLP alerts reaching an analyst | alerts needing a person over the week up to the newest alert | set by NAM's SOC lead against the week-2 baseline |
| Alerts per day | the same week | baseline for sizing |
| Outages found by users first | the outage log | set by NAM |
| AI agreement per decision type | AI decisions matching analysts' rulings | set by NAM's SOC lead (gates recommend) |
| The model's share and cost per alert | measured weekly | NAM's budget |
| Coverage, tool health, Dome Score trend | computed daily | agreed with the CISO |

## 6.5 Rollback

| Situation | Rollback |
|---|---|
| A tool misbehaves | *Pause* the tool at once (audited); everything it would have done becomes a manual recommendation |
| A tool change is wrong | *Restore* proposes any earlier configuration version |
| The AI's agreement slips | automatic demotion; a lead can demote at once |
| A governance document is wrong (weights, catalogue, policy) | propose the previous version; a second person approves |
| Automation must stop | the kill switch (durable, every replica, immediate) |
| An action was wrong | its reverse action (itself under the policy) |
| The platform must be removed | stop the deployment; the tools are unchanged (Phase 1-2 read only); export the audit log and evidence first |

## 6.6 Decisions requested from NAM

| # | Decision | Why it matters |
|---|---|---|
| D1 | The SIEM and SOAR products | the SIEM connector beyond the webhook; the execution backend |
| D2 | Tool versions and licensed APIs; which Trend Micro product | every connector path and shape is a placeholder until confirmed |
| D3 | Where the model runs and which models that region offers (or none) | residency; cost |
| D4 | Agreement target and minimum sample per decision type | nothing is promoted until set |
| D5 | Which actions NAM accepts as reversible | the Phase 3 policy |
| D6 | Whether NAM's auditors require a named person on every closure | if yes, DLP stays at recommend |
| D7 | The Dome Score weights | agreed with the CISO, approved by two leads |
| D8 | NAM's CSCRF control list; confirmed regulatory deadlines | the catalogue is a draft; only CERT-In's 6 hours is in it, to verify |
| D9 | The baseline source (AD, CMDB or Intune export) | coverage is measured against it |
| D10 | Retention periods and legal hold | retention settings |
