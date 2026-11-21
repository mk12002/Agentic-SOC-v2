# 9. Development roadmap and readiness

| | |
|---|---|
| **Document** | CyberDome for NAM - review pack, document 9 of 9 (for the customer presentation) |
| **Answers** | What is built, what is not, the roadmap by phase, dependencies on NAM, next steps |

## 9.1 Current status

| Module | Status |
|---|---|
| Dome Connect: connectors for Forcepoint DLP, Silverfort, Trend Micro, Trellix ePO, the AD / CMDB export | Built, fake mode on placeholder APIs - to be confirmed against NAM's versions |
| Dome Connect: tool health and configuration snapshots | Built (where each tool reports or exports them) |
| Plug-and-play: capability declarations on every connector, workflows by capability, readiness check, declared connectors for plain REST tools | Built (an onboarding screen and push intake for every record kind not yet) |
| Dome Graph: control coverage | Built |
| Dome Agents: DLP triage, AI investigator, earned autonomy (shadow, recommend), DLP rule changes with classification quality | Built |
| Cross-tool cases | Built (privileged check-outs wait for Arcon) |
| Dome Score, adjustable weights, CISO view, board deck and weekly brief | Built |
| Dome Comply: catalogue, evidence, audit pack, breach assessments, reportability, drafts | Built (catalogue a draft; NAM's control list and deadlines to confirm) |
| Pilot scorecard | Built |
| Platform essentials: cases, approvals, actions and policy (containment four-eyes), AI gateway and usage policy, watch lists, notifications, reports, access, audit | Built |
| Arcon, Cloudflare, SIEM / SOAR product connectors; SOAR execution (M9) | Not built (products / versions unknown) |
| The decide stage | Not built (Phase 3; gated) |

Verification: the automated suite on SQLite and PostgreSQL, the connector conformance suite, browser tours of every
screen, the NAM penetration test (round 39) and feature-by-feature verification - see `docs/TEST_REPORT.md`.

## 9.2 Roadmap

| Phase | Weeks | Build | Prove |
|---|---|---|---|
| 1 - connect and see | 1-6 | each Phase 1 connector confirmed against NAM's API (only the request code changes); fixtures from recorded responses | coverage, tool health, the DLP queue and the Dome Score on NAM's data; AI in shadow; baselines |
| 2 - triage and correlate | 7-14 | Arcon, Cloudflare, SIEM, SOAR (read) connectors; privileged check-outs in the cross-tool rules | agreement targets met; recommend stage per decision type; rule changes made and verified |
| 3 - act and prove | 15-20 | SOAR execution backend (M9); write scopes per accepted action; the adversarial DLP-content test set | approved actions executed and verified; decide stage only where earned; audit pack accepted |

## 9.3 Dependencies on NAM

The decisions in *Deployment and validation*, section 6.6 (tool versions and APIs, model region, targets, weights,
control list, baseline source, retention), the prerequisites in section 6.2, and named people: a SOC lead (targets,
promotions), a second lead (two-person approvals), the CISO (weights), the compliance team (catalogue), engineers
(tool changes).

## 9.4 Next steps

1. Agree the hosting environment and region; provision P1-P3.
2. Obtain the API documentation and read-only accounts for the Phase 1 tools; confirm each connector and run its
   preflight.
3. Connect the baseline first, then Trellix and Trend Micro, then Forcepoint, then Silverfort.
4. Week 2: capture baselines; NAM's SOC lead sets targets; the CISO agrees the weights; compliance starts
   validating the catalogue.
5. Phase 1 gate review with the CISO.
