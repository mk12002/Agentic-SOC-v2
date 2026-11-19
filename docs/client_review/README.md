# CyberDome for NAM - security and architecture review pack

| | |
|---|---|
| **Version** | 2.0 - 2026-11-19 |
| **Status** | For review by NAM's security, architecture, risk and compliance teams |
| **Classification** | Confidential - prepared for NAM's review |
| **Scope** | CyberDome as it would run in NAM's environment (or an Indian cloud region): architecture, integrations with NAM's security tools, data, AI, governance, deployment and validation |

## What CyberDome is, in one paragraph

An AI-first layer that runs **inside NAM's own environment** (or an Indian cloud region) above the security tools NAM
already owns - Forcepoint DLP, Silverfort, Trend Micro, Trellix ePO and the AD / CMDB export, with Arcon, Cloudflare
and NAM's SIEM and SOAR to follow. It reads those tools through their APIs, resolves every record to one device or one
person, and on that picture shows which devices miss a control and which tools are unhealthy, triages DLP incidents,
joins one person's signals from several tools into one case, scores the security posture with a formula NAM's CISO
agrees, maps evidence to SEBI CSCRF, DPDP and CERT-In, and measures the pilot. It recommends actions; **a person
approves them by default, and containment always needs two people**. An optional AI model - in NAM's environment or
an Indian region - investigates, explains and decides DLP dispositions **only as far as each decision type has earned**,
under guardrails that hold at every stage; every figure, score and severity is computed in code.

## The documents

| # | Document | Answers |
|---|---|---|
| 1 | [Solution architecture](01_SOLUTION_ARCHITECTURE.md) | What runs where; diagrams; hosting model; infrastructure components; network connectivity |
| 2 | [Security tool integrations](02_SECURITY_TOOL_INTEGRATIONS.md) | Each of NAM's tools: what it is used for, API and authentication, permissions, read vs write, egress, what is still to confirm |
| 3 | [Data flow and protection](03_DATA_FLOW_AND_PROTECTION.md) | What data is collected, processed and stored; personal data; retention and deletion; encryption; residency; every transfer outside |
| 4 | [AI / LLM security](04_AI_LLM_SECURITY.md) | Where the model runs, what it sees, what it may and may not decide, the earned-autonomy ladder, safeguards, cost and abuse controls |
| 5 | [Security risk and governance](05_SECURITY_RISK_AND_GOVERNANCE.md) | Risk assessment, access control, audit, monitoring, human approval, security testing performed |
| 6 | [Deployment and validation](06_DEPLOYMENT_AND_VALIDATION.md) | The phased pilot, prerequisites, testing method, success criteria, rollback, decisions requested |
| 7 | [Use-case mapping](07_USE_CASE_MAPPING.md) | NAM's challenges mapped to CyberDome's capabilities and expected benefits |
| 8 | [Architecture and data flow overview](08_ARCHITECTURE_AND_DATA_FLOW_OVERVIEW.md) | One view of the architecture, data flow, AI, human control and external transfers |
| 9 | [Development roadmap and readiness](09_DEVELOPMENT_ROADMAP_AND_READINESS.md) | What is built, what is not, the roadmap by phase, dependencies, next steps |

Diagrams are in [`diagrams/`](diagrams/) as SVG. A Word edition - one independent .docx per document, each readable on
its own - is generated with `python scripts/build_review_pack.py` (it embeds the diagrams).

## How to read the status statements

| Status | Meaning |
|---|---|
| **Implemented** | Built, enforced in code and covered by automated tests that run on every build (SQLite and PostgreSQL) |
| **Configured at deployment** | Built; its value is NAM's choice or comes from NAM's environment (identity provider, network, vault, retention, model region) |
| **To validate in NAM's environment** | Built and tested against vendor-shaped data, not yet against NAM's real tools, volumes or users - covered by the pilot |
| **Not built** | Planned (with its phase), or waiting on a decision by NAM |

## Evidence behind these documents

Every statement is taken from the platform's code and its engineering record; figures are measured on sample data,
never estimated, and no figure here describes NAM's estate.

| Topic | Source in the repository |
|---|---|
| Architecture, flows | `docs/ARCHITECTURE.md`, `docs/ENGINEERING.md` |
| Threat model, penetration tests | `docs/SECURITY.md` |
| The AI and its guardrails | `docs/AI_AND_AUTONOMY.md` |
| Failure behaviour | `docs/FAILURE_MODES.md` |
| Settings, jobs, monitoring, access, backups | `docs/OPERATIONS.md`, `docs/HIGH_AVAILABILITY.md` |
| Deployment and per-tool onboarding | `docs/DEPLOYMENT_GUIDE.md`, `docs/CONNECTORS.md` |
| Test rounds and results | `docs/TEST_REPORT.md`, `docs/FEATURE_VERIFICATION.md` |
| Requirement-by-requirement coverage | `docs/REQUIREMENTS_TRACEABILITY.md` |

## Open items for NAM

The questions NAM needs to answer before or during the pilot are collected in *Deployment and validation*, section 6.
