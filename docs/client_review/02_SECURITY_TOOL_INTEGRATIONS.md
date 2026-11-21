# 2. Security tool integrations

| | |
|---|---|
| **Document** | CyberDome for NAM - review pack, document 2 of 9 |
| **Answers** | For each of NAM's tools: what CyberDome uses it for, the API and authentication, the permissions, read vs write, egress, and what is still to confirm |

## 2.1 How every integration works

| Property | How | Status |
|---|---|---|
| One connector per tool | a module that reads the tool's API, normalises records to one schema and (only where planned) offers actions | Implemented |
| Fake mode first | vendor-shaped sample responses through exactly the same parsing and action code a live tool uses | Implemented |
| Placeholders, not guesses | NAM's tool versions and licensed APIs are not yet known. Every endpoint path is a setting; the page shape and field names are marked UNVERIFIED in each module; a connector is never built from memory of a vendor's API | Implemented; To validate in NAM's environment |
| Stages | fixtures → recording (live reads saved as sanitised fixtures) → read-only → recommend (actions offered, never above L2) → automate; one approved step at a time | Implemented |
| Preflight before going live | configuration, sign-in, every stream and the permission it needs, parsing, freshness, volume - each failure with its fix | Implemented |
| Secrets | in NAM's vault, mounted as files (`<NAME>_FILE`); the console shows only *set / not set*; a configuration may only reference a secret | Implemented |
| Least privilege | a dedicated read-only account per tool; write scope only for an action NAM accepts, from Phase 3 | Configured at deployment |
| Rate limits | each tool's request budget shared across processes; `Retry-After` honoured; a refused token renewed once; a missing permission reported at once | Implemented |
| Writes | only through the action layer: policy, approval, audit; containment always four-eyes | Implemented |
| One broken tool never stops the others | a misconfigured connector is isolated with its reason; everything else works | Implemented |
| Plug-and-play by capability | each connector declares what it provides (EDR device inventory, DLP incidents, risky sign-ins, encryption state...); every module reads capabilities, never a product's name, so another product of the same kind is used everywhere once connected; `capabilities --check` names any module still lacking a capability before go-live | Implemented |
| A tool without a connector | a plain REST / JSON API can be described in a definition file - read-only, relative paths on the tool's own host, fixed field converters, no code and no secret in the file; anything else (actions, look-ups, unusual sign-in) needs a connector written once | Implemented |

## 2.2 Phase 1 tools

### Forcepoint DLP - data protection

| Item | Detail |
|---|---|
| Used for | DLP incidents (the DLP triage queue), endpoint agent check-ins (coverage: DLP agent reporting), the product's health (certificates, sync and deployment jobs, directory import), the rule configuration (change baseline, rule-change verification) |
| API and authentication | Forcepoint Security Manager REST API; an API token of a read-only application account, as a header |
| Read permissions | incident read (reports / REST API role), endpoint status read, system health read |
| Write permissions | **none** - a rule change is proposed and approved in CyberDome and made by an engineer in Forcepoint |
| Egress | the Security Manager host, 443 |
| To confirm with NAM | the version and licensed REST API; the incident export call and its date filters; whether check-ins, job state and certificate expiry are exposed; the classifier names for PAN / Aadhaar / investor data; how classifier type and OCR origin are reported |
| Status | Implemented in fake mode; To validate in NAM's environment |

### Silverfort - identity

| Item | Detail |
|---|---|
| Used for | risky authentications per person: the identity context of a DLP alert and cross-tool rule X1; the Dome Score's identity domain; policy configuration (change baseline) |
| API and authentication | Silverfort console API; API token of an application, as a header |
| Read permissions | read access to authentication risk events |
| Write permissions (Phase 3, through approval) | revoke sessions; set MFA requirements for a user - reversible, recommended at L2 |
| Egress | the Silverfort console host, 443 |
| To confirm with NAM | how risk is exported (REST API or a log forwarder), the levels and factors reported, and the revoke / MFA calls |
| Status | Implemented in fake mode; actions are placeholders; To validate in NAM's environment |

### Trend Micro - endpoint

| Item | Detail |
|---|---|
| Used for | the agent inventory and check-ins (coverage: EDR agent, silent agents), detections (cross-tool rule X3, kind `edr_alert`) |
| API and authentication | the console's API (region-specific URL); API key of a role, as a header |
| Read permissions | endpoint inventory read, detections read |
| Write permissions (Phase 3, through approval) | isolate and restore endpoints - **containment: two people always**, offered only when three or more tools agree |
| Egress | the console API host, 443 |
| To confirm with NAM | which product and version (Apex One or Vision One) and its API; the detections feed; the isolate / restore calls |
| Status | Implemented in fake mode; actions are placeholders; To validate in NAM's environment |

### Trellix ePO - disk encryption

| Item | Detail |
|---|---|
| Used for | disk-encryption state of every managed device (coverage), the server's certificates and tasks (tool health), policies (change baseline) |
| API and authentication | ePO web API; a read-only ePO user |
| Read permissions | system tree read, drive encryption query, server health read |
| Write permissions | none |
| Egress | the ePO server, 443 |
| To confirm with NAM | the ePO version and web API access; the drive-encryption query; whether certificate expiry and server-task results can be read |
| Status | Implemented in fake mode; To validate in NAM's environment |

### AD / CMDB export - the baseline

| Item | Detail |
|---|---|
| Used for | the device and people baseline every coverage figure is measured against; privileged groups; DLP policy-group membership |
| API and authentication | a service that serves the export; API key |
| Read permissions | read access to the device and user export |
| Write permissions | none |
| To confirm with NAM | which system is the baseline (AD, a CMDB or an endpoint-management export), how it is served and refreshed; the privileged groups |
| Status | Implemented in fake mode; To validate in NAM's environment |

## 2.3 Other integrations

| Tool | Used for | Authentication | Permissions | Status |
|---|---|---|---|---|
| NAM's SIEM (product unknown) | alerts pushed into the incident workflow | API key (analyst role, incident scope) in `X-API-Key` on `POST /api/v1/ingest/alerts`; field names mapped by a setting; a batch is never refused for one bad alert | push only | Implemented (generic webhook) |
| ServiceNow | tickets (create / update after approval); optional CMDB ownership | OAuth client or basic auth; a dedicated integration user | `itil` (tickets: read, and create / update after approval), `cmdb_read` | Implemented |
| Jira | tickets, as an alternative | integration user e-mail + API token | Browse projects; Create issues, Add comments, Transition issues (after approval) | Implemented |
| Ownership CSV | owners and criticality where the CMDB has none | a mounted file | file read | Implemented |
| Entra ID (sign-in, not a data source) | console sign-in, app roles | the platform's app registration | none on the directory | Configured at deployment |

## 2.4 Phase 2-3 tools (not built)

| Tool | Planned use | Planned writes | Pattern |
|---|---|---|---|
| Arcon (privileged access) | credential check-outs and sessions: the privileged-access domain of the Dome Score, cross-tool rules | check in / rotate a credential (containment: four-eyes) | the platform core's PAM connector |
| Cloudflare (WAF) | security events, certificate state: the web domain of the Dome Score | none planned | the connector scaffold |
| SOAR (product unknown) | run status; later the execution backend for approved actions (M9) | executes approved actions, still behind the action layer | the action layer's backend |

Each starts with the vendor's documentation for NAM's version, `connector new`, fixtures from recorded responses and
the same preflight.

## 2.5 What each integration can and cannot do

* No connector reads mail content, file contents or user documents. The DLP incident carries what Forcepoint reports
  about an incident (classifier names and match counts, destination, the sender, subject and file names); the
  subject and file names are kept apart as untrusted text.
* No connector follows a URL taken from data, and a vendor's next-page link is followed with credentials only on the
  tool's own host.
* Every value placed in a vendor query or URL path is escaped for that language.
* No write reaches a tool without an action request, a policy decision and a person's approval (two for containment).
