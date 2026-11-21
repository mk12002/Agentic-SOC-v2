# Connectors - CyberDome for NAM

Generated from the connector manifests by `scripts/build_connector_docs.py` - regenerate after changing a connector.
It lists the connectors of the NAM product scope (`core/scope.py:NAM_CONNECTORS`); the platform core's other
connectors exist only in the `full` scope and are not part of NAM's deployment.

## NAM's tools and their state

| Tool | Role | Phase | Connector | State |
|---|---|---|---|---|
| Forcepoint DLP | data protection | 1 | `forcepoint_dlp` | fake mode; placeholder API |
| Silverfort | identity (IAM) | 1 | `silverfort` | fake mode; placeholder API; actions are placeholders |
| Trend Micro (product to confirm) | endpoint | 1 | `trend_micro` | fake mode; placeholder API; isolate is a placeholder |
| Trellix ePO | disk encryption | 1 | `trellix_epo` | fake mode; placeholder API |
| AD / CMDB export | device and people baseline | 1 | `directory_export` (+ `cmdb_csv` ownership file) | fake mode; placeholder file shape |
| Arcon | privileged access | 2 | - | not built (the platform core's PAM connector is the pattern) |
| Cloudflare | WAF | 2 | - | not built |
| SIEM (product unknown) | logs | 2 | `generic_siem` (webhook) | generic; a product connector once known |
| SOAR (product unknown) | execution | 2-3 | - | not built (M9) |
| ServiceNow / Jira | tickets | - | `servicenow`, `jira` | inherited, unchanged |

**Placeholders.** NAM's tool versions, editions and licensed APIs are not yet known, and a connector is never built
from memory of a vendor's API. The five NAM connectors therefore share `connectors/tools/_paged.py`: every endpoint
path is a `<stream>_path` setting, the page shape `{"items", "next_page_token"}` is a placeholder and the confidence
is `Unknown`. When the vendor's documentation for NAM's installed version is in hand, only `fetch_page` and `_live`
change; the fixtures are rebuilt from recorded, sanitised responses (record-and-sanitise). Each module says what is
UNVERIFIED in its docstring.

**Modes and stages.** Every connector runs vendor-shaped fixtures through the same parsing, normalisation and action
code as live mode (`fake`). A tool then moves one approved step at a time: `record` (live reads saved as sanitised
fixtures), `read` (live, no actions), `recommend` (actions offered, never above L2), `automate` (the autonomy policy
decides). Phase 1 and 2 connectors run at `read` / `recommend`; a write is requested per action in Phase 3 through the
SOAR backend behind `ActionService`.

**Conformance.** Every connector passes `test_connector_conformance.py` (paging in its own style, resume from a
watermark never a continuation token, `Retry-After`, a refused token renewed once, a missing permission reported at
once, every field missing, null or of the wrong type) and `test_live_wire.py` (built as a live tool over HTTP from the
fixtures: same records, credentials on every request). The NAM connectors also pass `test_connector_nam_stack.py`
(paging and resume, one device across four tools, nothing added to other workflows beyond the planned actions).

**Before a tool goes live:** *Preflight* (Integrations), `python -m soc_platform preflight <name>` or
`POST /api/v1/config/connectors/{name}/preflight` checks the configuration, sign-in, every stream and the permission
it needs, parsing, freshness and volume, and says how to fix each failure. Onboarding NAM's tools step by step:
[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) section 5.

**Onboarding a tool (live):**

1. Create a dedicated service account / API client with the read scopes (write scopes only for actions NAM accepts).
2. Put the secrets in the vault (or environment) under the names *Integrations -> Configure* shows (convention
   `<CONNECTOR>_<SETTING>`); they are never typed into the console.
3. *Configure*: the non-secret settings (the confirmed endpoint paths included) and the stage **Recording** or
   **Read-only**; propose. The preflight runs on the proposal; a lead approves; it applies within seconds.
4. Check Integrations: records ingested, freshness, reconciliation against the tool's own total.
5. Promote to **Recommend**, and in Phase 3 to **Automate**, per action NAM accepts.

**Adding a tool that has no connector** (Arcon, Cloudflare, the SIEM or SOAR product):
`python -m soc_platform connector new <name> --category <cat> --tool "Vendor Product"` writes a connector that already
follows the platform's rules, its fixtures, its paging test and a switched-off config entry; then add the name to
`scope.NAM_CONNECTORS` and run `python -m soc_platform connector check <name>`.

## All connectors of the NAM scope


| Connector | Tool | Category | Streams | Lookups | Actions | Confidence |
|---|---|---|---|---|---|---|
| `cmdb_csv` | Ownership mapping (CSV) | cmdb | cmdb | host | - | High |
| `directory_export` | Directory export (devices and users) | directory | devices, users | - | - | Unknown |
| `forcepoint_dlp` | Forcepoint DLP | dlp | dlp_incidents, endpoints, health | - | - | Unknown |
| `generic_siem` | Generic SIEM/SOAR webhook | siem | pushed | - | - | High |
| `jira` | Jira (ITSM) | itsm | tickets | - | ticket.create, ticket.update | Unknown |
| `servicenow` | ServiceNow (ITSM + CMDB) | itsm | tickets, cmdb | host | ticket.create, ticket.update | Unknown |
| `silverfort` | Silverfort | identity | risk_events | - | identity.release_mfa, identity.require_mfa, identity.revoke_sessions | Unknown |
| `trellix_epo` | Trellix ePO (drive encryption) | encryption | systems, health | - | - | Unknown |
| `trend_micro` | Trend Micro endpoint security | edr | endpoints, alerts | - | endpoint.isolate, endpoint.release | Unknown |

## Per-connector setup

### Ownership mapping (CSV) (`cmdb_csv`)

Maintained hostname-pattern to owner/platform-team/criticality mapping on a mounted file (fallback for A04/D06). For cloud resources, prefer the ownership mapping uploaded on the Cloud posture screen.

- Vendor: internal · focus areas: vulnerability, incident
- Provides: cmdb.assets (cmdb)
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with NAM: -
- Configuration:
  - `path`: CSV path: hostname,owner,platform_team,environment,criticality,serial_number

### Directory export (devices and users) (`directory_export`)

The baseline of joined devices and people that control coverage is reconciled against.

- Vendor: internal · focus areas: dlp
- Provides: directory.devices (devices), directory.users (users)
- Read scopes: read access to the device and user export
- Write scopes (only for approved actions): -
- To confirm with NAM: Which system is the baseline (Active Directory, CMDB or endpoint-management export), how it is served and how often it is refreshed; the admin groups that mark a privileged account
- Configuration:
  - `base_url`: URL of the service that serves the export
  - `api_key` (secret): API key
  - `privileged_groups` (optional): Groups whose members are privileged (default: the built-in admin groups)
  - `devices_path` (optional): Endpoint path of the devices stream (default /api/v1/devices; to be confirmed against the installed version)
  - `users_path` (optional): Endpoint path of the users stream (default /api/v1/users; to be confirmed against the installed version)

### Forcepoint DLP (`forcepoint_dlp`)

Data-loss incidents, endpoint agent check-ins, and the product's certificates and sync jobs.

- Vendor: Forcepoint · focus areas: dlp
- Provides: dlp.agents (endpoints), dlp.incidents (dlp_incidents), tool.config_export (look-up), tool.health (health)
- Read scopes: incident read (reports / REST API role), endpoint status read, system health read
- Write scopes (only for approved actions): -
- To confirm with NAM: Version and licensed REST API; the incident export call and its date filters; whether endpoint check-ins, job state and certificate expiry can be read; classifier names for PAN / Aadhaar
- Configuration:
  - `base_url`: Forcepoint Security Manager API URL
  - `api_key` (secret): API token of a read-only application account
  - `user_domain` (optional): UPN suffix for bare user names
  - `dlp_incidents_path` (optional): Endpoint path of the dlp incidents stream (default /api/v1/incidents; to be confirmed against the installed version)
  - `endpoints_path` (optional): Endpoint path of the endpoints stream (default /api/v1/endpoints; to be confirmed against the installed version)
  - `health_path` (optional): Endpoint path of the health stream (default /api/v1/system/health; to be confirmed against the installed version)
  - `config_path` (optional): Endpoint path of the configuration export (default /api/v1/policies/rules; to be confirmed against the installed version)

### Generic SIEM/SOAR webhook (`generic_siem`)

Normalises alerts pushed to /api/v1/ingest/alerts from any SIEM/SOAR.

- Vendor: any · focus areas: incident
- Provides: siem.alerts (look-up)
- Read scopes: see vendor docs / to confirm
- Write scopes (only for approved actions): -
- To confirm with NAM: -
- Configuration:
  - `field_map` (optional): Mapping of platform fields to payload keys

### Jira (ITSM) (`jira`)

Remediation tickets as Jira issues with comments/status sync.

- Vendor: Atlassian · focus areas: vulnerability, incident
- Provides: itsm.tickets (tickets)
- Read scopes: Browse projects
- Write scopes (only for approved actions): Create issues, Add comments, Transition issues
- To confirm with NAM: Only if NAM uses Jira (Q03)
- Configuration:
  - `base_url`: https://<site>.atlassian.net
  - `email`: Integration user email
  - `api_token` (secret): API token
  - `project_key` (optional): Project key
  - `issue_type` (optional): Issue type for new tickets (default Task)

### ServiceNow (ITSM + CMDB) (`servicenow`)

Remediation/incident tickets with bidirectional status; CMDB ownership and criticality.

- Vendor: ServiceNow · focus areas: vulnerability, incident
- Provides: cmdb.assets (cmdb), itsm.tickets (tickets)
- Read scopes: itil (read the ticket table), cmdb_read (CMDB CI table)
- Write scopes (only for approved actions): itil (create and update tickets, work notes)
- To confirm with NAM: Which ITSM system; API access; workflow ownership (Q03)
- Configuration:
  - `instance_url`: https://<instance>.service-now.com
  - `client_id` (secret) (optional): OAuth client id
  - `client_secret` (secret) (optional): OAuth client secret
  - `username` (secret) (optional): Basic-auth integration user
  - `password` (secret) (optional): Basic-auth password
  - `ticket_table` (optional): incident | sn_vul_vulnerable_item | custom
  - `cmdb_table` (optional): CMDB CI table

### Silverfort (`silverfort`)

Risky authentications per person: the identity context of a data-loss alert.

- Vendor: Silverfort · focus areas: dlp
- Provides: identity.risk_events (risk_events), tool.config_export (look-up)
- Read scopes: read access to authentication risk events
- Write scopes (only for approved actions): revoke sessions and set MFA requirements for a user
- To confirm with NAM: How authentication risk is exported (REST API or log forwarder), the risk levels and factors reported, and - for the action rollout - the calls that revoke sessions and force MFA
- Configuration:
  - `base_url`: Silverfort console API URL
  - `api_key` (secret): API token of an application that reads risk (and revokes sessions / sets MFA, once actions are on)
  - `user_domain` (optional): UPN suffix for bare user names
  - `risk_events_path` (optional): Endpoint path of the risk events stream (default /api/v1/risk/events; to be confirmed against the installed version)
  - `config_path` (optional): Endpoint path of the configuration export (default /api/v1/policies; to be confirmed against the installed version)

### Trellix ePO (drive encryption) (`trellix_epo`)

Disk-encryption state of every managed device, and the server's certificates and tasks.

- Vendor: Trellix · focus areas: dlp
- Provides: encryption.inventory (systems), tool.config_export (look-up), tool.health (health)
- Read scopes: system tree read, drive encryption query, server health read
- Write scopes (only for approved actions): -
- To confirm with NAM: ePO version and web API access; the query for drive-encryption state; whether certificate expiry and server-task results can be read
- Configuration:
  - `base_url`: ePO server API URL
  - `api_key` (secret): Credential of a read-only ePO user
  - `systems_path` (optional): Endpoint path of the systems stream (default /api/v1/systems; to be confirmed against the installed version)
  - `health_path` (optional): Endpoint path of the health stream (default /api/v1/server/health; to be confirmed against the installed version)
  - `config_path` (optional): Endpoint path of the configuration export (default /api/v1/policies; to be confirmed against the installed version)

### Trend Micro endpoint security (`trend_micro`)

EDR agent inventory and detections: which devices are protected, when each agent last reported, what it detected; device isolation behind two approvers.

- Vendor: Trend Micro · focus areas: dlp
- Provides: edr.alerts (alerts), edr.inventory (endpoints)
- Read scopes: endpoint inventory read, detections read
- Write scopes (only for approved actions): isolate and restore endpoints
- To confirm with NAM: Which product and version (Apex One or Vision One) and its API; the detections feed; and - for the action rollout - the isolate / restore calls
- Configuration:
  - `base_url`: API URL of the console (region specific)
  - `api_key` (secret): API key of a role that reads endpoints and detections (and isolates, once actions are on)
  - `user_domain` (optional): UPN suffix for bare user names
  - `endpoints_path` (optional): Endpoint path of the endpoints stream (default /api/v1/endpoints; to be confirmed against the installed version)
  - `alerts_path` (optional): Endpoint path of the alerts stream (default /api/v1/alerts; to be confirmed against the installed version)

