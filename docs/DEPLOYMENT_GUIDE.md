# Deployment guide - CyberDome in NAM's environment

How to deploy CyberDome for NAM: hosting (NAM's environment or an Indian cloud region), the database, secrets and
production settings, Entra ID sign-in, connecting each of NAM's tools, NAM's own LLM gateway, the rollout of actions
by phase, the first syncs, the go-live checklist, and what is still to be decided with NAM. Read with
[OPERATIONS.md](OPERATIONS.md) (settings, jobs, monitoring), [HIGH_AVAILABILITY.md](HIGH_AVAILABILITY.md) (the
redundant deployment), [CONNECTORS.md](CONNECTORS.md) (each connector's settings) and
[AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md).

**Hosting and residency.** NAM's data - DLP incidents with PAN / Aadhaar classes, investor records' metadata, people
and devices - stays in India: the platform, its database and backups, and the model (when on) run in NAM's own
environment or an Indian cloud region (for Azure: Central India or South India). Raw vendor logs stay in the
deployment's region. The model is optional: `SOC_LLM_PROVIDER=none` runs every module on its computed path.

## 1. What changes between the demo and NAM's environment

| Area | Demo | Client environment | Section |
|---|---|---|---|
| Hosting | laptop, SQLite or local PostgreSQL | container host / VM / Kubernetes, PostgreSQL 16, TLS reverse proxy | 1, 2 |
| Data | `python -m soc_platform demo` loads the Acme sample organisation | **never run `demo`**; data arrives from NAM's tools | 2.4 |
| Organisation facts | `acme-demo.com`, demo suppliers | NAM's mail domains, supplier list, sanctioned SaaS list | 2.3 |
| Sign-in | dev tokens (`SOC_AUTH_MODE=dev`) | Entra ID single sign-on with app roles and MFA (`SOC_AUTH_MODE=entra`) | 3 |
| Connectors | `mode: fake` (vendor-shaped fixtures) | `mode: live` per tool, credentials from a vault | 4 |
| LLM | the developer's Azure AI Foundry deployment | NAM's own LLM gateway (Claude / Gemini / OpenAI models behind it) | 5 |
| Actions | recommended, approved in the demo | recommended only (L2) until NAM's change board promotes them | 6 |
| Secrets | `.env` on a laptop | Key Vault (or similar) mounted as files: `<NAME>_FILE` | 2.2 |

**Code changes needed:** none for a standard deployment. Everything below is configuration. The exceptions (an LLM
gateway that needs OAuth tokens instead of a static key, or a tool API NAM runs in a non-standard way) are
called out where they apply, with the file to change.

**Deployment order** (each step is usable on its own):

1. Platform up on PostgreSQL with Entra sign-in, no connectors live (section 1-3).
2. Read-only connectors, one at a time: the directory export first (the baseline), then Trellix and Trend Micro, then Forcepoint DLP, then Silverfort (5, 8).
3. The in-house LLM (5). The platform is fully functional before this; the LLM only adds narrative.
4. Write permissions and action rollout, per action type, through the autonomy policy (6).

---

## 2. Target architecture

```text
                        Analysts' browsers (Entra SSO + MFA)
                                     │ HTTPS
                          ┌──────────▼──────────┐
                          │ TLS reverse proxy /  │  (App Gateway, nginx, IIS ARR...)
                          │ WAF                  │
                          └──────────┬──────────┘
                                     │ HTTP 8080 (private)
             ┌───────────────────────▼───────────────────────┐
             │ platform-api   (python -m soc_platform serve)  │──┐
             │ platform-scheduler (python -m soc_platform     │  │ outbound HTTPS only:
             │                     scheduler)                  │  │  - vendor APIs (section 4)
             └───────────────┬────────────────────────────────┘  │  - client LLM gateway (section 5)
                             │                                    │  - Entra ID (login.microsoftonline.com)
                    ┌────────▼────────┐                          │
                    │ PostgreSQL 16    │                          │
                    └─────────────────┘                          │
             Secrets: Key Vault → files mounted at /run/secrets ──┘
```

- **Images:** `deploy/Dockerfile` (multi-stage, non-root user `soc`, port 8080). The NAM scope does not need the inherited phishing ML engine:
  build the default image (`docker build -f deploy/Dockerfile -t soc-platform:<tag> .`).
- **Compose reference:** `deploy/docker-compose.yml` (`postgres`, `platform-api`, `platform-scheduler`; the
  `engine` profile services are the ML engine's own legacy services and are **not** needed - the engine runs inside
  the platform process).
- **Windows hosts** are supported (the platform is developed and fully tested on Windows 11 with SQLite and
  PostgreSQL); containers on Linux are the recommended production shape.
- **High availability and scaling:** the API is stateless (any number of replicas behind the proxy) and schedulers
  take renewed database leases, so several are safe and a dead one's job is taken over within two minutes. Set
  `SOC_BLOB_STORE=database` so stored e-mails and reports are in PostgreSQL, readable by every replica. The
  Kubernetes package (`deploy/kubernetes`, Azure and on-prem overlays), the reference topologies, the connection budget,
  recovery targets and the failover drill are in `docs/HIGH_AVAILABILITY.md`. The image runs `SOC_API_WORKERS=4` processes; give one per CPU core and keep
  `workers x (SOC_DB_POOL_SIZE + SOC_DB_MAX_OVERFLOW)` under PostgreSQL's `max_connections`. Measured on a laptop
  ([OPERATIONS.md](OPERATIONS.md) - Server and database under load, Connector sync and volume): four processes served 100
  concurrent analysts at 150 requests/s with no error; sync stores about 146 records/s on SQLite and about 75 on a
  local PostgreSQL, flat as the estate grows. NAM's own volume is measured during deployment
  (`scripts/measure_scale.py`, `scripts/load_test.py` against the target environment).
- **Inbound:** only the reverse proxy reaches port 8080. Nothing in the platform accepts connections from the tools
  except the optional SIEM push endpoint (`POST /api/v1/ingest/alerts`, authenticated with an API key).
- **Outbound:** HTTPS to the hosts listed per connector in section 4, the LLM gateway, and Entra ID. Nothing ever
  fetches URLs found in e-mail content (no SSRF surface), and the ML engine makes no outbound calls at all.
- **WAF and DDoS protection:** put the console behind NAM's web application firewall / reverse proxy (Azure
  Application Gateway WAF, Front Door or the on-premises equivalent) with TLS; the platform adds its own rate limit,
  request-size cap and security headers. Keep the console off the internet where possible (internal network / VPN).
- **Logs to the SIEM:** collect every container's stdout (`SOC_LOG_FORMAT=json`) and the audit export into the
  NAM's SIEM (through its own log agent), so the SOC monitors the platform itself.
- **Encryption at rest:** files the platform writes (raw payloads, reported e-mail, reports) are encrypted with
  `SOC_DATA_KEY`; the database is protected by the managed PostgreSQL service's encryption or encrypted volumes
  (Azure Disk Encryption / BitLocker / LUKS) - confirm one is on before go-live.

---

## 3. Install and base configuration

### 3.1 Database

PostgreSQL 16, a dedicated database and **two** logins - one that owns the schema, one the platform runs as:

```sql
CREATE ROLE soc LOGIN PASSWORD '<from vault>';            -- schema owner: used only by init-db
CREATE ROLE soc_app LOGIN PASSWORD '<from vault>';        -- the running platform
CREATE DATABASE soc_platform OWNER soc;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE soc_platform TO soc_app;
```

Both URLs verify the server's certificate: `?sslmode=verify-full&sslrootcert=system` for a managed server with a
public CA chain (Azure Flexible Server), or `sslrootcert=<path to the CA>` for your own. Production refuses any other
`sslmode` (libpq's default `prefer` can be downgraded or intercepted). The URLs carry passwords, so keep them in the
vault and mount them: `SOC_DATABASE_URL_FILE=/run/secrets/db_url` (runtime) for the platform, and the owner's URL only
for the migration step:

```bash
SOC_DATABASE_URL_FILE=/run/secrets/db_owner_url SOC_DB_RUNTIME_ROLE=soc_app python -m soc_platform init-db
# creates / extends the tables, then grants soc_app read / write on every table, SELECT + INSERT only on audit_log
# (a database trigger refuses UPDATE / DELETE / TRUNCATE on it too) and no schema rights
```

The platform's processes then run with `SOC_SCHEMA_MANAGE=0` (they only check the schema exists). Allow-list the
`pg_trgm` extension (Azure: server parameter `azure.extensions`; deploy/azure/main.bicep does): it backs the search
box's indexes, and without it search scans tables.

Upgrades: `init-db` (the migration step, run before the new version's pods start) creates new tables, adds new
*nullable* columns and widens text columns on existing databases. There is no migration framework, so a release that adds a required column, renames or drops one will
say so and ship a scripted migration.

### 3.2 Secrets

Every secret setting can be supplied as `<NAME>_FILE` pointing at a mounted file (Key Vault CSI driver, Docker/K8s
secrets). Connector settings in `config/connectors.yaml` use `${ENV_NAME}`, and `ENV_NAME_FILE` works for those too.
Never write a literal secret into `connectors.yaml`.

Generate the platform's own keys once:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # SOC_DATA_KEY
python -c "import secrets; print(secrets.token_urlsafe(48))"                                # break-glass secret
python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '<break-glass secret>'
```

Store the break-glass secret sealed (two-person), and give the platform only its SHA-256 (`SOC_BREAKGLASS_SHA256`).

On Azure, keep every secret in Key Vault and mount it as a file (the overlay does this; nothing is synced into a
Kubernetes Secret, so no secret value sits in etcd). Connector secrets the same way: add the object to
`keyvault-secrets.yaml` and set `<ENV_NAME>_FILE=/mnt/secrets/<object>` in the settings ConfigMap.

### 3.3 Production settings

The minimum production environment (all names are real settings; full list in `.env.example` and
[OPERATIONS.md](OPERATIONS.md)):

```bash
SOC_ENVIRONMENT=prod                      # refuses dev tokens and time-travel test settings; requires SOC_DATA_KEY
SOC_DATABASE_URL_FILE=/run/secrets/db_url  # the runtime role, ?sslmode=verify-full&sslrootcert=...
SOC_SCHEMA_MANAGE=0                       # init-db (schema owner) changes the schema; the platform never does
SOC_DATA_KEY_FILE=/run/secrets/data_key   # encryption at rest for raw payloads and reported e-mails
SOC_ORG_DOMAINS=client.com,client.co.in,client.onmicrosoft.com   # every internal mail domain incl. the tenant's
SOC_CONNECTOR_MODE=live                   # default mode; each connector can still override in connectors.yaml
SOC_CONNECTORS_CONFIG=/app/config/connectors.yaml
SOC_PUBLIC_URL=https://cyberdome.nam.example     # links in notifications
SOC_TRUSTED_PROXIES=10.0.0.0/24          # the reverse proxy's address or subnet (X-Forwarded-For is trusted only from it)
SOC_BREAKGLASS_SHA256_FILE=/run/secrets/breakglass_sha256
SOC_BLOB_STORE=database                   # stored e-mails and reports in PostgreSQL (several hosts; HIGH_AVAILABILITY.md)
SOC_RAW_PAYLOAD_DIR=/data/raw             # scratch with the database store; the store itself with SOC_BLOB_STORE=file
SOC_REPORT_OUTPUT_DIR=/data/reports
SSL_CERT_FILE=/etc/ssl/certs/client-ca-bundle.pem   # only if internal consoles or the LLM gateway use a corporate CA
# identity: section 4; connectors: section 5; LLM: section 6
```

Organisation facts to replace (files under `config/`, mounted into the container):

| File / setting | What to put in it |
|---|---|
| `config/suppliers.yaml` (+ `SOC_SUPPLIER_DOMAINS`) | NAM's real suppliers and their domains - used to recognise supplier impersonation and look-alike domains |
| `config/sanctioned_services.yaml` | SaaS NAM has approved - everything else seen in DNS is reported as shadow IT |
| `config/connectors.yaml` | which tools exist (`enabled`), `mode: live`, and `${ENV}` references (section 4) |
| `SOC_ORG_DOMAINS` | all internal mail domains |

### 3.4 First start

The packaged ways are the Kubernetes overlays (`deploy/kubernetes`, HIGH_AVAILABILITY.md; on Azure the resources come
from `deploy/azure/main.bicep`) and, for one host, `deploy/docker-compose.yml` (production defaults; TLS to
PostgreSQL, the role split, a TLS proxy and nightly dumps as profiles). By hand:

```bash
SOC_DATABASE_URL_FILE=/run/secrets/db_owner_url SOC_DB_RUNTIME_ROLE=soc_app python -m soc_platform init-db
python -m soc_platform serve            # API + console + embedded scheduler, or:
SOC_EMBEDDED_SCHEDULER=0 python -m soc_platform serve   &   python -m soc_platform scheduler
```

- **Do not run `demo` or `reset-demo`** in NAM environment (`reset-demo` refuses in prod anyway).
- Check `GET /health` signed in (database, audit chain, kill switch; anonymous callers only get "ok") and
  `GET /api/v1/admin/self-check` (cross-surface consistency proof) after the first syncs.
- The inherited phishing ML engine never loads in the NAM scope (`SOC_PRODUCT_SCOPE=nam`), whatever
  `SOC_PHISHING_ENGINE` says.

---

## 4. Identity and sign-in (Entra ID)

The API validates Entra ID v2.0 access tokens (RS256, tenant JWKS, audience, issuer, expiry); the console signs users
in with the Entra authorization-code flow with PKCE. Roles come from **app roles** on the platform's app registration.

> Verification status: the token validation is covered by tests; the console's sign-in flow is implemented to the
> documented Entra v2.0 SPA flow and unit-tested for its configuration, but it can only be exercised end to end in a
> real tenant. Test it on day one (3.4).

### 4.1 App registration (one registration for API and console)

In NAM's Entra admin centre → App registrations → New registration:

1. **Name:** `SOC Platform`. Supported account types: this organisation only.
2. **Expose an API:** set the Application ID URI to `api://<application-id>` (the default). Add a scope, e.g.
   `access_as_user` (admins and users can consent).
3. **Manifest:** set `"requestedAccessTokenVersion": 2` (older portals: `accessTokenAcceptedVersion`). The platform
   accepts v2.0 tokens (issuer `https://login.microsoftonline.com/<tenant>/v2.0`) and the tenant's v1 tokens
   (`https://sts.windows.net/<tenant>/`), with a minute of clock-skew leeway; any other tenant is refused.
4. **Authentication → Add a platform → Single-page application:** redirect URI `https://cyberdome.nam.example/` (the
   console's origin followed by `/`). Also add it as the front-channel logout URL if desired.
5. **API permissions:** add `SOC Platform → access_as_user` (delegated) and grant admin consent.
6. **App roles** (Allowed member types: **Users/Groups** only - an application holding an app role is treated as a
   service account by the platform anyway: a token without a delegated scope can never approve, change policy or
   manage access):

| App role value | Platform role | Scope |
|---|---|---|
| `SOC.Analyst` | analyst - investigate, request actions | all domains |
| `SOC.Lead` | lead - approve actions, approve policy | all domains |
| `SOC.Admin` | admin - access management | all domains |
| `SOC.Automation_Admin` | automation_admin - connectors, propose policy (cannot approve) | all domains |
| `SOC.Auditor` | auditor - read-only incl. audit log and evidence export | all domains |
| `SOC.Analyst.Dlp`, `SOC.Lead.Incident`, ... | the same role limited to one domain | `Dlp` / `Incident` |

7. **Enterprise applications → SOC Platform → Users and groups:** assign security groups to the roles
   (e.g. `SG-SOC-L1` → `SOC.Analyst`, `SG-SOC-Leads` → `SOC.Lead`). Set "Assignment required" = Yes.
8. **Conditional Access:** require MFA for the app. For step-up on sensitive operations (approvals, policy, kill
   switch, access management) the platform checks the token's `amr` for `mfa`, or a Conditional Access authentication
   context: create one (e.g. `c1`) and set `SOC_MFA_AUTH_CONTEXT=c1`.

### 4.2 Settings

```bash
SOC_AUTH_MODE=entra
SOC_ENTRA_TENANT_ID=<tenant id>
SOC_ENTRA_AUDIENCE=api://<application id>
# only if the console has its OWN registration instead of sharing the API's:
# SOC_ENTRA_SPA_CLIENT_ID=<console app id>
# SOC_ENTRA_SCOPE=api://<api app id>/access_as_user      (default: <audience>/.default)
SOC_REQUIRE_MFA=1                          # default in prod
```

The console fetches `GET /api/v1/auth/config` (tenant, client id, scope - public values), sends the user to
`login.microsoftonline.com`, redeems the code with PKCE, and uses the access token for the API. When the token
expires the user presses *Sign in with Microsoft* again (Entra keeps the session, so it is one click). *Sign out*
ends the Entra session too.

### 4.3 Service accounts and break-glass

- **API keys** (Access screen → API keys): for the Prometheus scraper (auditor, all domains), a SIEM pushing alerts
  (analyst, incident domain), automation. Keys are hashed, expire within 365 days, and can never approve actions,
  change policy or manage access.
- **Break-glass:** `POST /api/v1/auth/break-glass` with the header `X-Break-Glass: <secret>`, verified against
  `SOC_BREAKGLASS_SHA256`, returns a 15-minute Bearer token (the secret is accepted nowhere else). Every use is
  audited and raises a critical finding; failed guesses are throttled per address. Test it once, then re-seal.
- **Privileged platform grants** (lead, admin, automation_admin on the Access screen) need a second administrator's
  approval and expire within 90 days. Prefer Entra app-role assignments through PIM for standing access.

### 4.4 Day-one sign-in test

1. Open `https://cyberdome.nam.example/` → *Sign in with Microsoft* → MFA prompt → Overview loads.
2. `GET /api/v1/me` (browser dev tools, or the Access screen) shows the expected roles and `role_scopes`.
3. A user with only `SOC.Analyst.Dlp` sees data protection only; a cross-tool (incident) case URL answers 404 and the Dome Score explains it needs all-domain access.
4. `GET /api/v1/dev/token` answers 404.
5. Failures: `401` from every call = audience/issuer mismatch (check `requestedAccessTokenVersion: 2` and
   `SOC_ENTRA_AUDIENCE`); roles empty = users not assigned to app roles; sign-in page error `AADSTS50011` = redirect
   URI not registered exactly as the console origin + `/`.

---

Roles for NAM: `SOC.Lead`, `SOC.Analyst`, `SOC.Auditor`, `SOC.Admin`, `SOC.AutomationAdmin` (all domains), or scoped
`SOC.<Role>.Dlp` / `SOC.<Role>.Incident`. The Dome Score, Dome Comply and Pilot screens need all-domain scope; the
two-lead approvals (weights, catalogue, promotions) need at least two all-domain leads.

## 5. Connecting NAM's tools

### 5.1 The procedure for every tool

Before the first tool, and after every change of tools: `python -m soc_platform capabilities --check` lists what each
switched-on tool provides and names any module whose required capability no tool provides yet (exit 1). A tool NAM
owns that has no connector but a plain REST / JSON API can be added from a definition file (section 5.12).

1. **Create a dedicated identity** in the tool (service principal / API client / integration user) with the **read**
   permissions listed below. Add write permissions only for action types NAM has approved (section 6).
2. **Store the credentials** in the vault; expose them to the container as the environment variables (or `_FILE`
   mounts) named in the tool's section - *Integrations → Configure* shows the exact names and whether each is set.
   Secrets are never typed into the console or stored by the platform.
3. **Allow outbound HTTPS** from the platform to the tool's hosts.
4. **Configure and promote it in the console** (*Integrations → Configure*): enter the non-secret settings (base URL,
   tenant id, mailbox...), choose the stage **Recording** (live reads, responses saved as sanitised fixtures, no
   actions) or **Read-only**, and propose. The **preflight** runs on the proposal - sign-in, every stream and the
   permission it needs, parsing, data freshness, clock, expected volume - and refuses it with the fix if anything is
   wrong. A lead approves (never the proposer); it applies within seconds, no restart. Tools NAM does not own:
   switch them off (they disappear from every workflow and dashboard). The same can be done in
   `config/connectors.yaml` (`stage: read`) for the deployment baseline; `python -m soc_platform config check` and
   `python -m soc_platform preflight <name>` give the same checks from a shell.
5. **Check** the Integrations screen: records ingested, freshness per stream, and reconciliation against the tool's
   own total where the tool reports one; then the resolution queue (Overview → *Awaiting resolution*, or
   `GET /api/v1/resolution/unresolved`) for identity/asset matches needing review.
6. Leave it running on the scheduler for a day before enabling the next tool, so problems have one cause.
7. **Promote** when NAM approves its actions: **Recommend** (every action offered, a person approves each -
   never above L2 whatever the policy says), later **Automate** (the autonomy policy decides, section 6). A tool that
   misbehaves can be **paused** at once from the same screen (audited; switching it back on is approved).

All connectors share: a per-connector token-bucket rate limit (never exceeds the vendor's budget, even with parallel
lookups), retries with back-off that honour `Retry-After` (seconds or a date, capped at 120 s), a refused token (401)
renewed once and the call repeated, a missing permission (403) reported at once - not retried - with the scopes to
grant (the preflight names the stream, the permission and the scopes), an HTML page answering instead of the API (a proxy
or login page) reported as such, and a circuit that marks the connector *error* on the Integrations screen instead of
failing workflows. A tool being down makes the affected evidence "unavailable" in the case; it never changes a
verdict silently.

**Resuming.** Event streams (DLP incidents, risky authentications, endpoint alerts, tickets) resume
from the newest change time seen, minus a 30-minute overlap for logs indexed late (`SOC_WATERMARK_OVERLAP_MINUTES`):
a sync reads what is new, not 30 days again. Inventories (users, machines, assets, CMDB, findings) are read in full
each sync. A continuation token is never kept between syncs (Graph and Jira tokens expire). Each page is committed as
it is stored, so the first backfill of a large tenant can be interrupted and resumes after its last page; a backlog
beyond `SOC_SYNC_MAX_PAGES` (1,000 pages per stream per sync) continues on the next sync.

Data formats: each connector parses the vendor's documented response shapes. They were audited field by field
against the vendors' public documentation and public reference integrations, and every connector passes a
conformance suite (`soc_platform/tests/test_connector_conformance.py`): reading across pages in its vendor's paging
style, resuming correctly, throttling, a refused token, a missing permission, and every field of every record missing
or null. What remains is running each connector against NAM's real tenant - step 5 above.

**Record the first live responses.** Put each tool in the **Recording** stage for its first syncs (or set
`SOC_RECORD_FIXTURES_DIR` for every live tool; [OPERATIONS.md](OPERATIONS.md) - Recording): every live response is written,
sanitised, as a test fixture. The pseudonym key comes from `SOC_RECORD_SALT`, else from `SOC_DATA_KEY`. After review of the
files and of `_scan.json` (and NAM's approval), the recordings let a connector fix be tested against the
tenant's real shapes, optional fields and oddities without access to the tenant.

**Before any NAM tool goes live** (CLAUDE.md §0.1): NAM's tool versions, editions and licensed APIs are not yet
known. For each tool, obtain the vendor's API documentation for NAM's installed version, confirm every placeholder
below (paths, page shape, field names, the permission each call needs), adapt the connector's `fetch_page` / `_live`,
record and sanitise the first live responses as fixtures, and run the preflight. Until then the connector stays at
stage `fake`. Every endpoint path is a setting (`<stream>_path`, `config_path`) so a confirmed path needs no code.

| Tool | Connector | Phase | Read scope to request | Write scope (only when NAM accepts the action) | Secret setting |
|---|---|---|---|---|---|
| AD / CMDB export | `directory_export` | 1 | read access to the device and user export | - | `DIRECTORY_EXPORT_API_KEY` |
| Forcepoint DLP | `forcepoint_dlp` | 1 | incident read (reports / REST API role), endpoint status read, system health read | - (rule changes are made by an engineer in Forcepoint) | `FORCEPOINT_DLP_API_KEY` |
| Silverfort | `silverfort` | 1 | read access to authentication risk events | revoke sessions, set MFA requirements for a user | `SILVERFORT_API_KEY` |
| Trend Micro | `trend_micro` | 1 | endpoint inventory read, detections read | isolate and restore endpoints | `TREND_MICRO_API_KEY` |
| Trellix ePO | `trellix_epo` | 1 | system tree read, drive encryption query, server health read | - | `TRELLIX_EPO_API_KEY` |

(Secret names follow the convention `<CONNECTOR>_<SETTING>`; *Integrations -> Configure* shows the exact names.)

### 5.2 AD / CMDB export (`directory_export`) - the baseline

The device and people baseline every coverage figure is measured against. It is read first on every start
(`inventory` job) so devices that events only name resolve onto it.

* **To confirm with NAM:** which system is the baseline (Active Directory, a CMDB or an endpoint-management export),
  how it is served and how often it is refreshed; the admin groups that mark a privileged account; the DLP
  policy-group membership attribute.
* **Settings:** `base_url` (the service that serves the export), `api_key` (secret), `privileged_groups` (default:
  the built-in admin groups), `devices_path` (default `/api/v1/devices`), `users_path` (default `/api/v1/users`).
* **Streams:** `devices` (in full), `users` (in full, with group membership).
* **Check after the first sync:** *Dome Graph · coverage* shows the baseline's device count; "not in the baseline"
  lists devices a tool sees that the export lacks - a long list means the export is incomplete.

### 5.3 Forcepoint DLP (`forcepoint_dlp`)

* **To confirm with NAM:** the version and licensed REST API; the incident export call and its date filters; whether
  endpoint check-ins, job state and certificate expiry can be read at all; the classifier names used for PAN /
  Aadhaar / investor data; how a classifier's type (pattern, dictionary, fingerprint, exact data match) and a match
  found in an image (OCR) are reported - both feed the classification-quality findings.
* **Settings:** `base_url` (Forcepoint Security Manager API URL), `api_key` (secret: a read-only application
  account), `user_domain` (UPN suffix for bare user names), `dlp_incidents_path` (default `/api/v1/incidents`),
  `endpoints_path` (`/api/v1/endpoints`), `health_path` (`/api/v1/system/health`), `config_path`
  (`/api/v1/policies/rules`).
* **Streams:** `dlp_incidents` (events, resumed from the newest change with an overlap), `endpoints` (agent
  inventory, in full), `health`; the rule configuration is read by the daily snapshot job.
* **Writes:** none. A rule change is proposed and approved in CyberDome and made by an engineer in Forcepoint.
* **Check after the first sync:** the DLP queue fills; rulings already given in Forcepoint appear as the analyst's;
  *Dome Connect · changes* shows a first snapshot of the rules.

### 5.4 Silverfort (`silverfort`)

* **To confirm with NAM:** how authentication risk is exported (REST API or a log forwarder), the risk levels and
  factors reported, and - for Phase 3 - the calls that revoke sessions and force MFA.
* **Settings:** `base_url`, `api_key` (secret: an application that reads risk, and revokes sessions / sets MFA once
  actions are on), `user_domain`, `risk_events_path` (default `/api/v1/risk/events`), `config_path`
  (`/api/v1/policies`).
* **Streams:** `risk_events` (kind `auth_risk`); policies by the snapshot job.
* **Actions (Phase 3, through approval):** `identity.revoke_sessions`, `identity.require_mfa` /
  `identity.release_mfa` - reversible, recommended at L2. The write calls are placeholders.

### 5.5 Trend Micro (`trend_micro`)

* **To confirm with NAM:** which product and version (Apex One or Vision One) and its API; the detections feed; and -
  for Phase 3 - the isolate / restore calls.
* **Settings:** `base_url` (region-specific console API), `api_key` (secret: a role that reads endpoints and
  detections, and isolates once actions are on), `user_domain`, `endpoints_path` (default `/api/v1/endpoints`),
  `alerts_path` (`/api/v1/alerts`).
* **Streams:** `endpoints` (agent inventory and check-ins), `alerts` (kind `edr_alert`, read by the cross-tool rules).
* **Actions:** `endpoint.isolate` / `endpoint.release` - **containment: two people always**, offered only when three
  or more tools agree on a cross-tool case. The write calls are placeholders.

### 5.6 Trellix ePO (`trellix_epo`)

* **To confirm with NAM:** the ePO version and web API access; the query for drive-encryption state; whether
  certificate expiry and server-task results can be read.
* **Settings:** `base_url` (ePO server API), `api_key` (secret: a read-only ePO user), `systems_path` (default
  `/api/v1/systems`), `health_path` (`/api/v1/server/health`), `config_path` (`/api/v1/policies`).
* **Streams:** `systems` (devices and encryption state, in full), `health`; policies by the snapshot job.
* **Writes:** none.

**Phase 2 tools** (not built): Arcon (privileged access; the platform core's PAM connector is the pattern),
Cloudflare (WAF security events, certificate state), NAM's SIEM product (until then the generic webhook, 5.10) and
SOAR (read run status; later the execution backend, M9). Each starts with `connector new`, its vendor documentation
and the same procedure.


### 5.7 ServiceNow (`servicenow`) - tickets and CMDB

**Used for:** remediation / incident tickets with status sync back, and the CMDB for owner, support group,
criticality and location of each host (the owner shown on cases and coverage).

**Create:** an integration user (web-service access only) with roles `itil` (read/create/update the ticket table)
and `cmdb_read`. OAuth: *System OAuth → Application Registry* → client credentials (NAM-credentials grant
must be enabled on the instance - it exists only in recent ServiceNow releases); otherwise basic auth for the
integration user.

**Settings:** `SERVICENOW_INSTANCE_URL`, either `SERVICENOW_CLIENT_ID` + `SERVICENOW_CLIENT_SECRET` or
`SERVICENOW_USERNAME` + `SERVICENOW_PASSWORD`, optional `SERVICENOW_TICKET_TABLE` (`incident` by default,
a custom table), optional `SERVICENOW_CMDB_TABLE` (default
`cmdb_ci_computer`).

**Egress:** `<instance>.service-now.com`.

**Notes:** reads use `sysparm_display_value=all`, so codes and UTC timestamps come from the raw values and names from
the display values (display timestamps would be in the integration user's timezone). If NAM's CMDB uses other
field names for criticality or environment, map them in `normalize` / `owner_for` in
`soc_platform/connectors/tools/itsm.py`.

### 5.8 Jira (`jira`) - alternative ticketing

Only if NAM tickets in Jira instead of ServiceNow (enable one of them). Integration user with *Browse
projects*, *Create issues*, *Add comments*, *Transition issues* on the SOC project; an API token.
Settings: `JIRA_BASE_URL` (`https://<site>.atlassian.net`), `JIRA_EMAIL`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY`.
Uses the current `/rest/api/3/search/jql` endpoint (the old `/search` was removed by Atlassian). Atlassian API
tokens now expire (at most a year): note the expiry date and rotate the token before it. Egress: the site host.

### 5.9 Ownership CSV (`cmdb_csv`) - fallback CMDB

If there is no usable CMDB: a maintained CSV `hostname,owner,platform_team,environment,criticality,serial_number`
(hostname may be a pattern), path in `CMDB_CSV_PATH`. Can run alongside ServiceNow as a gap-filler. Save it from
Excel as it comes: UTF-8 (with or without the byte-order mark) or Windows-1252, separated by commas, semicolons, tabs
or pipes; headers in any case or spacing, and the usual aliases (`Host Name`, `Server`, `Owner Email`, `Team`, `Env`,
`Serial`, `Subscription ID`) are recognised. A file with neither a hostname nor a subscription column is reported in
the log and assigns no owners. The file is re-read when it changes; no restart is needed.

**Or the ownership upload** (`POST /api/v1/ownership/upload`; its screen is not offered in the NAM scope): the same idea without a file on the host - Excel or CSV, stored in the database (so every replica and the scheduler use it), previewed, versioned and audited, with resource / subscription / cloud / resource-type matching that cloud names need (the file connector cuts names at the first dot). Wiz has no CMDB of its own: ask the cloud teams for a sheet of subscription or resource -> owning team before go-live ([OPERATIONS.md](OPERATIONS.md) - Ownership mapping).

### 5.10 NAM's SIEM (`generic_siem`)

**NAM's SIEM (push), until its product is known:** create an API key (analyst role, incident domain) and have the SIEM POST
`{"alerts": [ ... ]}` to `https://cyberdome.nam.example/api/v1/ingest/alerts` with header `X-API-Key`. Replays are
de-duplicated. If its field names differ from the defaults (`id, title, severity, timestamp, host, user, src_ip,
dst_ip, domain, url, sha256, source`), set `GENERIC_SIEM_FIELD_MAP` to a JSON object, e.g.
`{"id": "alert_id", "title": "rule_name", "time": "event_time"}`. Nested payloads are mapped with dotted paths
(Elastic Security: `{"id": "kibana.alert.uuid", "title": "kibana.alert.rule.name", "host": "host.name",
"user": "user.name"}`); `soc_platform/fixtures/generic_siem.json` has worked samples for a flat payload, a Splunk ES
notable and an Elastic Security alert. The response is `{"ingested": n, "rejected": n, "reasons": [...]}`: an alert
without its id is refused with the reason while the rest of the batch lands, so the SIEM should not resend the batch
on a partial rejection (an `ingest.rejected` line is also logged).

### 5.12 A tool without a connector (declared connector)

When NAM runs a product the platform has no connector for and it offers a plain REST / JSON API, describe it in a
definition file (`config/connectors.d/<name>.yaml`; example in `config/connectors.d/examples/`): the sign-in type,
and for each capability it provides the path, paging, identifier, time and field mapping - written against the
vendor's documentation for NAM's version. `python -m soc_platform connector validate <file>` checks it and reads its
fixture file; then follow section 5.1 (credentials as `${VAR}` references, preflight, a lead's approval, stages). A
declared connector reads only; actions, look-ups and unusual APIs (asynchronous jobs, non-standard sign-in) need a
code connector.

### 5.11 Outbound allow-list

The platform calls out only to what is configured. Allow, from the platform's pods / hosts:

| Destination | Why | When |
|---|---|---|
| Each NAM tool's API host (`base_url` of `directory_export`, `forcepoint_dlp`, `silverfort`, `trend_micro`, `trellix_epo`) | reads; in Phase 3 the approved actions | once the tool is past `fake` |
| ServiceNow / Jira instance | tickets | if used |
| `login.microsoftonline.com` | Entra sign-in keys (JWKS) | always (production) |
| The model endpoint (NAM's gateway, or the Indian-region model) | narrative, the AI's decisions and plans | only if `SOC_LLM_PROVIDER` is set; must be in `SOC_LLM_APPROVED_ENDPOINTS` |
| Notification webhooks (Teams / Slack / SIEM) | findings above the threshold | if `SOC_NOTIFY_WEBHOOKS` is set (https only) |

Nothing else: no public intelligence feed, no URL taken from a message, no telemetry. NAM's SIEM pushes **into**
the platform (5.10); the SOAR will be called by the platform once M9 exists.

## 6. Connecting NAM's own LLM gateway

### 6.1 What the LLM does here (and what it never does)

The platform works completely without an LLM. With one, it writes narrative (case accounts, the Dome Score in plain
words, report commentary, a regulator's draft, answers in analyst Q&A), chooses read-only look-ups for a DLP
investigation from a fixed menu, and gives its own close / escalate decision on DLP alerts - stored beside the
computed one, and acting only once that decision type is promoted (shadow and recommend only in this version; decide
is refused in code). **It never produces a figure, score or severity**, and never decides containment or
reportability. A numeric-fidelity guardrail drops any sentence whose figures are not in the cited evidence, uncited
claims are dropped, and with the model off every figure, severity and computed outcome is identical (a test proves
it). Details: [AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md).

Every prompt passes through the platform's gateway (`soc_platform/llm/gateway.py`): pseudonymisation of internal
identities before the call and restoration after, a monthly token budget, a circuit breaker, bounded timeouts, an
approved-endpoint allow-list, model-version pinning, and a log of every call (redacted prompt, response, tokens,
latency) kept for `SOC_LLM_LOG_RETENTION_DAYS`.

### 6.2 Replacing the demo Azure model

The demo uses the developer's own Azure AI Foundry deployment (`SOC_LLM_PROVIDER=azure_foundry`). In NAM
environment:

1. **Remove** every demo LLM value: `SOC_LLM_ENDPOINT`, `SOC_LLM_API_KEY`, `SOC_LLM_DEPLOYMENT*`,
   `SOC_LLM_APPROVED_ENDPOINTS`, `SOC_LLM_MODEL_VERSION`. Nothing of the demo Azure resource may remain in NAM
   configuration, and the demo key must never be copied into NAM's vault. Rotate the demo key after the
   hand-over if it was ever on a shared machine.
2. **Configure NAM's gateway** as below. No code changes are needed when the gateway speaks either of the two
   protocols the platform supports.

### 6.3 Which provider setting to use

NAM's platform gives access to Claude, Gemini and OpenAI models. The question is which **API shape** its
backend endpoint exposes:

| The gateway exposes | `SOC_LLM_PROVIDER` | Works for |
|---|---|---|
| OpenAI-style `POST .../v1/chat/completions` (most multi-vendor gateways: LiteLLM, Portkey, Kong AI, Azure APIM AI gateway, custom) | `openai_compatible` | any model behind it - Claude, Gemini and OpenAI models are all selected by model name |
| The Claude Messages API (`POST .../v1/messages`) | `anthropic` | Claude models |
| Azure OpenAI / Azure AI Foundry directly | `azure_foundry` (v1 API) or `azure_openai` | OpenAI models on Azure |
| Only a vendor-native Gemini API (`generateContent`) and nothing else | - (needs a small provider class, 5.7) | Gemini |

**Recommended:** `openai_compatible` against the gateway's OpenAI-compatible endpoint. One configuration reaches all
three vendors, and different features can even use different vendors' models.

### 6.4 Configuration: OpenAI-compatible gateway (recommended)

```bash
SOC_LLM_PROVIDER=openai_compatible
SOC_LLM_ENDPOINT=https://llm-gateway.client.internal/v1        # base URL; /chat/completions is appended
SOC_LLM_API_KEY_FILE=/run/secrets/llm_gateway_key              # the key the gateway issued to this application
SOC_LLM_MODELS=<model names as the gateway names them, comma-separated>   # offered per feature on the AI usage screen
SOC_LLM_DEPLOYMENT=<default model for summaries and reports>
SOC_LLM_DEPLOYMENT_SMALL=<default model for routine narrative>
SOC_LLM_APPROVED_ENDPOINTS=https://llm-gateway.client.internal/v1   # anything else is refused at start-up
SOC_LLM_MODEL_VERSION=<model-version pins, comma-separated>      # optional; a different version is logged as a mismatch
SOC_LLM_MONTHLY_TOKEN_BUDGET=50000000                          # see 5.6

# how the gateway wants to be called (no code changes):
SOC_LLM_AUTH_HEADER=Authorization        # or x-api-key, api-key, Ocp-Apim-Subscription-Key ...
SOC_LLM_AUTH_PREFIX="Bearer "            # "" when the header carries the bare key
SOC_LLM_EXTRA_HEADERS={"x-app-id":"soc-platform","x-cost-centre":"SEC-001"}   # fixed, non-secret headers
SOC_LLM_CA_BUNDLE=/etc/ssl/certs/client-ca.pem                 # when the gateway's certificate is internally issued
SOC_LLM_JSON_MODE=1                      # set 0 if the gateway or a model rejects response_format
```

The platform sends `{"model", "temperature": 0.1, "messages": [system, user], "response_format": {"type":
"json_object"}}` and reads `choices[0].message.content` and `usage.prompt_tokens / completion_tokens`. With
`SOC_LLM_JSON_MODE=0` the `response_format` field is left out and the JSON requirement is written into the system
instruction instead; replies are parsed tolerantly (the first JSON object in the reply) either way.

**Choosing models** (names depend on how NAM's gateway exposes them). `SOC_LLM_MODELS` lists the models an
administrator can pick per feature on the AI usage screen (default: gpt-4.1-nano, gpt-4.1-mini, gpt-4.1; more are
added to the list as NAM deploys them, `name=id` where the gateway's id differs). The two defaults:

| Default | Used for | Pick |
|---|---|---|
| `SOC_LLM_DEPLOYMENT` | case and incident summaries, attack story, deep analysis, reports | the strongest reasoning model NAM allows (a Claude Opus/Sonnet-class, GPT-4.1-class or Gemini Pro-class model) |
| `SOC_LLM_DEPLOYMENT_SMALL` | routine narrative, notifications, short commentary, planners | a fast, cheap model (Claude Haiku-class, GPT mini-class, Gemini Flash-class) |

After go-live, *AI usage -> Models -> Check which models answer* confirms which listed models the endpoint serves.

Requirements for a model to be suitable: reliable JSON output, instruction following for citations
(`[E1]`-style evidence ids), and a context window larger than the biggest prompt measured in
[AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md). Run the checks in 6.8 for each candidate and read a few narratives: a model that
often ignores the citation format loses sentences to the guardrail and gives thinner prose.

### 6.5 Configuration: Claude Messages API through the gateway

```bash
SOC_LLM_PROVIDER=anthropic
SOC_LLM_ENDPOINT=https://llm-gateway.client.internal/anthropic   # base URL the SDK calls /v1/messages on
SOC_LLM_API_KEY_FILE=/run/secrets/llm_gateway_key                # sent as x-api-key by the official SDK
SOC_LLM_DEPLOYMENT=<Claude model id as the gateway names it>
SOC_LLM_DEPLOYMENT_SMALL=<smaller Claude model id>
SOC_LLM_APPROVED_ENDPOINTS=https://llm-gateway.client.internal/anthropic
SOC_LLM_EXTRA_HEADERS={"x-app-id":"soc-platform"}                # optional
SOC_LLM_CA_BUNDLE=/etc/ssl/certs/client-ca.pem                   # optional
SOC_LLM_SERVER_FALLBACK=0     # if the gateway rejects the beta refusal-fallback feature (see below)
```

With the model ids `claude-opus-5` or `claude-fable-5-1` the provider asks the Claude API for a server-side fallback
model if the first declines (a beta feature). A gateway that does not pass beta features through will fail those
calls; `SOC_LLM_SERVER_FALLBACK=0` turns it off (a refusal then simply uses the deterministic text).

### 6.6 Budget, rate and data-handling settings

| Setting | Default | Set it to |
|---|---|---|
| `SOC_LLM_MONTHLY_TOKEN_BUDGET` | 50,000,000 | the starting monthly allocation. After go-live, administrators manage the monthly and daily budgets, per-person limits and each feature's model and answer cap on the **AI usage** screen (no restart; versioned, audited). Enter NAM's per-model prices there so cost is shown in its terms. Measured tokens per component: [AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md). |
| `SOC_LLM_MAX_TOKENS_FIELD` | `max_tokens` | `max_completion_tokens` if the gateway or model rejects `max_tokens` (the answer cap the AI usage policy sets) |
| `SOC_LLM_CONCURRENCY` | 4 | at most the gateway's per-application concurrency |
| `SOC_LLM_TIMEOUT_SECONDS` / `SOC_LLM_TIMEOUT_LARGE_SECONDS` / `SOC_LLM_CONNECT_TIMEOUT_SECONDS` | 30 / 120 / 10 | raise the large timeout if the gateway queues requests |
| `SOC_LLM_BREAKER_FAILURES` / `SOC_LLM_BREAKER_SECONDS` | 3 / 60 | how quickly screens stop waiting for a failing gateway |
| `SOC_LLM_REDACT_PII` | on | **keep on**, even for an in-house model: prompts then carry pseudonyms (`USER_1`, `HOST_2` ...) instead of names and addresses, and names are restored in the answer, so narrative quality is unchanged while the gateway's own logs never hold identities. Turn off only with NAM's data-protection approval. |
| `SOC_LLM_LOG_RETENTION_DAYS` | 180 | NAM's retention policy for AI interaction logs |
| `SOC_EVENT_RETENTION_DAYS` | 400 | how long sign-ins, DNS and other telemetry stay in the context store (events cited by a case or insight are kept); set to NAM's security-evidence retention (Q24) |

Being trained on company data does not give the model any of the platform's case data: it only sees the evidence
the platform sends in each prompt. Nothing in the platform fine-tunes or trains a model.

### 6.7 When code changes are needed

| Situation | Change | Where |
|---|---|---|
| The gateway requires an OAuth / Entra ID access token per call instead of a static key | a provider subclass that obtains and caches the token (the connectors' `entra_app_auth` / `OAuth2ClientCredentials` in `soc_platform/connectors/http.py` can be reused) and returns it from `_headers()` | `soc_platform/llm/providers/openai_compatible.py` |
| The gateway speaks neither the OpenAI nor the Claude protocol (e.g. only Gemini `generateContent`, or a proprietary JSON) | a new `Provider` with one method `complete(system, user, *, tier, max_tokens=None, model=None) -> Completion` (`model`: the model the AI usage policy chose), registered in `build_provider` | `soc_platform/llm/providers/<name>.py`, `soc_platform/llm/gateway.py` |
| The gateway returns token usage under other field names | adjust the `usage` parsing in the provider | same file |
| The gateway answers only as a stream (server-sent events) and cannot return one complete response | read the stream to its end inside the provider and return the assembled text and usage as one `Completion` (the platform needs the whole answer before the citation check, so nothing is shown to the analyst token by token) | the provider in use |

Each is a small, isolated change (the existing providers are about 50 lines each); the gateway, guardrails,
redaction and fallbacks stay as they are. Add a test like `test_openai_compatible_provider` in
`soc_platform/tests/test_intelligence.py`.

### 6.8 Verifying the LLM connection

1. `GET /api/v1/llm/status` - provider, models, budget used, per-workflow latency.
2. Live test (sends a few small prompts; costs tokens):
   `SOC_LIVE_LLM=1 python -m pytest soc_platform/tests/test_live_llm.py -q`
3. Full check including model-written report and deep analysis: `python scripts/verify_features.py --llm`
   (reads the `SOC_LLM_*` lines from `.env`).
4. Token measurement for NAM's cost model: `python scripts/measure_llm_usage.py`, then update
   [AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md).
5. In the console: the Overview's *Situation brief* is marked *LLM narrative*; a case narrative carries citations;
   the Reports screen names the configured provider; an attack story offers the *Deep analysis* panel.
6. Failure behaviour to confirm once: point the endpoint at a closed port → screens keep working with deterministic
   text, calls are logged with status `error`, and after 3 failures the circuit opens for 60 s (status
   `circuit_open`) so screens stop waiting.

---

**For NAM in particular:** the endpoint is in NAM's environment or an Indian region (CLAUDE.md §0.4 rule 8); which
models that region offers is still to be decided; until then `SOC_LLM_PROVIDER=none` is a complete configuration
(every module runs on its computed path). The NAM features and their default sizes are in
[AI_AND_AUTONOMY.md](AI_AND_AUTONOMY.md) section 2; `dlp.disposition` and `dlp.investigate` are the ones that run at
volume (capped by `SOC_DLP_AI_MAX_PER_RUN`).

## 7. Rollout by phase (the deck's gates)

| Phase | Weeks | Tools and stages | What the AI does | Gate |
|---|---|---|---|---|
| 1 - connect and see | 1-6 | Forcepoint, Silverfort, Trend Micro, Trellix, the directory export at `read` | investigates and decides in **shadow** (stored beside the analyst's, nothing happens) | the CISO uses one live view; baseline captured (alerts per day, share reaching the model, cost per alert) |
| 2 - triage and correlate | 7-14 | + Arcon, Cloudflare, the SIEM and SOAR (read); tools may move to `recommend` | a decision type may be promoted to **recommend** once its target (set by NAM's SOC lead) is met and a second lead approves; DLP rule-change proposals | the agreement target set by NAM's SOC lead is met |
| 3 - act and prove | 15-20 | write scopes per action NAM accepts; execution through NAM's SOAR (M9) behind `ActionService` | reversible actions at L3 / L4 per type if approved; **decide** only after the adversarial DLP-content test set exists and passes | the audit pack accepted |

Throughout: containment (isolate, disable, rotate) is four-eyes; reportability is a person's decision; every figure
is computed. Before Phase 3, review the autonomy policy with NAM: which actions NAM accepts as reversible, and
whether NAM's auditors require a named person on every closure (then DLP stays at recommend).

## 8. First-sync plan

1. Directory export at `record`, then `read`: check the baseline count on *Dome Graph · coverage* against NAM's own
   number of joined devices; fix the export before going further (coverage is measured against it).
2. Trellix and Trend Micro at `record` / `read`: coverage fills; review "not in the baseline" and silent agents.
3. Forcepoint at `record` / `read`: the DLP queue fills; the rulings NAM's analysts already gave in Forcepoint become
   the agreement baseline; review the classifier names against the personal-data classes.
4. Silverfort at `record` / `read`: identity-risk facts appear on DLP alerts; cross-tool cases may open.
5. Review the recordings (`_scan.json`) and keep them only where NAM agrees; unset `SOC_RECORD_FIXTURES_DIR`.
6. Week 2: capture the pilot baselines (*Pilot scorecard*); the SOC lead sets targets per KPI and per decision type;
   the CISO agrees the Dome Score weights (two leads approve); the compliance team starts validating the catalogue.

## 9. Production hardening checklist

- [ ] `SOC_ENVIRONMENT=prod`, `SOC_AUTH_MODE=entra`, `SOC_REQUIRE_MFA=1`, `SOC_DEV_JWT_SECRET` unset.
- [ ] `SOC_DATA_KEY` from the vault; rotation = prepend a new key, `python -m soc_platform blobs reencrypt`, remove the old.
- [ ] TLS at the reverse proxy (TLS 1.2+); `SOC_TRUSTED_PROXIES` set to the proxy (address or subnet) only; port 8080
  not reachable otherwise. Internet-facing: WAF in prevention mode with the rate-limit rule (deploy/azure/main.bicep,
  `internetFacing=true`). Internal: the existing gateway's owner grants the AGIC identity Contributor on it.
- [ ] PostgreSQL: `sslmode=verify-full`, the owner / runtime role split (`SOC_DB_RUNTIME_ROLE`, `SOC_SCHEMA_MANAGE=0`),
  `pg_trgm` allowed, backups and a tested restore ([OPERATIONS.md](OPERATIONS.md) - Backups).
- [ ] Images: built by the release workflow, deployed **by digest**, signature verified at admission
  (`deploy/kubernetes/policy/verify-images.yaml`: Kyverno; or Azure Policy with Ratify).
- [ ] Network: default-deny policies applied; the database reachable only from the platform's pods (overlay
  `soc-database-egress`); the ingress rule matches the real gateway (Azure: the Application Gateway subnet).
- [ ] Every connector credential in the vault; least privilege as listed; write scopes only for approved actions.
- [ ] Break-glass secret sealed; hash configured; tested once.
- [ ] Outbound allow-list (5.10) enforced at the firewall/proxy.
- [ ] LLM: approved endpoint set, budget set, redaction on, demo keys absent.
- [ ] Monitoring: `/metrics` scraped with an auditor API key (`kubectl apply -k deploy/kubernetes/monitoring`); the
  alert rules routed to on-call; `audit.anchor` log lines kept in write-once retention in the log platform.
- [ ] Logs: stdout of every container collected (`SOC_LOG_FORMAT=json`) into NAM's log platform / SIEM;
  alerts on WARNING / ERROR lines, failed jobs and model-call errors ([OPERATIONS.md](OPERATIONS.md) - Logs, traces and
  diagnostics). If the reverse proxy sets `X-Request-ID`, the same id appears in its logs and the platform's.
- [ ] Retention periods and legal-hold process agreed with NAM.
- [ ] Banned-data check: no demo data loaded (`demo` never run), no tool NAM owns left in the Fixtures stage.
- [ ] `python -m soc_platform config check` clean; `python -m soc_platform preflight --all` ready for every tool in use;
  the configuration exported (*Integrations → Export*) and kept with the deployment record.
- [ ] Partners and sanctioned services (what DLP destinations are classified by) replaced with NAM's lists (*Integrations → Suppliers & sanctioned
  services*, approved by a lead) - the demo lists must not stay in force.
- [ ] Recording off: no tool left in the Recording stage and `SOC_RECORD_FIXTURES_DIR` unset after the first syncs; recordings reviewed (`_scan.json`) and kept
  only where NAM approved; the salt not stored with them.
- [ ] Capacity: `SOC_API_WORKERS` one per core; `workers x (SOC_DB_POOL_SIZE + SOC_DB_MAX_OVERFLOW)` below PostgreSQL's
  `max_connections`; `scripts/load_test.py` run against the target environment with the expected number of analysts.
- [ ] `SOC_CONNECTOR_RATE_SHARE` = API workers + 1 (the scheduler service), so together the processes stay within each
  tool's rate budget; statement and idle-transaction timeouts left at their production defaults (300 s / 600 s);
  `SOC_SHUTDOWN_GRACE_SECONDS` below the orchestrator's stop grace period.
- [ ] A restore drill done on the target environment, and `GET /api/v1/audit/verify` clean on the restored copy;
  `python -m soc_platform audit verify --anchor SEQ:HASH` with the latest anchored head from the log platform.
- [ ] Separation of duties: containment (isolate / release a host, disable an account, reset a password, rotate a
  privileged secret) is four-eyes whatever the policy says; at least two people hold the lead role with all-domain
  scope, or four-eyes actions, weights, catalogue and promotions cannot be approved.
- [ ] `SOC_PRODUCT_SCOPE=nam` (the default); the model endpoint in NAM's environment or an Indian region (or
  `SOC_LLM_PROVIDER=none`); `SOC_LLM_REDACT_PII=1`.
- [ ] Every NAM connector at stage `read` (Phase 1-2); its confirmed endpoint paths set; no tool left at `fake`.
- [ ] Dome Score weights agreed with the CISO and approved by two leads; DLP decision-type targets set by NAM's SOC
  lead; the control catalogue validated by NAM's compliance team (two people).

## 10. Still to decide with NAM (do not assume)

| Question | Why it matters | Where it lands |
|---|---|---|
| SIEM and SOAR products | the SIEM connector (beyond the webhook) and the execution backend (M9) | `connector new`; `ActionService` backend |
| Tool versions and licensed APIs (Forcepoint, Silverfort, Trend Micro product, Trellix, Arcon, Cloudflare) | every connector path and shape is a placeholder until confirmed | section 5 |
| Which Trend Micro product (Apex One or Vision One) | API and detections feed differ | `trend_micro` |
| Where the model runs and which models that region offers | residency; feature model choice; cost | section 6, AI usage screen |
| Agreement target and minimum sample per decision type | nothing is promoted until set | Data protection screen |
| Which actions NAM accepts as reversible | the Phase 3 autonomy policy | Automation policy |
| Whether auditors require a named person on every closure | if yes, DLP stays at recommend | decision types |
| The Dome Score weights | agreed with the CISO, approved by two leads | Dome Score screen |
| NAM's CSCRF control list; confirmed regulatory deadlines | the catalogue is a draft; only CERT-In's 6 hours is in it, "to verify" | Dome Comply |
| The baseline source (AD, CMDB or Intune export) | coverage is measured against it | `directory_export` |
| Retention periods (CERT-In's 180 days for logs) and legal hold | retention settings | [OPERATIONS.md](OPERATIONS.md) |

