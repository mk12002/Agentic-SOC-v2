"""Generate docs/CONNECTORS.md from the connector manifests (the code is the source of truth).

    python scripts/build_connector_docs.py
"""

from __future__ import annotations

import os
from pathlib import Path

from soc_platform.connectors.registry import ConnectorRegistry, discover
from soc_platform.core import scope

OUT = Path(__file__).resolve().parents[1] / "docs" / "CONNECTORS.md"

HEAD = """# Connectors - CyberDome for NAM

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

"""


def main() -> None:
    os.environ.setdefault("SOC_PRODUCT_SCOPE", "nam")
    reg = ConnectorRegistry.all_fake()
    parts = [HEAD, "| Connector | Tool | Category | Streams | Lookups | Actions | Confidence |", "|---|---|---|---|---|---|---|"]
    rows = []
    for name, m in sorted(discover().items()):
        if name not in scope.NAM_CONNECTORS:
            continue
        c = reg.get(name)
        acts = sorted({a.action_type for a in (m.actions(c) if m.actions else [])})
        parts.append(f"| `{name}` | {m.tool} | {m.category} | {', '.join(c.streams) or '-'} | "
                     f"{', '.join(getattr(c, 'lookups', ()) or ()) or '-'} | {', '.join(acts) or '-'} | {m.confidence} |")
        cfg = "\n".join(f"  - `{f.name}`{' (secret)' if f.secret else ''}{'' if f.required else ' (optional)'}: {f.description}"
                        for f in m.config) or "  - none"
        provides = ", ".join(f"{cap} ({', '.join(p.streams) or 'look-up'})" for cap, p in sorted(m.provides.items()))
        rows.append(f"### {m.tool} (`{name}`)\n\n{m.description}\n\n"
                    f"- Vendor: {m.vendor} · focus areas: {', '.join(m.focus_areas)}\n"
                    f"- Provides: {provides or '-'}\n"
                    f"- Read scopes: {', '.join(getattr(c, 'read_scopes', ()) or ()) or 'see vendor docs / to confirm'}\n"
                    f"- Write scopes (only for approved actions): {', '.join(getattr(c, 'write_scopes', ()) or ()) or '-'}\n"
                    f"- To confirm with NAM: {m.to_confirm or '-'}\n- Configuration:\n{cfg}\n")
    parts += ["", "## Per-connector setup", ""] + rows
    OUT.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"{len(rows)} connectors -> {OUT}")


if __name__ == "__main__":
    main()
