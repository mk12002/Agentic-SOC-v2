"""Trend Micro endpoint security connector: which devices carry the EDR agent and whether it reports.

Read: endpoints (agent inventory, in full), alerts (detections, resumed from the newest change; record kind
``edr_alert``, read by the cross-tool rules - not the incident pipeline's ``alert``). Write: isolate a device and
restore it (``endpoint.isolate`` / ``endpoint.release``), only through ``ActionService``; the policy makes isolation
four-eyes, always.
UNVERIFIED (see ``_paged.py``): the product in use (Apex One or Vision One), the path, the page shape and the
field names are placeholders that run in fake mode only.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, need, parse_ts, path_part, sev_name, targets_of
from soc_platform.connectors.tools._paged import PagedConnector, device_type, path_fields
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

STREAMS = {"endpoints": ("/api/v1/endpoints", None), "alerts": ("/api/v1/alerts", "updated_at")}


class TrendMicroConnector(PagedConnector):
    name = "trend_micro"
    tool = "trend_micro"
    dimension = "endpoint"
    streams = ("endpoints", "alerts")
    STREAMS = STREAMS
    read_scopes = ("endpoint inventory read", "detections read")
    write_scopes = ("isolate and restore endpoints",)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "alerts":
            return [self._alert(raw)]
        fqdn = str(raw.get("fqdn") or "")
        return [NormalizedRecord(
            kind="asset", tool=self.tool, source_type="endpoint", source_id=str(need(raw, "agent_guid")),
            observed_at=parse_ts(raw.get("last_connected")), dimension="endpoint",  # dated as the tool reports it, like every inventory; whether it is still listed is read from the sync time
            keys={"trend_agent_guid": raw.get("agent_guid"), "serial_number": raw.get("serial_number")},
            attributes={"hostname": raw.get("endpoint_name") or fqdn.split(".")[0], "fqdn": fqdn if "." in fqdn else None,
                        "ip": raw.get("ip"), "os": raw.get("os_name"), "device_type": device_type(raw.get("os_name")),
                        "agent_version": raw.get("agent_version"),
                        "agent_status": str(raw.get("agent_status") or "").lower() or None,
                        "last_connected": raw.get("last_connected")})]

    def _alert(self, raw: dict[str, Any]) -> NormalizedRecord:
        """A detection, at alert-title level: what, where, who, how bad. Its own kind (``edr_alert``) so the
        incident pipeline, which reads the other EDRs' alerts in their shape, is unchanged."""
        refs: list[EntityRef] = []
        ep = raw.get("endpoint") if isinstance(raw.get("endpoint"), dict) else {}
        if ep.get("agent_guid") or ep.get("name"):
            refs.append(EntityRef(kind="asset", role="host", keys={"trend_agent_guid": ep.get("agent_guid")},
                                  attributes={"hostname": ep.get("name"), "ip": ep.get("ip")}))
        user = user_ref(raw.get("user"), default_domain=self.settings.get("user_domain"))
        if user is not None:
            refs.append(user)
        sev = sev_name(raw.get("severity"))
        return NormalizedRecord(
            kind="edr_alert", tool=self.tool, source_type="alert", source_id=str(need(raw, "id")),
            observed_at=parse_ts(raw.get("created_at")), dimension="endpoint", severity=sev,
            title=str(raw.get("title") or "Endpoint alert")[:200], refs=refs,
            attributes={"severity": sev, "status": str(raw.get("status") or "").lower() or None,
                        "category": raw.get("category") if isinstance(raw.get("category"), str) else None,
                        "action": raw.get("action") if isinstance(raw.get("action"), str) else None})

    # ------------------------------------------------------------------ actions (only through ActionService)

    def isolate(self, params: dict, targets: list) -> dict:
        return {"isolated": [g for g in targets_of(targets, "asset", "trend_agent_guid")
                             if self.post(f"/api/v1/endpoints/{path_part(g)}/isolate", json={"reason": str(params.get("reason") or "")[:200]}) is not None]}

    def release(self, params: dict, targets: list) -> dict:
        return {"released": [g for g in targets_of(targets, "asset", "trend_agent_guid")
                             if self.post(f"/api/v1/endpoints/{path_part(g)}/restore", json={}) is not None]}


def _has_guid(params: dict, targets: list) -> list[str]:
    return [] if targets_of(targets, "asset", "trend_agent_guid") else ["no device target with a Trend Micro agent id"]


def _actions(c: TrendMicroConnector) -> list:
    # UNVERIFIED: the isolate / restore calls are placeholders (fake mode only) until the product's API is confirmed
    return [ConnectorAction("endpoint.isolate", c, c.isolate, preconditions=_has_guid, reverse_type="endpoint.release",
                            description="Isolate the device from the network (Trend Micro)"),
            ConnectorAction("endpoint.release", c, c.release, preconditions=_has_guid,
                            description="Restore the device's network connection (Trend Micro)")]


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="trend_micro", tool="Trend Micro endpoint security", vendor="Trend Micro", category="edr", dimension="endpoint",
    description="EDR agent inventory and detections: which devices are protected, when each agent last reported, "
                "what it detected; device isolation behind two approvers.",
    factory=lambda s, t: TrendMicroConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live, actions=_actions,
    config=[ConfigField("base_url", "API URL of the console (region specific)", kind="url"),
            ConfigField("api_key", "API key of a role that reads endpoints and detections (and isolates, once actions are on)",
                        secret=True),
            ConfigField("user_domain", "UPN suffix for bare user names", required=False),
            *path_fields(STREAMS)],
    confidence="Unknown",
    to_confirm="Which product and version (Apex One or Vision One) and its API; the detections feed; and - for the "
               "action rollout - the isolate / restore calls",
    fake_settings={"base_url": "https://edr.example.invalid", "user_domain": "acme-demo.com"},
    focus_areas=("dlp",),
)
