"""Trend Micro endpoint security connector: which devices carry the EDR agent and whether it reports.

Read: endpoints (agent inventory, in full). Write: none in this version - host isolation is added with the action
rollout, behind ``ActionService`` and two approvers. Detections join the incident pipeline with the cross-tool rules.
UNVERIFIED (see ``_paged.py``): the product in use (Apex One or Vision One), the path, the page shape and the
field names are placeholders that run in fake mode only.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import need, parse_ts
from soc_platform.connectors.tools._paged import PagedConnector, device_type, path_fields
from soc_platform.core.schema import NormalizedRecord

STREAMS = {"endpoints": ("/api/v1/endpoints", None)}


class TrendMicroConnector(PagedConnector):
    name = "trend_micro"
    tool = "trend_micro"
    dimension = "endpoint"
    streams = ("endpoints",)
    STREAMS = STREAMS
    read_scopes = ("endpoint inventory read",)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
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


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="trend_micro", tool="Trend Micro endpoint security", vendor="Trend Micro", category="edr", dimension="endpoint",
    description="EDR agent inventory: which devices are protected and when each agent last reported.",
    factory=lambda s, t: TrendMicroConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("base_url", "API URL of the console (region specific)", kind="url"),
            ConfigField("api_key", "API key of a read-only role", secret=True),
            *path_fields(STREAMS)],
    confidence="Unknown",
    to_confirm="Which product and version (Apex One or Vision One) and its API; the detections feed; and - for the "
               "action rollout - the isolate / restore calls",
    fake_settings={"base_url": "https://edr.example.invalid"},
    focus_areas=("dlp",),
)
