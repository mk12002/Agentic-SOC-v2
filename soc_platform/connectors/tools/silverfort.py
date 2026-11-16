"""Silverfort connector: risky authentications (identity context for data-loss triage).

Read: risk_events (events, resumed from the newest change). Write: none in this version - revoking sessions and
forcing MFA are added with the action rollout, behind ``ActionService``.
UNVERIFIED (see ``_paged.py``): the path, the page shape and the field names are placeholders that run in fake mode
only. To confirm: whether authentication risk is read through a REST API or only through the log forwarder, and
the risk levels and factor names the installed version reports.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import need, parse_ts, sev_name
from soc_platform.connectors.tools._paged import PagedConnector, flag, path_fields
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

STREAMS = {"risk_events": ("/api/v1/risk/events", "event_time")}
RISK = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "informational"}


class SilverfortConnector(PagedConnector):
    name = "silverfort"
    tool = "silverfort"
    dimension = "identity"
    streams = ("risk_events",)
    STREAMS = STREAMS
    read_scopes = ("read access to authentication risk events",)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        refs: list[EntityRef] = []
        user = user_ref(raw.get("user"), default_domain=self.settings.get("user_domain"))
        if user is not None:
            refs.append(user)
        if raw.get("source_host"):          # an unmanaged device has no name: its address alone is not a device
            refs.append(EntityRef(kind="asset", role="source_host",
                                  attributes={"hostname": raw.get("source_host"), "ip": raw.get("source_ip")}))
        level = RISK.get(str(raw.get("risk_level") or "").lower(), sev_name(raw.get("risk_level")))
        factors = raw.get("risk_factors")
        # its own kind, not "signin": the incident and risk pipelines read sign-ins in another tool's shape, and this
        # stream joins them with the cross-tool rules, not before
        return [NormalizedRecord(
            kind="auth_risk", tool=self.tool, source_type="risk_event", source_id=str(need(raw, "id")),
            observed_at=parse_ts(raw.get("event_time")), dimension="identity", severity=level,
            title=f"Risky sign-in ({level})", refs=refs,
            attributes={"risk_level": level, "result": str(raw.get("result") or "").lower() or None,
                        "risk_factors": [str(f)[:120] for f in factors if isinstance(f, str)][:10] if isinstance(factors, list) else [],
                        "device_managed": flag(raw.get("device_managed")), "mfa": str(raw.get("mfa") or "").lower() or None,
                        "destination": raw.get("destination") if isinstance(raw.get("destination"), str) else None,
                        "protocol": raw.get("protocol") if isinstance(raw.get("protocol"), str) else None,
                        "source_ip": raw.get("source_ip") if isinstance(raw.get("source_ip"), str) else None})]


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="silverfort", tool="Silverfort", vendor="Silverfort", category="identity", dimension="identity",
    description="Risky authentications per person: the identity context of a data-loss alert.",
    factory=lambda s, t: SilverfortConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("base_url", "Silverfort console API URL", kind="url"),
            ConfigField("api_key", "API token of a read-only application", secret=True),
            ConfigField("user_domain", "UPN suffix for bare user names", required=False),
            *path_fields(STREAMS)],
    confidence="Unknown",
    to_confirm="How authentication risk is exported (REST API or log forwarder), the risk levels and factors "
               "reported, and - for the action rollout - the calls that revoke sessions and force MFA",
    fake_settings={"base_url": "https://identity.example.invalid", "user_domain": "acme-demo.com"},
    focus_areas=("dlp",),
)
