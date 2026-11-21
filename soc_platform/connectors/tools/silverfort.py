"""Silverfort connector: risky authentications (identity context for data-loss triage).

Read: risk_events (events, resumed from the newest change). Write (only through ``ActionService``): revoke a person's
sessions (``identity.revoke_sessions``), require MFA at every sign-in (``identity.require_mfa``) and lift it again
(``identity.release_mfa``) - all reversible.
UNVERIFIED (see ``_paged.py``): the path, the page shape and the field names are placeholders that run in fake mode
only. To confirm: whether authentication risk is read through a REST API or only through the log forwarder, and
the risk levels and factor names the installed version reports.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import ConnectorAction, need, parse_ts, path_part, sev_name, targets_of
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
    CONFIG_PATH = "/api/v1/policies"
    read_scopes = ("read access to authentication risk events",)
    write_scopes = ("revoke sessions and set MFA requirements for a user",)

    def _upns(self, targets: list) -> list[str]:
        return targets_of(targets, "identity", "upn")

    def revoke(self, params: dict, targets: list) -> dict:
        return {"revoked": [u for u in self._upns(targets)
                            if self.post(f"/api/v1/users/{path_part(u)}/sessions/revoke", json={}) is not None]}

    def require_mfa(self, params: dict, targets: list) -> dict:
        return {"mfa_required": [u for u in self._upns(targets)
                                 if self.post(f"/api/v1/users/{path_part(u)}/mfa", json={"required": True}) is not None]}

    def release_mfa(self, params: dict, targets: list) -> dict:
        return {"mfa_released": [u for u in self._upns(targets)
                                 if self.post(f"/api/v1/users/{path_part(u)}/mfa", json={"required": False}) is not None]}

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


def _has_upn(params: dict, targets: list) -> list[str]:
    return [] if targets_of(targets, "identity", "upn") else ["no person target with a UPN"]


def _actions(c: SilverfortConnector) -> list:
    # UNVERIFIED: the calls are placeholders (fake mode only) until the installed version's API is confirmed
    return [ConnectorAction("identity.revoke_sessions", c, c.revoke, preconditions=_has_upn,
                            description="Revoke the person's sessions (Silverfort)"),
            ConnectorAction("identity.require_mfa", c, c.require_mfa, preconditions=_has_upn,
                            reverse_type="identity.release_mfa", description="Require MFA at every sign-in (Silverfort)"),
            ConnectorAction("identity.release_mfa", c, c.release_mfa, preconditions=_has_upn,
                            description="Lift the MFA requirement set by the platform (Silverfort)")]


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="silverfort", tool="Silverfort", vendor="Silverfort", category="identity", dimension="identity",
    provides={"identity.risk_events": "risk_events", "tool.config_export": None},
    description="Risky authentications per person: the identity context of a data-loss alert.",
    factory=lambda s, t: SilverfortConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live, actions=_actions,
    config=[ConfigField("base_url", "Silverfort console API URL", kind="url"),
            ConfigField("api_key", "API token of an application that reads risk (and revokes sessions / sets MFA, "
                                   "once actions are on)", secret=True),
            ConfigField("user_domain", "UPN suffix for bare user names", required=False),
            *path_fields(STREAMS, "/api/v1/policies")],
    confidence="Unknown",
    to_confirm="How authentication risk is exported (REST API or log forwarder), the risk levels and factors "
               "reported, and - for the action rollout - the calls that revoke sessions and force MFA",
    fake_settings={"base_url": "https://identity.example.invalid", "user_domain": "acme-demo.com"},
    focus_areas=("dlp",),
)
