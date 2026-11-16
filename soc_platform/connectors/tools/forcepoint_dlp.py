"""Forcepoint DLP connector: data-loss incidents, the endpoint agents and the product's own upkeep.

Read: dlp_incidents (events, resumed from the newest change), endpoints (agent inventory, in full), health
(certificates, sync and deployment jobs, the directory import - in full). Write: none: a rule or policy change is made
by an engineer in Forcepoint, never by the platform.
UNVERIFIED (see ``_paged.py``): the paths, the page shape and the field names are placeholders that run in fake mode
only. To confirm against the installed version: the incident export API and its filters, whether agent check-ins and
job / certificate state are exposed at all, and the classifier names used for personal data.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import need, parse_ts, sev_name, source_verdict
from soc_platform.connectors.tools._paged import PagedConnector, path_fields
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

STREAMS = {"dlp_incidents": ("/api/v1/incidents", "updated_at"), "endpoints": ("/api/v1/endpoints", None),
           "health": ("/api/v1/system/health", None)}
CHANNELS = {"email": "email", "smtp": "email", "web": "web", "http": "web", "https": "web", "endpoint_removable_media":
            "removable_media", "usb": "removable_media", "removable_media": "removable_media", "printing": "print",
            "print": "print", "cloud": "cloud", "endpoint_application": "application"}
ACTIONS = {"blocked": "blocked", "block": "blocked", "quarantined": "quarantined", "quarantine": "quarantined",
           "permitted": "permitted", "permit": "permitted", "audited": "permitted", "audit": "permitted",
           "encrypted": "encrypted", "notified": "permitted"}


def _text(v: Any, limit: int = 300) -> str | None:
    return str(v)[:limit] if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v) else None


def _classifiers(v: Any) -> list[dict[str, Any]]:
    """What matched: each classifier's name and how many times (a count that is not a whole number reads as 0)."""
    out = []
    for c in v if isinstance(v, list) else []:
        if isinstance(c, dict) and _text(c.get("name")):
            n = c.get("matches")
            out.append({"name": _text(c["name"], 120),
                        "matches": int(n) if isinstance(n, (int, float)) and not isinstance(n, bool) and n >= 0 else 0})
    return out


class ForcepointDlpConnector(PagedConnector):
    name = "forcepoint_dlp"
    tool = "forcepoint_dlp"
    dimension = "data_protection"
    streams = ("dlp_incidents", "endpoints", "health")
    STREAMS = STREAMS
    health_stream = "endpoints"
    read_scopes = ("incident read (reports / REST API role)", "endpoint status read", "system health read")

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "health":
            return [self.health_record(raw)]
        return [self._endpoint(raw) if stream == "endpoints" else self._incident(raw)]

    def _endpoint(self, e: dict[str, Any]) -> NormalizedRecord:
        fqdn = str(e.get("fqdn") or "")
        return NormalizedRecord(
            kind="asset", tool=self.tool, source_type="endpoint", source_id=str(need(e, "id")),
            observed_at=parse_ts(e.get("last_checkin")), dimension="endpoint",  # dated as the tool reports it, like every inventory; whether it is still listed is read from the sync time
            keys={"forcepoint_endpoint_id": e.get("id")},
            attributes={"hostname": e.get("hostname") or fqdn.split(".")[0], "fqdn": fqdn if "." in fqdn else None,
                        "ip": e.get("ip"), "agent_version": e.get("agent_version"),
                        "agent_status": str(e.get("status") or "").lower() or None,
                        "last_checkin": e.get("last_checkin"), "profile": e.get("profile")})

    def _incident(self, i: dict[str, Any]) -> NormalizedRecord:
        src = i.get("source") if isinstance(i.get("source"), dict) else {}
        dst = i.get("destination") if isinstance(i.get("destination"), dict) else {}
        refs: list[EntityRef] = []
        user = user_ref(src.get("user"), default_domain=self.settings.get("user_domain"))
        if user is not None:
            refs.append(user)
        if src.get("hostname") or src.get("ip"):
            refs.append(EntityRef(kind="asset", role="host", attributes={"hostname": src.get("hostname"),
                                                                         "ip": src.get("ip")}))
        files = i.get("file_names")
        rule = _text(i.get("rule"), 200)
        return NormalizedRecord(
            kind="dlp_incident", tool=self.tool, source_type="incident", source_id=str(need(i, "id")),
            observed_at=parse_ts(i.get("event_time")), title=rule or _text(i.get("policy"), 200) or "DLP incident",
            severity=sev_name(i.get("severity")), dimension=self.dimension, refs=refs,
            attributes={"channel": CHANNELS.get(str(i.get("channel") or "").lower(), "other"),
                        "action": ACTIONS.get(str(i.get("action") or "").lower(), "unknown"),
                        "status": str(i.get("status") or "").lower() or None,
                        "policy": _text(i.get("policy"), 200), "rule": rule, "classifiers": _classifiers(i.get("classifiers")),
                        "destination_kind": str(dst.get("kind") or "").lower() or None,
                        "destination": _text(dst.get("value"), 400),
                        # written by the person who sent it: shown to analysts, never a reason to lower anything
                        "subject": _text(i.get("subject"), 400),
                        "file_names": [str(f)[:200] for f in files if isinstance(f, str)][:20] if isinstance(files, list) else [],
                        "size_bytes": i.get("size_bytes") if isinstance(i.get("size_bytes"), int) else None,
                        "source_user": _text(src.get("user"), 200),
                        # the ruling an analyst already gave in Forcepoint: the baseline the AI is measured against
                        "source_verdict": source_verdict(i.get("resolution")),
                        "resolved_by": _text(i.get("resolved_by"), 200)},
            deep_link=f"{str(self.settings.get('base_url') or '').rstrip('/')}/incidents/{i.get('id')}")


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="forcepoint_dlp", tool="Forcepoint DLP", vendor="Forcepoint", category="dlp", dimension="data_protection",
    description="Data-loss incidents, endpoint agent check-ins, and the product's certificates and sync jobs.",
    factory=lambda s, t: ForcepointDlpConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("base_url", "Forcepoint Security Manager API URL", kind="url"),
            ConfigField("api_key", "API token of a read-only application account", secret=True),
            ConfigField("user_domain", "UPN suffix for bare user names", required=False),
            *path_fields(STREAMS)],
    confidence="Unknown",
    to_confirm="Version and licensed REST API; the incident export call and its date filters; whether endpoint "
               "check-ins, job state and certificate expiry can be read; classifier names for PAN / Aadhaar",
    fake_settings={"base_url": "https://dlp.example.invalid", "user_domain": "acme-demo.com"},
    focus_areas=("dlp",),
)
