"""Trellix ePO connector: disk-encryption state per device, and the product's own upkeep.

Read: systems (managed devices with their encryption state, in full), health (certificates and server tasks, in
full). Write: none.
UNVERIFIED (see ``_paged.py``): the paths, the page shape and the field names are placeholders that run in fake mode
only. To confirm: the ePO version and its web API (queries are usually run through it), the query that returns
drive-encryption state, and whether certificate expiry can be read.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import need, parse_ts
from soc_platform.connectors.tools._paged import PagedConnector, device_type, flag, path_fields
from soc_platform.core.schema import NormalizedRecord

STREAMS = {"systems": ("/api/v1/systems", None), "health": ("/api/v1/server/health", None)}


class TrellixEpoConnector(PagedConnector):
    name = "trellix_epo"
    tool = "trellix_epo"
    dimension = "data_protection"
    streams = ("systems", "health")
    STREAMS = STREAMS
    CONFIG_PATH = "/api/v1/policies"
    read_scopes = ("system tree read", "drive encryption query", "server health read")

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        if stream == "health":
            return [self.health_record(raw)]
        enc = raw.get("encryption") if isinstance(raw.get("encryption"), dict) else {}
        fqdn = str(raw.get("fqdn") or "")
        return [NormalizedRecord(
            kind="asset", tool=self.tool, source_type="system", source_id=str(need(raw, "node_id")),
            observed_at=parse_ts(raw.get("last_communication")), dimension="endpoint",  # dated as the tool reports it, like every inventory; whether it is still listed is read from the sync time
            keys={"epo_node_id": raw.get("node_id"), "serial_number": raw.get("serial_number")},
            attributes={"hostname": raw.get("name") or fqdn.split(".")[0], "fqdn": fqdn if "." in fqdn else None,
                        "ip": raw.get("ip"), "os": raw.get("os"), "device_type": device_type(raw.get("os")),
                        "last_communication": raw.get("last_communication"),
                        # True / False as the tool states it; None when it reports nothing for this device
                        "disk_encrypted": flag(enc.get("state")),
                        "encryption_state": str(enc.get("state") or "").lower() or None,
                        "encryption_product_version": enc.get("product_version")})]


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="trellix_epo", tool="Trellix ePO (drive encryption)", vendor="Trellix", category="encryption",
    provides={"encryption.inventory": "systems", "tool.health": "health", "tool.config_export": None},
    dimension="data_protection",
    description="Disk-encryption state of every managed device, and the server's certificates and tasks.",
    factory=lambda s, t: TrellixEpoConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("base_url", "ePO server API URL", kind="url"),
            ConfigField("api_key", "Credential of a read-only ePO user", secret=True),
            *path_fields(STREAMS, "/api/v1/policies")],
    confidence="Unknown",
    to_confirm="ePO version and web API access; the query for drive-encryption state; whether certificate expiry and "
               "server-task results can be read",
    fake_settings={"base_url": "https://epo.example.invalid"},
    focus_areas=("dlp",),
)
