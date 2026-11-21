"""Directory export connector: the organisation's own list of joined devices and people (Active Directory, a CMDB or
an endpoint-management export served over HTTP) - the baseline every control is reconciled against.

Read: devices (in full), users (in full). Write: none.
UNVERIFIED (see ``_paged.py``): which system serves the baseline (AD, CMDB or Intune export) and its API are to be
confirmed; the paths and page shape here are placeholders that run in fake mode only.
"""

from __future__ import annotations

from typing import Any

from soc_platform.connectors.http import ApiKeyHeader, HttpTransport
from soc_platform.connectors.registry import ConfigField, ConnectorManifest
from soc_platform.connectors.tools._common import need, parse_ts
from soc_platform.connectors.tools._paged import PagedConnector, device_type, flag, path_fields
from soc_platform.core.schema import NormalizedRecord

STREAMS = {"devices": ("/api/v1/devices", None), "users": ("/api/v1/users", None)}
PRIVILEGED_GROUPS = ("domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
                     "backup operators")


def _names(v: Any) -> list[str]:
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return [str(x).strip() for x in v if isinstance(x, (str, int)) and str(x).strip()] if isinstance(v, list) else []


class DirectoryExportConnector(PagedConnector):
    name = "directory_export"
    tool = "directory_export"
    dimension = "identity"
    streams = ("devices", "users")
    STREAMS = STREAMS
    read_scopes = ("read access to the device and user export",)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        return [self._device(raw) if stream == "devices" else self._user(raw)]

    def _device(self, d: dict[str, Any]) -> NormalizedRecord:
        fqdn = str(d.get("dns_name") or "")
        name = str(d.get("name") or fqdn.split(".")[0])
        return NormalizedRecord(
            kind="asset", tool=self.tool, source_type="device", source_id=str(need(d, "id")),
            observed_at=parse_ts(d.get("last_logon")), dimension="endpoint",  # dated as the tool reports it, like every inventory; whether it is still listed is read from the sync time
            keys={"ad_object_guid": d.get("id"), "serial_number": d.get("serial_number")},
            attributes={"hostname": name, "fqdn": fqdn if "." in fqdn else None, "ip": d.get("ip"), "os": d.get("os"),
                        "device_type": device_type(d.get("os"), d.get("type")), "ou": d.get("ou"),
                        "directory_enabled": flag(d.get("enabled")), "last_logon": d.get("last_logon"),
                        "primary_user": str(d.get("managed_by") or "").lower() or None})

    def _user(self, u: dict[str, Any]) -> NormalizedRecord:
        groups = _names(u.get("groups"))
        privileged = {g.lower() for g in _names(self.settings.get("privileged_groups"))} or set(PRIVILEGED_GROUPS)
        upn = str(u.get("upn") or "").lower()
        return NormalizedRecord(
            kind="identity", tool=self.tool, source_type="user", source_id=str(need(u, "id")), dimension="identity",
            keys={"upn": upn, "sam": u.get("sam"), "sid": u.get("sid")},
            attributes={"display_name": u.get("display_name"), "department": u.get("department"),
                        "title": u.get("title"), "directory_enabled": flag(u.get("enabled")), "groups": groups,
                        # stated by the directory (a flag or an admin group), never guessed from an account's name
                        "privileged": bool(flag(u.get("privileged")) or any(g.lower() in privileged for g in groups))})


def _live(s: dict[str, Any]) -> HttpTransport:
    return HttpTransport(s["base_url"], ApiKeyHeader("Authorization", s["api_key"], "Bearer "))


MANIFEST = ConnectorManifest(
    name="directory_export", tool="Directory export (devices and users)", vendor="internal", category="directory",
    provides={"directory.devices": "devices", "directory.users": "users"},
    dimension="identity",
    description="The baseline of joined devices and people that control coverage is reconciled against.",
    factory=lambda s, t: DirectoryExportConnector(s, t, rate_per_sec=2, burst=4), live_transport=_live,
    config=[ConfigField("base_url", "URL of the service that serves the export", kind="url"),
            ConfigField("api_key", "API key", secret=True),
            ConfigField("privileged_groups", "Groups whose members are privileged (default: the built-in admin "
                                             "groups)", required=False, kind="list"),
            *path_fields(STREAMS)],
    confidence="Unknown",
    to_confirm="Which system is the baseline (Active Directory, CMDB or endpoint-management export), how it is "
               "served and how often it is refreshed; the admin groups that mark a privileged account",
    fake_settings={"base_url": "https://directory.example.invalid"},
    focus_areas=("dlp",),
)
