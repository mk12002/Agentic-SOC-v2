"""Shared base for the NAM stack's REST connectors (Forcepoint DLP, Silverfort, Trend Micro, Trellix, the directory
export): several streams, each read with a page token inside one sync.

UNVERIFIED API SHAPE. Tool versions and licensed APIs are not known yet, so these connectors run in fake mode
only: every path is a setting (``<stream>_path``) with a placeholder default, and a page is read as
``{"items": [...], "next_page_token": "..."}``. When the vendor's documentation for the installed version is in
hand, only ``fetch_page`` (paging, parameters) and the ``_live`` transport of a module change; the normalisers, the
streams' meaning and everything built on them stay.

Resume rules (the same as every other connector): an event stream resumes from the newest change time it saw
(``since:<time>``), an inventory or health stream is read in full each sync; a page token is never kept between syncs.
"""

from __future__ import annotations

from typing import Any, ClassVar

from soc_platform.connectors.base import Page
from soc_platform.connectors.registry import ConfigField
from soc_platform.connectors.tools._common import ToolConnector, Watermark, need, parse_ts
from soc_platform.core.schema import NormalizedRecord

HEALTH_TYPES = ("certificate", "sync_job", "directory_sync", "service")


class PagedConnector(ToolConnector):
    # stream -> (placeholder path, change-time field for an event stream or None for an inventory read in full)
    STREAMS: ClassVar[dict[str, tuple[str, str | None]]] = {}
    page_size = 200

    def path_of(self, stream: str) -> str:
        if stream not in self.STREAMS:
            raise ValueError(f"unknown stream {stream}")
        return str(self.settings.get(f"{stream}_path") or self.STREAMS[stream][0])

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        path, changed = self.path_of(stream), self.STREAMS[stream][1]
        # Between syncs the cursor is "since:<newest change time seen>" (event streams) or nothing (inventories);
        # within one sync it is "<page token>|<since>".
        token, _, since = (cursor or "").partition("|")
        wm = Watermark.of(self, stream)
        if not cursor or cursor.startswith("since:"):
            since, token = (wm.start(cursor) or "") if changed else "", ""
        params: dict[str, Any] = {"limit": self.page_size}
        if since:
            params["updated_since"] = since
        if token:
            params["page_token"] = token
        body = self.get(path, params=params)
        recs = (body.get("items") if isinstance(body, dict) else None) or []
        if changed:
            wm.see(recs, changed)
        nxt = body.get("next_page_token") if isinstance(body, dict) else None
        if nxt and recs:
            return Page(recs, f"{nxt}|{since}", has_more=True)
        return Page(recs, wm.finish() if changed else None, has_more=False, reset=True)

    # ------------------------------------------------------------------ tool health (Dome Connect)

    def health_record(self, raw: dict[str, Any]) -> NormalizedRecord:
        """One thing the tool reports about its own upkeep: a certificate, a sync or deployment job, the directory
        import. Stored as it is reported; what counts as late, failed or expiring is judged in
        ``intelligence/tool_health.py``, never here."""
        kind = str(raw.get("type") or "").lower()
        users = raw.get("unmapped_users")
        return NormalizedRecord(
            kind="tool_health", tool=self.tool, source_type="health", source_id=str(need(raw, "id")),
            observed_at=parse_ts(raw.get("reported_at")), title=str(raw.get("name") or raw.get("id") or ""),
            dimension=self.dimension,
            attributes={"check": kind if kind in HEALTH_TYPES else "service", "status": str(raw.get("status") or "").lower(),
                        "reported_at": raw.get("reported_at"), "last_run": raw.get("last_run"),
                        "interval_minutes": raw.get("interval_minutes"), "expires_at": raw.get("expires_at"),
                        "detail": raw.get("detail"),
                        "unmapped_users": [str(u) for u in users if u] if isinstance(users, list) else []})


def path_fields(streams: dict[str, tuple[str, str | None]]) -> list[ConfigField]:
    """One optional setting per stream: its endpoint path (the defaults are placeholders until the API is confirmed)."""
    return [ConfigField(f"{s}_path", f"Endpoint path of the {s.replace('_', ' ')} stream (default {p}; to be confirmed "
                                     f"against the installed version)", required=False) for s, (p, _) in streams.items()]


def flag(v: Any) -> bool | None:
    """A vendor's yes / no in whatever form it comes; None when it says nothing."""
    if isinstance(v, bool):
        return v
    s = str(v or "").strip().lower()
    if s in {"true", "yes", "1", "enabled", "on", "active", "encrypted", "online", "installed"}:
        return True
    if s in {"false", "no", "0", "disabled", "off", "inactive", "not encrypted", "decrypted", "offline", "missing"}:
        return False
    return None


def device_type(os_name: Any, hint: Any = None) -> str:
    """workstation or server, from what the tool says (a stated type wins over the operating system's name)."""
    h = str(hint or "").lower()
    if h in {"server", "workstation"}:
        return h
    o = str(os_name or "").lower()
    return "server" if any(w in o for w in ("server", "linux", "ubuntu", "rhel", "centos", "debian")) else "workstation"
