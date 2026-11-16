"""Security controls per device: is the EDR agent there, is the DLP agent reporting, is the disk encrypted.

One device is one entity whatever tool reported it (entity resolution), and each tool's own view of it is kept under
``attributes["by_tool"][tool]``. A tool *lists* a device only through its own inventory record, and only while that
record is still in the tool's newest full read (``Snapshot.listed``):

* a device merely named in one of the tool's events - the laptop a DLP incident came from - is not thereby covered;
* a device the tool stopped listing (agent removed, object deleted from the directory) stops counting, once its
  record is ``SOC_INVENTORY_STALE_HOURS`` (48) older than the tool's newest read.

A control's state is read from the tool that owns it:

* ``ok``       the tool lists the device and the control is working
* ``silent``   the agent is installed but has not reported for ``SOC_AGENT_SILENT_HOURS`` (24)
* ``off``      the tool lists the device and says the control is not in force (disk not encrypted)
* ``unknown``  the tool lists the device but says nothing about the control
* ``missing``  the tool does not list the device at all

"Silent" and "stale" are measured from the newest report or read of that same tool (never later than now), not from
the wall clock: after an outage of the tool or the platform, or on dated sample data, every agent would otherwise
look silent at once. Everything here is computed; nothing is asked of a model.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.core.models import Entity, SourceRecord, utcnow

BASELINE_TOOL = "directory_export"
SHORT = ("missing", "silent", "off")          # states that leave the device without the control


@dataclass(frozen=True)
class Control:
    id: str
    label: str
    tool: str
    applies_to: tuple[str, ...]               # device types the control is expected on
    seen_field: str | None                    # the tool's "last reported" time for the device
    domain: str                               # the posture domain it counts towards


CONTROLS = (
    Control("edr", "EDR agent", "trend_micro", ("workstation", "server"), "last_connected", "endpoint"),
    Control("dlp_agent", "DLP agent reporting", "forcepoint_dlp", ("workstation",), "last_checkin", "data_protection"),
    Control("disk_encryption", "Disk encryption", "trellix_epo", ("workstation",), None, "data_protection"),
)
INVENTORY_TOOLS = (BASELINE_TOOL, *[c.tool for c in CONTROLS])


@dataclass
class Snapshot:
    """The devices and what each inventory tool currently says about them, read once per computation."""

    assets: list[Entity] = field(default_factory=list)
    listed: dict[str, set[str]] = field(default_factory=dict)      # tool -> entity ids in its newest full read
    newest: dict[str, datetime] = field(default_factory=dict)      # control tool -> newest agent report it holds

    @property
    def connected(self) -> set[str]:
        """Tools that list at least one device. A control whose tool lists nothing is "not measured", never
        "missing everywhere"."""
        return {t for t, ids in self.listed.items() if ids}

    def view(self, asset: Entity, tool: str) -> dict[str, Any] | None:
        """The tool's own record of the device, or None when the tool does not (or no longer) list it."""
        if asset.id not in self.listed.get(tool, ()):
            return None
        v = ((asset.attributes or {}).get("by_tool") or {}).get(tool)
        return v if isinstance(v, dict) else {}

    def tools_of(self, asset: Entity) -> set[str]:
        return {t for t, ids in self.listed.items() if asset.id in ids}


def _hours(name: str, default: float) -> timedelta:
    try:
        hours = float(os.environ.get(name, default) or default)
    except ValueError:
        hours = default
    return timedelta(hours=max(1.0, hours))


def silent_after() -> timedelta:
    return _hours("SOC_AGENT_SILENT_HOURS", 24)


def stale_after() -> timedelta:
    return _hours("SOC_INVENTORY_STALE_HOURS", 48)


def _ts(v: Any) -> datetime | None:
    from soc_platform.connectors.tools._common import parse_ts

    return parse_ts(v)


def _aware(v: datetime) -> datetime:
    from datetime import UTC

    return v if v.tzinfo is not None else v.replace(tzinfo=UTC)


def snapshot(session: Session) -> Snapshot:
    records = session.execute(select(SourceRecord.tool, SourceRecord.entity_id, SourceRecord.fetched_at).where(
        SourceRecord.tool.in_(INVENTORY_TOOLS), SourceRecord.kind == "asset", SourceRecord.entity_id.is_not(None))).all()
    last_read: dict[str, datetime] = {}
    for tool, _, at in records:
        if at is not None and (tool not in last_read or _aware(at) > last_read[tool]):
            last_read[tool] = _aware(at)
    listed: dict[str, set[str]] = {}
    for tool, eid, at in records:
        if at is not None and last_read[tool] - _aware(at) <= stale_after():
            listed.setdefault(tool, set()).add(eid)
    ids = sorted({e for s in listed.values() for e in s})
    assets: list[Entity] = []
    for i in range(0, len(ids), 500):
        assets += session.execute(select(Entity).where(Entity.id.in_(ids[i:i + 500]), Entity.kind == "asset")).scalars()
    assets.sort(key=lambda a: a.id)
    snap = Snapshot(assets=assets, listed=listed)
    now = utcnow()
    for c in CONTROLS:
        if not c.seen_field:
            continue
        times = [t for a in assets if (v := snap.view(a, c.tool)) is not None
                 and (t := _ts(v.get(c.seen_field))) is not None and t <= now]
        if times:
            snap.newest[c.tool] = max(times)
    return snap


def device_type(asset: Entity, snap: Snapshot) -> str:
    for tool in INVENTORY_TOOLS:
        t = (snap.view(asset, tool) or {}).get("device_type")
        if t in ("workstation", "server"):
            return t
    return "workstation"


def control_state(control: Control, asset: Entity, snap: Snapshot) -> tuple[str, str]:
    """(state, what an engineer needs to know) for one control on one device."""
    seen = snap.view(asset, control.tool)
    if seen is None:
        return "missing", f"not listed by {control.tool}"
    if control.id == "disk_encryption":
        enc = seen.get("disk_encrypted")
        if enc is True:
            return "ok", "encrypted"
        if enc is False:
            return "off", f"reported as {seen.get('encryption_state') or 'not encrypted'}"
        return "unknown", "the tool reports no encryption state for this device"
    last = _ts(seen.get(control.seen_field)) if control.seen_field else None
    ref = snap.newest.get(control.tool)
    if last is not None and ref is not None and ref - last > silent_after():
        hours = int((ref - last).total_seconds() // 3600)
        return "silent", f"last reported {last.strftime('%Y-%m-%d %H:%M')} UTC ({hours} h before the newest check-in)"
    if last is None:
        return "unknown", "installed, no check-in time reported"
    return "ok", f"reported {last.strftime('%Y-%m-%d %H:%M')} UTC"


def device_controls(asset: Entity, snap: Snapshot) -> list[dict[str, Any]]:
    """Every control expected on this device, with its state. Controls whose tool is not connected are left out."""
    kind = device_type(asset, snap)
    out = []
    for c in CONTROLS:
        if c.tool not in snap.connected or kind not in c.applies_to:
            continue
        state, detail = control_state(c, asset, snap)
        out.append({"control": c.id, "label": c.label, "tool": c.tool, "state": state, "detail": detail})
    return out
