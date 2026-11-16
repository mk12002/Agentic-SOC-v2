"""Control coverage (Dome Graph): which devices are missing a security control.

The baseline is the directory export (the devices the organisation says it has). Each control is asked of the tool
that owns it (``core/controls.py``). A device is *fully covered* only when every control expected on it is in place and
reporting - a stricter test than "the device is visible". Reported besides: devices a control tool sees that the
baseline does not list (often where the real gaps are), and controls that are not measured because their tool is not
connected (never counted as missing).

Devices short of a control are ranked so the riskiest is fixed first: by the number of DLP alerts with personal data
on the device or from its main user, then by how many controls are missing, then by name. Every figure is computed.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.core import controls
from soc_platform.core.models import EntityKey
from soc_platform.domains.dlp.models import DlpAlert


def _exposure(session: Session) -> tuple[Counter, Counter]:
    """DLP alerts carrying personal data, counted per device and per person."""
    def per(column) -> Counter:
        rows = session.execute(select(column, func.count()).where(DlpAlert.personal_data.is_(True), column.is_not(None))
                               .group_by(column)).all()
        return Counter(dict(rows))

    return per(DlpAlert.host_entity_id), per(DlpAlert.user_entity_id)


def _people(session: Session, upns: set[str]) -> dict[str, str]:
    """UPN -> identity entity id, for the devices' main users."""
    out: dict[str, str] = {}
    ordered = sorted(upns)
    for i in range(0, len(ordered), 500):
        for value, eid in session.execute(select(EntityKey.key_value, EntityKey.entity_id).where(
                EntityKey.kind == "identity", EntityKey.key_name == "upn", EntityKey.key_value.in_(ordered[i:i + 500]))).all():
            out[value] = eid
    return out


def coverage(session: Session, *, limit: int = 500) -> dict[str, Any]:
    snap = controls.snapshot(session)
    rows, connected = snap.assets, snap.connected
    base = {a.id: snap.view(a, controls.BASELINE_TOOL) for a in rows}
    baseline = [a for a in rows if base[a.id] is not None and base[a.id].get("directory_enabled") is not False]
    measured = [c for c in controls.CONTROLS if c.tool in connected]
    not_measured = [{"control": c.id, "label": c.label, "tool": c.tool} for c in controls.CONTROLS if c.tool not in connected]
    if not baseline:
        return {"available": False, "reason": "No device baseline has been read yet (the directory export).",
                "baseline": {"tool": controls.BASELINE_TOOL, "devices": 0}, "controls": [], "not_measured": not_measured,
                "devices_short": [], "unlisted": [], "fully_covered": 0, "coverage_percent": None}
    newest = snap.newest
    hosts_exp, users_exp = _exposure(session)
    main_user = {a.id: str(base[a.id].get("primary_user") or "") for a in baseline}
    people = _people(session, {u for u in main_user.values() if u})
    per = {c.id: Counter() for c in measured}
    short_rows = []
    full = 0
    for a in baseline:
        states = controls.device_controls(a, snap)
        for s in states:
            per[s["control"]]["applicable"] += 1
            per[s["control"]][s["state"]] += 1
        short = [s for s in states if s["state"] in controls.SHORT]
        if states and not short:
            full += 1
        if short:
            exposure = hosts_exp.get(a.id, 0) + users_exp.get(people.get(main_user[a.id], ""), 0)
            short_rows.append({"entity_id": a.id, "name": a.display_name, "device_type": controls.device_type(a, snap),
                               "primary_user": main_user[a.id] or None, "missing": short,
                               "personal_data_alerts": exposure})
    short_rows.sort(key=lambda r: (-r["personal_data_alerts"], -len(r["missing"]), r["name"]))
    for i, r in enumerate(short_rows):
        r["rank"] = i + 1
    control_tools = {c.tool for c in controls.CONTROLS}
    unlisted = sorted(({"entity_id": a.id, "name": a.display_name, "seen_by": sorted(snap.tools_of(a) & control_tools)}
                       for a in rows if base[a.id] is None and snap.tools_of(a) & control_tools), key=lambda r: r["name"])
    return {"available": True,
            "baseline": {"tool": controls.BASELINE_TOOL, "devices": len(baseline)},
            "controls": [{"control": c.id, "label": c.label, "tool": c.tool, "domain": c.domain,
                          "applies_to": list(c.applies_to), "applicable": per[c.id]["applicable"],
                          "covered": per[c.id]["ok"], "short": sum(per[c.id][s] for s in controls.SHORT),
                          "missing": per[c.id]["missing"], "silent": per[c.id]["silent"], "off": per[c.id]["off"],
                          "unknown": per[c.id]["unknown"],
                          "covered_percent": round(100 * per[c.id]["ok"] / per[c.id]["applicable"], 1)
                          if per[c.id]["applicable"] else None} for c in measured],
            "not_measured": not_measured, "fully_covered": full, "devices_short_count": len(short_rows),
            "coverage_percent": round(100 * full / len(baseline), 1),
            "devices_short": short_rows[:limit], "unlisted": unlisted[:limit],
            "silent_after_hours": controls.silent_after().total_seconds() / 3600,
            "as_of": {t: v.isoformat() for t, v in sorted(newest.items())}}
