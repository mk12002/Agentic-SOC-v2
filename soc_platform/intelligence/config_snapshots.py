"""Configuration snapshots (Dome Score / Dome Connect): what each tool's configuration was, what changed, whether the
change was recorded, and whether posture dipped after it.

* **Where the tool can export it.** A connector with ``exports_config`` gives its policies / rules in full
  (``config_items``). Tools that cannot are listed as "not exported" - never assumed unchanged.
* **Snapshots.** ``scheduled`` (the ``config_snapshot`` job, daily: a new row only when the content changed, else the
  newest row is confirmed), ``manual``, and a change's ``before_change`` / ``after_change`` pair, which carry the
  change's reference. Each stores every item (sorted by its id), a content hash and the posture score at that moment.
* **Drift.** Between two consecutive snapshots of a tool: items added, removed, and changed field by field. A
  difference is *planned* when it is the after-change snapshot of a recorded change, or when it falls inside a change
  window still open (a before-change snapshot with no after-change yet); otherwise it is *unplanned* and is reported
  on tool health.
* **Posture dip.** The after-change record compares the posture score with the one taken before the change.

Nothing here changes a tool; every figure is computed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, Float, Integer, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.connectors.base import ConnectorError
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow

REASONS = ("scheduled", "manual", "before_change", "after_change")
MAX_ITEMS = 5000
MAX_VALUE = 300
RECENT_DAYS = 7


class ConfigSnapshot(Base):
    __tablename__ = "config_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(String(16))
    reference: Mapped[str] = mapped_column(BoundedText(120), default="")      # the change's ticket or name
    note: Mapped[str] = mapped_column(BoundedText(1000), default="")
    items: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str] = mapped_column(String(64))
    posture_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    taken_by: Mapped[str] = mapped_column(String(256))
    taken_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    confirmed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)   # newest read with this content


def _hash(items: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(items, sort_keys=True, ensure_ascii=True, default=str).encode()).hexdigest()


def _short(v: Any) -> Any:
    s = json.dumps(v, sort_keys=True, ensure_ascii=False, default=str) if not isinstance(v, str) else v
    return s if len(s) <= MAX_VALUE else s[:MAX_VALUE] + "…"


def _label(item: dict[str, Any]) -> str:
    return str(item.get("name") or item.get("id"))


def diff(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    """Items added, removed and changed (field by field) between two snapshots, keyed by the item's id."""
    a = {str(i["id"]): i for i in before}
    b = {str(i["id"]): i for i in after}
    changed = []
    for k in sorted(set(a) & set(b)):
        fields = [{"field": f, "before": _short(a[k].get(f)), "after": _short(b[k].get(f))}
                  for f in sorted(set(a[k]) | set(b[k])) if a[k].get(f) != b[k].get(f)]
        if fields:
            changed.append({"id": k, "name": _label(b[k]), "fields": fields})
    return {"added": [{"id": k, "name": _label(b[k])} for k in sorted(set(b) - set(a))],
            "removed": [{"id": k, "name": _label(a[k])} for k in sorted(set(a) - set(b))],
            "changed": changed,
            "count": len(set(b) - set(a)) + len(set(a) - set(b)) + len(changed)}


class ConfigSnapshots:
    def __init__(self, session: Session, registry: Any) -> None:
        self.s = session
        self.registry = registry
        self.audit = AuditLog(session)

    # ------------------------------------------------------------------ reading the tools

    def capable(self) -> dict[str, bool]:
        """Every enabled tool and whether it exports its configuration."""
        out = {}
        for name in sorted(self.registry.enabled_names()):
            out[name] = bool(getattr(self.registry.get(name), "exports_config", False))
        return out

    def _read(self, tool: str) -> tuple[list[dict[str, Any]], int]:
        if not self.capable().get(tool):
            raise KeyError(f"{tool} is not connected or does not export its configuration")
        raw = self.registry.get(tool).config_items()
        items = sorted(({k: v for k, v in i.items()} for i in raw if i.get("id") not in (None, "")), key=lambda i: str(i["id"]))
        if len(items) > MAX_ITEMS:
            raise ValueError(f"{tool} exported {len(items)} configuration items; the snapshot keeps at most {MAX_ITEMS}")
        return items, len(raw) - len(items)

    def latest(self, tool: str) -> ConfigSnapshot | None:
        return self.s.execute(select(ConfigSnapshot).where(ConfigSnapshot.tool == tool)
                              .order_by(ConfigSnapshot.id.desc()).limit(1)).scalars().first()

    def _previous(self, snap: ConfigSnapshot) -> ConfigSnapshot | None:
        return self.s.execute(select(ConfigSnapshot).where(ConfigSnapshot.tool == snap.tool, ConfigSnapshot.id < snap.id)
                              .order_by(ConfigSnapshot.id.desc()).limit(1)).scalars().first()

    def open_window(self, tool: str) -> ConfigSnapshot | None:
        """The before-change snapshot of a change still in progress, if any."""
        last = self.s.execute(select(ConfigSnapshot).where(
            ConfigSnapshot.tool == tool, ConfigSnapshot.reason.in_(("before_change", "after_change")))
            .order_by(ConfigSnapshot.id.desc()).limit(1)).scalars().first()
        return last if last is not None and last.reason == "before_change" else None

    def take(self, tool: str, *, reason: str, by: str, reference: str = "", note: str = "") -> ConfigSnapshot:
        """Read the tool's configuration and keep it. A scheduled read that finds nothing new only confirms the
        newest snapshot (no new row)."""
        from soc_platform.intelligence.posture import posture

        if reason not in REASONS:
            raise ValueError(f"reason must be one of {', '.join(REASONS)}")
        items, dropped = self._read(tool)
        h = _hash(items)
        last = self.latest(tool)
        if reason == "scheduled" and last is not None and last.content_hash == h:
            last.confirmed_at = utcnow()
            self.s.flush()
            return last
        snap = ConfigSnapshot(tool=tool, reason=reason, reference=reference[:120], note=note[:1000], items=items,
                              item_count=len(items), content_hash=h, posture_score=posture(self.s)["score"], taken_by=by)
        self.s.add(snap)
        self.s.flush()
        change = self.change_of(snap)
        self.audit.append(actor_type="agent" if by.startswith("agent:") else "human", actor_id=by,
                          event_type="config.snapshot", subject_type="tool", subject_id=tool,
                          payload={"snapshot": snap.id, "reason": reason, "reference": snap.reference,
                                   "items": len(items), "dropped_without_id": dropped, "hash": h,
                                   "changes": change["diff"]["count"] if change else None,
                                   "planned": change["planned"] if change else None})
        return snap

    # ------------------------------------------------------------------ changes

    def change_of(self, snap: ConfigSnapshot) -> dict[str, Any] | None:
        """What changed between this snapshot and the one before it, and whether it was planned."""
        prev = self._previous(snap)
        if prev is None:
            return None
        d = diff(prev.items, snap.items)
        planned = snap.reason == "after_change" or prev.reason == "before_change"
        return {"from": prev.id, "to": snap.id, "diff": d, "planned": planned if d["count"] else None,
                "reference": snap.reference or prev.reference if planned else ""}

    def changes(self, *, tool: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        q = select(ConfigSnapshot).order_by(ConfigSnapshot.id.desc()).limit(limit * 2)
        if tool:
            q = q.where(ConfigSnapshot.tool == tool)
        out = []
        for snap in self.s.execute(q).scalars():
            c = self.change_of(snap)
            if c and c["diff"]["count"]:
                out.append({"tool": snap.tool, "at": snap.taken_at.isoformat(), "snapshot": snap.id, **c})
        return out[:limit]

    def unplanned(self, *, days: int = RECENT_DAYS) -> list[dict[str, Any]]:
        since = utcnow() - timedelta(days=days)
        return [c for c in self.changes(limit=200) if c["planned"] is False and datetime.fromisoformat(c["at"]) >= since]

    def before_change(self, tool: str, by: Principal, *, reference: str, note: str = "") -> ConfigSnapshot:
        _may_record(by)
        if not reference.strip():
            raise ValueError("a change needs its reference (ticket or name)")
        if self.open_window(tool) is not None:
            raise ValueError(f"a change to {tool} is already in progress; record its after-change snapshot first")
        return self.take(tool, reason="before_change", by=by.id, reference=reference.strip(), note=note)

    def after_change(self, tool: str, by: Principal, *, note: str = "") -> dict[str, Any]:
        _may_record(by)
        before = self.open_window(tool)
        if before is None:
            raise ValueError(f"no change to {tool} is in progress: take a before-change snapshot first")
        after = self.take(tool, reason="after_change", by=by.id, reference=before.reference, note=note)
        d = diff(before.items, after.items)
        dip = (None if before.posture_score is None or after.posture_score is None
               else round(after.posture_score - before.posture_score, 1))
        return {"reference": before.reference, "before": self.view(before, with_items=False),
                "after": self.view(after, with_items=False), "diff": d, "posture_change": dip,
                "posture_dipped": dip is not None and dip < 0}

    # ------------------------------------------------------------------ read models

    def view(self, snap: ConfigSnapshot, *, with_items: bool = True) -> dict[str, Any]:
        out = {"id": snap.id, "tool": snap.tool, "reason": snap.reason, "reference": snap.reference, "note": snap.note,
               "items": snap.item_count, "hash": snap.content_hash, "posture_score": snap.posture_score,
               "taken_by": snap.taken_by, "taken_at": snap.taken_at.isoformat(), "confirmed_at": snap.confirmed_at.isoformat()}
        if with_items:
            out["content"] = snap.items
            out["change"] = self.change_of(snap)
        return out

    def get(self, snapshot_id: int) -> dict[str, Any]:
        snap = self.s.get(ConfigSnapshot, snapshot_id)
        if snap is None:
            raise KeyError("unknown snapshot")
        return self.view(snap)

    def overview(self) -> dict[str, Any]:
        tools = []
        for name, ok in self.capable().items():
            last = self.latest(name) if ok else None
            window = self.open_window(name) if ok else None
            tools.append({"tool": name, "exports_config": ok,
                          "latest": self.view(last, with_items=False) if last else None,
                          "change_in_progress": {"reference": window.reference, "since": window.taken_at.isoformat(),
                                                 "by": window.taken_by} if window else None})
        return {"tools": tools, "changes": self.changes(), "unplanned_recent": len(self.unplanned())}

    def snapshot_all(self, *, by: str = "agent:config") -> dict[str, Any]:
        """The scheduled read of every tool that exports its configuration. One tool down never stops the others."""
        from soc_platform.core.observability import event

        taken, unchanged, failed = [], [], []
        for name, ok in self.capable().items():
            if not ok:
                continue
            before = self.latest(name)
            try:
                snap = self.take(name, reason="scheduled", by=by)
            except (ConnectorError, ValueError) as exc:
                failed.append(name)
                event("config.snapshot_failed", 30, tool=name, error=f"{type(exc).__name__}: {exc}"[:300])
                continue
            (unchanged if before is not None and snap.id == before.id else taken).append(name)
        return {"taken": taken, "unchanged": unchanged, "failed": failed}


def _may_record(by: Principal) -> None:
    """Recording a change to a tool is for the people who run the tools (connector management), in person."""
    if by.is_agent or by.is_service or not by.can(Perm.MANAGE_CONNECTORS):
        raise PermissionError("manage_connectors permission required (a person)")
