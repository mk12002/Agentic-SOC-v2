"""Tool health watch (Dome Connect): problems with the security tools themselves, found before something breaks.

Read from what each tool reports about its own upkeep (the connectors' ``health`` streams) and from the agents'
check-ins (``core/controls.py``):

* a certificate close to expiry        warning at ``SOC_CERT_WARN_DAYS`` (30), critical at ``SOC_CERT_CRITICAL_DAYS`` (14)
* a sync or deployment job that failed (critical), finished with errors (warning) or is late - not run for twice its
  interval (warning)
* a directory import that left people out of every policy group (warning: they are in no data-protection policy)
* agents that stopped reporting         warning; critical above ``AGENTS_SILENT_CRITICAL`` of the devices expected

"Now" for a tool is the newest time that tool reported (never later than the clock), so dated sample data and a tool
that was unreachable for a while are judged as of their own last report. Each finding carries the next step for an
engineer; nothing here changes a tool. A tool that exposes none of this is listed as "not reported by the tool" -
health is shown wherever a tool reports it, never assumed.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from soc_platform.connectors.tools._common import parse_ts
from soc_platform.core import controls
from soc_platform.core.models import Entity, utcnow

AGENTS_SILENT_CRITICAL = 0.10
ORDER = {"critical": 0, "warning": 1}
FAILED = {"failed", "error", "failure", "stopped"}
PARTIAL = {"completed_with_errors", "warning", "partial", "degraded"}


def _days(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default) or default))
    except ValueError:
        return default


def _finding(tool: str, check: str, severity: str, title: str, detail: str, next_step: str, **data: Any) -> dict[str, Any]:
    return {"tool": tool, "check": check, "severity": severity, "title": title, "detail": detail,
            "next_step": next_step, "data": data}


def _health_findings(tool: str, items: list[Entity], now: datetime) -> list[dict[str, Any]]:
    warn, crit = _days("SOC_CERT_WARN_DAYS", 30), _days("SOC_CERT_CRITICAL_DAYS", 14)
    out = []
    for it in items:
        a = it.attributes or {}
        name = it.display_name or "unnamed check"
        check = str(a.get("check") or "service")
        status = str(a.get("status") or "")
        if check == "certificate":
            expires = parse_ts(a.get("expires_at"))
            if expires is None:
                continue
            left = (expires - now).days
            if left < 0:
                out.append(_finding(tool, check, "critical", f"{name} has expired",
                                    f"Expired on {expires:%Y-%m-%d}.", "Renew the certificate now.", days_left=left))
            elif left <= warn:
                out.append(_finding(tool, check, "critical" if left <= crit else "warning", f"{name}: {left} day(s) left",
                                    f"Expires on {expires:%Y-%m-%d}.", "Raise a renewal ticket.", days_left=left))
            continue
        last = parse_ts(a.get("last_run"))
        interval = a.get("interval_minutes")
        if status in FAILED:
            out.append(_finding(tool, check, "critical", f"{name} failed", str(a.get("detail") or "The tool reports a failure."),
                                "Check the job in the tool and re-run it.", status=status))
        elif status in PARTIAL and not a.get("unmapped_users"):    # with names, the finding below says what went wrong
            out.append(_finding(tool, check, "warning", f"{name} finished with errors",
                                str(a.get("detail") or "The tool reports errors."), "Review the job's log in the tool.",
                                status=status))
        if last is not None and isinstance(interval, (int, float)) and not isinstance(interval, bool) and interval > 0:
            late = (now - last).total_seconds() / 60 - 2 * float(interval)
            if late > 0:
                out.append(_finding(tool, check, "warning", f"{name} is late",
                                    f"Last ran {last:%Y-%m-%d %H:%M} UTC; expected every {int(interval)} minutes.",
                                    "Check that the job is scheduled and running.", last_run=last.isoformat()))
        people = [str(u) for u in a.get("unmapped_users") or []]
        if people:
            out.append(_finding(tool, "directory_sync", "warning", f"{len(people)} people are in no policy group",
                                "The directory import could not map: " + ", ".join(sorted(people)[:10])
                                + (" ..." if len(people) > 10 else "") + ". No data-protection policy applies to them.",
                                "Fix the directory mapping for these accounts.", people=sorted(people)))
    return out


def _agent_findings(session: Session) -> list[dict[str, Any]]:
    snap = controls.snapshot(session)
    out = []
    for c in controls.CONTROLS:
        if c.tool not in snap.connected or not c.seen_field:
            continue
        listed = [a for a in snap.assets if snap.view(a, c.tool) is not None]
        silent = sorted(a.display_name for a in listed if controls.control_state(c, a, snap)[0] == "silent")
        if silent:
            share = len(silent) / len(listed)
            hours = int(controls.silent_after().total_seconds() // 3600)
            out.append(_finding(c.tool, "agents", "critical" if share > AGENTS_SILENT_CRITICAL else "warning",
                                f"{len(silent)} {c.label.split(' ')[0]} agent(s) silent for more than {hours} h",
                                "Not reporting: " + ", ".join(silent[:10]) + (" ..." if len(silent) > 10 else "") + ".",
                                "Re-push the agent through endpoint management (a change to the estate: on approval).",
                                devices=silent, listed=len(listed)))
    return out


def tool_health(session: Session, tools: list[str] | None = None) -> dict[str, Any]:
    """``tools``: the connected tools to list (so a healthy or silent tool still shows); default: those that reported."""
    items: dict[str, list[Entity]] = {}
    for e in session.execute(select(Entity).where(Entity.kind == "tool_health").order_by(Entity.canonical_key)).scalars():
        items.setdefault(str((e.attributes or {}).get("tool") or "unknown"), []).append(e)
    clock = utcnow()
    findings: list[dict[str, Any]] = []
    as_of: dict[str, str] = {}
    for tool, recs in sorted(items.items()):
        times = [t for r in recs if (t := parse_ts((r.attributes or {}).get("reported_at"))) is not None and t <= clock]
        now = max(times) if times else clock
        as_of[tool] = now.isoformat()
        findings += _health_findings(tool, recs, now)
    findings += _agent_findings(session)
    findings.sort(key=lambda f: (ORDER[f["severity"]], f["tool"], f["title"]))
    agents = {c.tool for c in controls.CONTROLS if c.seen_field} & controls.snapshot(session).connected
    names = sorted(set(tools or []) | set(items) | agents)
    summary = []
    for t in names:
        mine = [f for f in findings if f["tool"] == t]
        reports = t in items or t in agents
        summary.append({"tool": t, "status": "critical" if any(f["severity"] == "critical" for f in mine) else
                        "warning" if mine else "healthy" if reports else "not_reported",
                        "findings": len(mine), "headline": mine[0]["title"] if mine else
                        "Healthy" if reports else "Health is not reported by this tool",
                        "checks": len(items.get(t, [])), "as_of": as_of.get(t)})
    return {"tools": summary, "findings": findings,
            "counts": {"critical": sum(f["severity"] == "critical" for f in findings),
                       "warning": sum(f["severity"] == "warning" for f in findings)}}
