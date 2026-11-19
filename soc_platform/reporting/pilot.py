"""Pilot scorecard (M13): what the pilot set out to change, measured against NAM's own week-2 baseline.

Every figure is computed from the platform's records or entered by a person where software cannot see it; the model
produces none of them. No target is preset: the SOC lead sets each one (the deck's figures are pilot targets to be
agreed, never defaults presented as agreed).

KPIs:

* ``dlp_reaching_analyst_pct``  share of the week's DLP alerts that reach an analyst - the computed check would not
                                close them (and, once a decision type decides, the AI did not close them)
* ``dlp_alerts_per_day``        the week's DLP alerts per day
* ``outages_found_by_users``    tool outages in 30 days that users found before the platform (from the outage log)
* ``ai_agreement_pct.<type>``   the AI's agreement with analysts per DLP decision type (its target is the decision
                                type's own, set on the autonomy screen)
* ``model_share_pct``           share of the week's DLP alerts the model decided on
* ``model_cost_per_alert``      cost of the DLP model calls in the week per DLP alert (USD, from the AI usage policy's prices)

The week is the 7 days up to the newest DLP alert, so dated sample data and a quiet weekend are judged alike.
QA re-checks of AI closures are reported on their own, never mixed into agreement.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow

WEEK = timedelta(days=7)
OUTAGE_DAYS = 30
PREFIX = "pilot."
KPIS: dict[str, dict[str, Any]] = {
    "dlp_reaching_analyst_pct": {"label": "DLP alerts reaching an analyst", "unit": "%", "better": "lower",
                                 "measured_from": "the week's DLP alerts the computed check (or a deciding AI) would not close"},
    "dlp_alerts_per_day": {"label": "DLP alerts per day", "unit": "alerts", "better": "lower",
                           "measured_from": "the week's DLP alerts / 7"},
    "outages_found_by_users": {"label": "Tool outages found by users first", "unit": "outages", "better": "lower",
                               "measured_from": "the outage log, last 30 days"},
    "model_share_pct": {"label": "DLP alerts decided by the model", "unit": "%", "better": "higher",
                        "measured_from": "the week's DLP alerts with the model's own decision stored"},
    "model_cost_per_alert": {"label": "Model cost per DLP alert", "unit": "USD", "better": "lower",
                             "measured_from": "DLP model calls in the week x the AI usage policy's prices / the week's alerts"},
}
KINDS = ("baseline", "target")


class PilotOutage(Base):
    """A tool outage and who found it first - users (a ticket, a call) or the platform (tool health)."""
    __tablename__ = "pilot_outages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tool: Mapped[str] = mapped_column(String(64))
    found_by: Mapped[str] = mapped_column(String(16))                 # users | platform
    found_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    summary: Mapped[str] = mapped_column(BoundedText(500), default="")
    recorded_by: Mapped[str] = mapped_column(String(256))
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


def _aware(v: datetime | None) -> datetime | None:
    from datetime import UTC

    return None if v is None else (v if v.tzinfo else v.replace(tzinfo=UTC))


def _week(s: Session) -> tuple[datetime, datetime] | None:
    from soc_platform.domains.dlp.models import DlpAlert

    newest = s.execute(select(func.max(DlpAlert.event_time))).scalar()
    return None if newest is None else (newest - WEEK, newest)


def measure(s: Session) -> dict[str, dict[str, Any]]:
    """The current value of every KPI, with what it was computed from."""
    from soc_platform.core.models import LLMCall
    from soc_platform.domains.dlp.models import DlpAlert
    from soc_platform.llm.usage_policy import UsagePolicyStore, _cost

    out: dict[str, dict[str, Any]] = {}
    wk = _week(s)
    if wk is None:
        for k in ("dlp_reaching_analyst_pct", "dlp_alerts_per_day", "model_share_pct", "model_cost_per_alert"):
            out[k] = {"current": None, "detail": "no DLP alert yet"}
    else:
        lo, hi = wk
        rows = s.execute(select(DlpAlert.computed_outcome, DlpAlert.ai_effective, DlpAlert.ai_outcome).where(
            DlpAlert.event_time > lo, DlpAlert.event_time <= hi)).all()
        n = len(rows)
        # today the AI never closes on its own (decide is refused): only the computed check keeps an alert away
        reach = sum(1 for comp, _eff, _ai in rows if comp != "close_benign")
        decided = sum(1 for *_x, ai in rows if ai is not None)
        from soc_platform.config import get_settings

        policy = UsagePolicyStore(s, get_settings()).active()
        calls = s.execute(select(LLMCall.model, LLMCall.prompt_tokens, LLMCall.completion_tokens).where(
            LLMCall.workflow.like("dlp.%"), LLMCall.ts >= _aware(utcnow()) - WEEK)).all()
        cost = sum(_cost(policy, m, a or 0, b or 0) for m, a, b in calls)
        week = {"from": _aware(lo).isoformat(), "to": _aware(hi).isoformat(), "alerts": n}
        out["dlp_reaching_analyst_pct"] = {"current": round(100 * reach / n, 1) if n else None, "reaching": reach, **week}
        out["dlp_alerts_per_day"] = {"current": round(n / 7, 1), **week}
        out["model_share_pct"] = {"current": round(100 * decided / n, 1) if n else None, "decided": decided, **week}
        out["model_cost_per_alert"] = {"current": round(cost / n, 5) if n and calls else (0.0 if n else None),
                                       "calls": len(calls), "cost": round(cost, 4), **week}
    since = _aware(utcnow()) - timedelta(days=OUTAGE_DAYS)
    outs = s.execute(select(PilotOutage).where(PilotOutage.found_at >= since)).scalars().all()
    by_users = sum(o.found_by == "users" for o in outs)
    out["outages_found_by_users"] = {"current": by_users if outs else None, "found_by_platform": len(outs) - by_users,
                                     "logged": len(outs), "detail": None if outs else "no outage logged in 30 days"}
    return out


def _entered(s: Session) -> dict[str, dict[str, Any]]:
    from soc_platform.reporting.models import ValueInput

    out: dict[str, dict[str, Any]] = {}
    for r in s.execute(select(ValueInput).where(ValueInput.kpi.like(PREFIX + "%"))
                       .order_by(ValueInput.set_at, ValueInput.id)).scalars():
        out.setdefault(r.kpi[len(PREFIX):], {})[r.kind] = {"value": r.value, "note": r.note, "set_by": r.set_by,
                                                           "set_at": _aware(r.set_at).isoformat()}
    return out


def _status(better: str, baseline: float | None, current: float | None, target: float | None) -> str:
    if current is None:
        return "no_data"
    lower = better == "lower"
    if target is not None and (current <= target if lower else current >= target):
        return "met"
    if baseline is None:
        return "no_baseline"
    if target is None:
        return "no_target"
    return "improving" if (current < baseline if lower else current > baseline) else "not_improved"


def scorecard(s: Session) -> dict[str, Any]:
    from soc_platform.core.decisions import DecisionStore

    m, e = measure(s), _entered(s)
    rows = []
    for k, d in KPIS.items():
        x = dict(m.get(k, {}))
        cur = x.pop("current", None)
        base = e.get(k, {}).get("baseline", {}).get("value")
        tgt = e.get(k, {}).get("target", {}).get("value")
        rows.append({"id": k, **d, "current": cur, "baseline": base, "target": tgt,
                     "baseline_note": e.get(k, {}).get("baseline", {}).get("note"),
                     "change_pct": round(100 * (cur - base) / base, 1) if cur is not None and base else None,
                     "status": _status(d["better"], base, cur, tgt), "supporting": x})
    agreement = []
    for t in DecisionStore(s).evaluate():
        tgt = (t.get("target") or {}).get("agreement_percent")
        agreement.append({"id": f"ai_agreement_pct.{t['decision_type']}", "label": t["label"],
                          "unit": "%", "stage": t["stage"], "current": t.get("agreement_percent"), "sample": t.get("sample"),
                          "target": tgt, "min_sample": (t.get("target") or {}).get("min_sample"),
                          "status": "no_data" if t.get("agreement_percent") is None else
                          "no_target" if tgt is None else "met" if t["agreement_percent"] >= tgt else "not_met"})
    from soc_platform.domains.dlp.models import DlpAlert

    # the AI's "close" where a person also ruled: how often the person agreed (reported apart from agreement above)
    ruled = s.execute(select(DlpAlert.analyst_outcome).where(DlpAlert.ai_effective == "close_benign",
                                                           DlpAlert.analyst_outcome.is_not(None))).scalars().all()
    return {"kpis": rows, "ai_agreement": agreement,
            "qa_rechecks": {"ai_would_close_and_person_ruled": len(ruled),
                            "person_disagreed": sum(o != "close_benign" for o in ruled),
                            "note": "The AI closes nothing on its own before the decide stage; once it does, 1 in 10 of "
                                    "its closures is re-checked by a person and reported here."},
            "statuses": {st: sum(r["status"] == st for r in rows)
                         for st in ("met", "improving", "not_improved", "no_baseline", "no_target", "no_data")}}


def set_figure(s: Session, kpi: str, kind: str, value: Any, *, note: str, by: str) -> dict[str, Any]:
    """Record a baseline or a target (replacing the previous one); audited."""
    from soc_platform.reporting.models import ValueInput

    if kpi not in KPIS:
        raise ValueError(f"unknown pilot KPI {kpi!r}")
    if kind not in KINDS:
        raise ValueError("kind is baseline or target")
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value) or value < 0:
        raise ValueError("the value must be a non-negative number")
    if KPIS[kpi]["unit"] == "%" and value > 100:
        raise ValueError("a percentage cannot exceed 100")
    for old in s.execute(select(ValueInput).where(ValueInput.kpi == PREFIX + kpi, ValueInput.kind == kind)).scalars():
        s.delete(old)
    s.add(ValueInput(kpi=PREFIX + kpi, kind=kind, value=float(value), note=str(note or "")[:500], set_by=by, set_at=utcnow()))
    s.flush()
    AuditLog(s).append(actor_type="human", actor_id=by, event_type="pilot.figure_set", subject_type="pilot_kpi",
                       subject_id=kpi, payload={"kind": kind, "value": float(value), "note": str(note or "")[:200]})
    return {"kpi": kpi, "kind": kind, "value": float(value)}


def capture_baseline(s: Session, kpi: str, *, by: str) -> dict[str, Any]:
    """Take the current measured value as the baseline (the pilot's week-2 measurement)."""
    if kpi not in KPIS:
        raise ValueError(f"unknown pilot KPI {kpi!r}")
    m = measure(s)[kpi]
    if m.get("current") is None:
        raise ValueError("nothing is measured yet for this KPI")
    period = f"the week {m['from'][:10]} to {m['to'][:10]}" if m.get("from") else "the last 30 days"
    return set_figure(s, kpi, "baseline", m["current"], note=f"captured from {period}", by=by)


def log_outage(s: Session, *, tool: str, found_by: str, found_at: datetime | None, summary: str, by: str) -> PilotOutage:
    if found_by not in ("users", "platform"):
        raise ValueError("found_by is users or platform")
    from soc_platform.connectors.registry import discover

    tool = str(tool or "").strip()
    if not tool:
        raise ValueError("name the tool")
    if tool not in discover():
        raise ValueError(f"unknown tool {tool[:64]!r}: name a connector (e.g. forcepoint_dlp)")
    when = _aware(found_at) or _aware(utcnow())
    if when > _aware(utcnow()) + timedelta(minutes=5):
        raise ValueError("an outage cannot be found in the future")
    if when < _aware(utcnow()) - timedelta(days=400):
        raise ValueError("an outage older than 400 days is outside the pilot")
    row = PilotOutage(tool=str(tool).strip()[:64], found_by=found_by, found_at=when, summary=str(summary or "")[:500],
                      recorded_by=by, recorded_at=utcnow())
    s.add(row)
    s.flush()
    AuditLog(s).append(actor_type="human", actor_id=by, event_type="pilot.outage_logged", subject_type="pilot_outage",
                       subject_id=str(row.id), payload={"tool": row.tool, "found_by": found_by, "found_at": when.isoformat()})
    return row


def outages(s: Session, *, days: int = 90) -> list[dict[str, Any]]:
    since = _aware(utcnow()) - timedelta(days=days)
    return [{"id": o.id, "tool": o.tool, "found_by": o.found_by, "found_at": _aware(o.found_at).isoformat(),
             "summary": o.summary, "recorded_by": o.recorded_by}
            for o in s.execute(select(PilotOutage).where(PilotOutage.found_at >= since)
                               .order_by(PilotOutage.found_at.desc(), PilotOutage.id.desc())).scalars()]
