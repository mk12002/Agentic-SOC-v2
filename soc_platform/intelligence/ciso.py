"""The CISO view (Dome Score screen, M10): everything a CISO needs on one page, every figure computed.

Built from the same functions as the screens behind it (posture, coverage, tool health, the DLP queue, decision types,
configuration snapshots, cases, approvals, the audit chain), so the CISO view never shows a figure another screen
contradicts. The model's part is ``explain``: plain words over the computed evidence, every sentence cited; without the
model the same evidence is written out by rule.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.core.models import ActionRequest, Case, Entity, utcnow
from soc_platform.core.schema import severity_rank

HEALTH_TOOLS = ("forcepoint_dlp", "silverfort", "trend_micro", "trellix_epo", "directory_export")
WINDOW_DAYS = 7          # "this week" against "the week before", anchored to the newest alert (not the wall clock)
PEOPLE_DAYS = 30


def _iso(v: Any) -> str | None:
    if v is None:
        return None
    from datetime import UTC

    return (v if v.tzinfo else v.replace(tzinfo=UTC)).isoformat()


def movement(session: Session, now_doc: dict[str, Any], *, days: int = 30) -> dict[str, Any] | None:
    """Why the score moved: today's computed posture against the oldest stored day in the window, per domain.

    A domain's contribution is its change weighted by its share of today's measured weight; the remainder is the
    change in the whole-score penalties (critical cases, critical tool-health findings) and in which domains are
    measured. Returns None until an earlier day with a score is stored."""
    from soc_platform.intelligence.models import PostureSnapshot

    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    today = utcnow().strftime("%Y-%m-%d")
    first = session.execute(select(PostureSnapshot).where(PostureSnapshot.day >= since, PostureSnapshot.day < today,
                                                          PostureSnapshot.score.is_not(None))
                            .order_by(PostureSnapshot.day)).scalars().first()
    if first is None or now_doc["score"] is None:
        return None
    before = (first.document or {}).get("domains") or {}
    W = now_doc["weights"]
    measured = [d for d in now_doc["domains"] if d["measured"] and W[d["id"]] > 0]
    total = sum(W[d["id"]] for d in measured) or 1
    rows, explained = [], 0.0
    for d in now_doc["domains"]:
        b, a = before.get(d["id"]), d["score"]
        if b is None and a is None:
            continue
        change = None if b is None or a is None else round(a - b, 1)
        contrib = None if change is None or not W[d["id"]] else round(change * W[d["id"]] / total, 1)
        explained += contrib or 0.0
        rows.append({"id": d["id"], "label": d["label"], "before": b, "after": a, "change": change,
                     "contribution": contrib,
                     "note": "newly measured" if b is None else "no longer measured" if a is None else None})
    change = round(now_doc["score"] - first.score, 1)
    rows.sort(key=lambda r: (-(abs(r["contribution"] or 0)), r["label"]))
    then_w = (first.document or {}).get("weights_version")
    return {"since": first.day, "from": first.score, "to": now_doc["score"], "change": change, "domains": rows,
            "other": round(change - explained, 1),
            "weights_changed": then_w != now_doc.get("weights_version") and "weights_version" in (first.document or {})}


def _dlp_week(session: Session) -> dict[str, Any]:
    from soc_platform.domains.dlp.models import DlpAlert

    newest = session.execute(select(func.max(DlpAlert.event_time))).scalar()
    if newest is None:
        return {"available": False}
    cut, prev = newest - timedelta(days=WINDOW_DAYS), newest - timedelta(days=2 * WINDOW_DAYS)

    def count(*where: Any) -> int:
        return session.execute(select(func.count()).select_from(DlpAlert).where(*where)).scalar() or 0

    this, last = count(DlpAlert.event_time > cut), count(DlpAlert.event_time > prev, DlpAlert.event_time <= cut)
    needs = count(DlpAlert.event_time > cut, DlpAlert.computed_outcome != "close_benign")
    by_type = dict(sorted(session.execute(select(DlpAlert.decision_type, func.count()).where(DlpAlert.event_time > cut)
                                          .group_by(DlpAlert.decision_type)).all()))
    return {"available": True, "as_of": _iso(newest), "days": WINDOW_DAYS, "alerts": this, "previous": last,
            "change": this - last, "personal_data": count(DlpAlert.event_time > cut, DlpAlert.personal_data.is_(True)),
            "needs_a_person": needs, "needs_a_person_percent": round(100 * needs / this, 1) if this else None,
            "by_channel": by_type}


def _people(session: Session) -> list[dict[str, Any]]:
    """People with the most escalated DLP alerts in the 30 days up to the newest alert: who to look at first."""
    from soc_platform.domains.dlp.models import DlpAlert

    newest = session.execute(select(func.max(DlpAlert.event_time))).scalar()
    if newest is None:
        return []
    rows = session.execute(select(DlpAlert.user_entity_id, DlpAlert.personal_data, DlpAlert.facts).where(
        DlpAlert.computed_outcome == "escalate", DlpAlert.user_entity_id.is_not(None),
        DlpAlert.event_time > newest - timedelta(days=PEOPLE_DAYS))).all()
    per: dict[str, Counter] = {}
    for uid, pd, facts in rows:
        c = per.setdefault(uid, Counter())
        c["escalated"] += 1
        c["personal_data"] += bool(pd)
        c["risky_sign_in"] |= ((facts or {}).get("identity_risk") or {}).get("level") in ("high", "critical")
        c["privileged"] |= bool(((facts or {}).get("user") or {}).get("privileged"))
    names = {e.id: e.display_name for e in session.execute(select(Entity).where(Entity.id.in_(sorted(per)))).scalars()}
    out = [{"entity_id": uid, "name": names.get(uid, uid), "escalated": c["escalated"], "personal_data": c["personal_data"],
            "risky_sign_in": bool(c["risky_sign_in"]), "privileged": bool(c["privileged"])} for uid, c in per.items()]
    return sorted(out, key=lambda r: (-r["escalated"], -r["personal_data"], r["name"]))[:5]


def _governance(session: Session, settings: Any, *, model_on: bool) -> dict[str, Any]:
    from soc_platform.core.access import kill_switch_on
    from soc_platform.core.audit import AuditLog
    from soc_platform.core.models import AuditRecord, LLMCall
    from soc_platform.core.policy import PolicyStore

    cp = AuditLog(session).checkpoint() or {}
    head = session.execute(select(func.max(AuditRecord.seq))).scalar()
    since = utcnow() - timedelta(days=30)
    calls = session.execute(select(func.count()).select_from(LLMCall).where(LLMCall.ts >= since)).scalar() or 0
    dropped = session.execute(select(func.coalesce(func.sum(LLMCall.claims_dropped), 0)).where(LLMCall.ts >= since)).scalar() or 0
    pending = session.execute(select(func.count()).select_from(ActionRequest).where(
        ActionRequest.status.in_(("recommended", "pending_approval")))).scalar() or 0
    return {"audit": {"events": head or 0, "verified": cp.get("ok"), "verified_up_to": cp.get("seq"),
                      "verified_at": cp.get("at")},
            "approvals_waiting": pending, "kill_switch": kill_switch_on(session, settings),
            "autonomy_policy_version": PolicyStore(session).active_version(),
            "model": "on" if model_on else "off", "model_calls_30d": calls, "model_statements_removed_30d": int(dropped)}


def ciso(session: Session, registry: Any, *, health_tools: list[str], settings: Any, model_on: bool) -> dict[str, Any]:
    from soc_platform.domains.dlp.service import DlpService
    from soc_platform.intelligence.config_snapshots import ConfigSnapshots
    from soc_platform.intelligence.control_coverage import coverage
    from soc_platform.intelligence.posture import posture, trend
    from soc_platform.intelligence.tool_health import tool_health

    p = posture(session)
    cov = coverage(session, limit=5)
    dlp = DlpService(session, registry)
    sm = dlp.summary()
    health = tool_health(session, health_tools)
    cfg = ConfigSnapshots(session, registry).overview()
    worst = sorted(session.execute(select(Case).where(Case.status != "closed", Case.severity.in_(("critical", "high"))))
                   .scalars(), key=lambda c: (-severity_rank(c.severity), c.created_at, c.id))
    from soc_platform.domains.dlp.models import DlpAlert

    reportable = session.execute(select(func.count()).select_from(DlpAlert).where(
        DlpAlert.personal_data.is_(True), DlpAlert.computed_outcome == "escalate")).scalar() or 0
    return {
        "as_of": _iso(utcnow()),
        "posture": {**p, "trend": trend(session), "movement": movement(session, p)},
        "coverage": {k: cov.get(k) for k in ("available", "reason", "coverage_percent", "fully_covered", "baseline",
                                             "controls", "not_measured", "devices_short", "devices_short_count")},
        "tool_health": health,
        "dlp": {**{k: sm[k] for k in ("alerts", "awaiting_a_person", "by_status", "by_computed", "personal_data_alerts",
                                      "ai_decided", "ai_and_computed_would_close", "open_cases", "noisy_rules",
                                      "computed_agreement_percent")},
                "model": "on" if model_on else "off", "week": _dlp_week(session), "people": _people(session)},
        "autonomy": {"decision_types": dlp.decisions.evaluate(),
                     "rule": "The AI may escalate alone and close only when the computed check agrees; "
                             "closing without a person is not switched on at any stage yet."},
        "changes": {"recent": cfg["changes"][:5], "unplanned_7d": cfg["unplanned_recent"],
                    "in_progress": [{"tool": t["tool"], **t["change_in_progress"]} for t in cfg["tools"] if t["change_in_progress"]],
                    "exporting_tools": sorted(t["tool"] for t in cfg["tools"] if t["exports_config"])},
        "cases": {"critical": sum(c.severity == "critical" for c in worst), "high": sum(c.severity == "high" for c in worst),
                  "items": [{"id": c.id, "domain": c.domain, "title": c.title, "severity": c.severity, "status": c.status,
                             "owner": c.assignee, "created_at": _iso(c.created_at)} for c in worst[:8]]},
        "regulatory": {"personal_data_escalations": reportable,
                       "note": "A person decides whether a personal-data incident is reportable (DPDP / CERT-In). "
                               "Regulatory evidence (Dome Comply) is not built yet."},
        "governance": _governance(session, settings, model_on=model_on),
    }


# ---------------------------------------------------------------------------------------------- the explanation
QUESTION = ("Explain to the CISO, in plain business language and at most six sentences, where the security posture "
            "stands, why the Dome Score moved, and what to do first. Use only the evidence.")


def evidence(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The computed figures the explanation may use, numbered P1, P2 ... (the model cites them; rules write them)."""
    p, out = doc["posture"], []

    def add(claim: str, weight: float) -> None:
        out.append({"id": f"P{len(out) + 1}", "claim": claim, "source": "posture", "weight": weight})

    if p["score"] is None:
        add("No domain can be measured yet: no tool and device baseline are connected.", 10)
        return out
    add(f"The Dome Score is {p['score']} out of 100 ({p['band']}), formula {p['formula_version']}, weights {p['weights_status']}.", 10)
    mv = p.get("movement")
    if mv:
        add(f"Since {mv['since']} the score moved by {mv['change']:+g} points, from {mv['from']} to {mv['to']}.", 9)
        for r in mv["domains"][:3]:
            if r["contribution"]:
                add(f"{r['label']} moved by {r['change']:+g} points, which moved the whole score by {r['contribution']:+g}.", 8)
    for d in p["domains"]:
        if not d["measured"]:
            add(f"{d['label']} is not measured: {d['reason']}", 2)
    for lv in p["levers"][:3]:
        add(f"Largest gain: {lv['action']} ({lv['domain']}) would raise the score by up to {lv['gain']:g} points.", 7)
    c = doc["cases"]
    if c["critical"] or c["high"]:
        add(f"{c['critical']} critical and {c['high']} high cases are open.", 6)
    h = doc["tool_health"]["counts"]
    if h["critical"] or h["warning"]:
        add(f"The tools themselves report {h['critical']} critical and {h['warning']} warning health finding(s).", 5)
    w = doc["dlp"]["week"]
    if w.get("available"):
        add(f"In the last {w['days']} days of data there were {w['alerts']} DLP alerts against {w['previous']} the week "
            f"before; {w['personal_data']} involved personal data.", 5)
    if doc["coverage"].get("available"):
        add(f"{doc['coverage']['devices_short_count']} of {doc['coverage']['baseline']['devices']} devices lack at "
            "least one expected control.", 6)
    return out


def explain(doc: dict[str, Any], gw: Any | None) -> dict[str, Any]:
    from soc_platform.llm.gateway import deterministic_grounded

    ev = evidence(doc)
    if gw is not None:
        out = gw.grounded("posture.explain", QUESTION, ev, tier="small")
        if out.get("source") != "deterministic" and out.get("claims"):
            return {**out, "evidence": ev}
    # by rule: the headline (score, and its change when known) as the summary, the rest as cited statements
    head = [e for e in ev if e["weight"] >= 9]
    rest = deterministic_grounded([e for e in ev if e["weight"] < 9], limit=6) if len(ev) > len(head) else {"claims": []}
    return {"summary": " ".join(e["claim"] for e in head), "claims": rest["claims"], "grounded": True,
            "insufficient_evidence": False, "evidence": ev, "source": "deterministic"}
