"""Posture score (Dome Score), version ``v1-draft``: one figure for the CISO, computed by a published formula.

DRAFT WEIGHTS. The weights and penalties below are a starting proposal; they are to be agreed with the CISO and will
then live in a versioned, two-person-approved document like the autonomy policy. Until then the API and the screen
label the score as a draft. Nothing here is written by a model: every figure can be recomputed from the factors
returned with it.

Domain scores (0-100, or "not measured" when no connected tool can tell):

* endpoint            share of the devices that should carry the EDR agent that do, and report
* data protection     mean of (DLP agent reporting, disk encryption) coverage
                      - 5 per critical and 2 per warning tool-health finding on a data-protection tool (at most 20)
                      - 3 per open DLP case (at most 15)
* identity            share of people in the directory without a high-risk sign-in in the 7 days up to the newest
                      sign-in event
* privileged access   not measured until a privileged-access tool is connected
* web                 not measured until a web-application-firewall tool is connected

Score = weighted mean of the measured domains (weights renormalised over what is measured)
        - 4 per open critical case (at most 20) - 2 per critical tool-health finding (at most 10), kept within 0-100.

A day's score is stored once a day (``snapshot``) so the change over a month can be shown.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from soc_platform.core import controls
from soc_platform.core.models import Case, Entity, utcnow
from soc_platform.intelligence.control_coverage import coverage
from soc_platform.intelligence.models import PostureSnapshot
from soc_platform.intelligence.tool_health import tool_health

FORMULA_VERSION = "v1-draft"
WEIGHTS = {"identity": 20, "privileged_access": 20, "endpoint": 20, "data_protection": 25, "web": 15}
LABELS = {"identity": "Identity", "privileged_access": "Privileged access", "endpoint": "Endpoint",
          "data_protection": "Data protection", "web": "Web (WAF)"}
DATA_PROTECTION_TOOLS = {"forcepoint_dlp", "trellix_epo"}
IDENTITY_WINDOW = timedelta(days=7)


def _clamp(v: float) -> float:
    return round(max(0.0, min(100.0, v)), 1)


def _factor(label: str, value: Any, effect: float | None = None, *, action: str | None = None,
            link: str | None = None) -> dict[str, Any]:
    """One input of the score. ``action`` / ``link``: what removes this reduction, and the screen where it is done."""
    out = {"label": label, "value": value, "effect": None if effect is None else round(effect, 1)}
    if action:
        out |= {"action": action, "link": link}
    return out


BANDS = ((85, "strong"), (70, "fair"), (50, "weak"), (0, "poor"))      # draft, like the weights


def band(score: float | None) -> str | None:
    return None if score is None else next(name for floor, name in BANDS if score >= floor)


def _identity(session: Session) -> dict[str, Any]:
    newest = session.execute(select(func.max(Entity.first_seen)).where(Entity.kind == "auth_risk")).scalar()
    people = [e for e in session.execute(select(Entity).where(Entity.kind == "identity")).scalars()
              if controls.BASELINE_TOOL in ((e.attributes or {}).get("by_tool") or {})]
    if newest is None or not people:
        return {"score": None, "measured": False, "factors": [],
                "reason": "No sign-in risk tool and directory are connected yet."}
    from soc_platform.core.context_store import ContextStore

    recent = [e for e in session.execute(select(Entity).where(Entity.kind == "auth_risk",
                                                             Entity.first_seen >= newest - IDENTITY_WINDOW)).scalars()
              if (e.attributes or {}).get("risk_level") in ("high", "critical")]
    ids = {p.id for p in people}
    store = ContextStore(session)
    risky = {ent.id for e in recent for _, ent in store.neighbors(e.id, kinds={"identity"}) if ent.id in ids}
    score = _clamp(100 * (1 - len(risky) / len(people)))
    return {"score": score, "measured": True, "reason": None,
            "factors": [_factor("People in the directory", len(people)),
                        _factor("People with a high-risk sign-in in the last 7 days of data", len(risky),
                                -100 * len(risky) / len(people),
                                action=f"Review the high-risk sign-ins of {len(risky)} person(s) and reset their sessions",
                                link="#/cases")]}


def posture(session: Session) -> dict[str, Any]:
    cov = coverage(session, limit=0)
    health = tool_health(session)
    by_control = {c["control"]: c for c in cov["controls"]}
    domains: dict[str, dict[str, Any]] = {}

    edr = by_control.get("edr")
    if edr and edr["covered_percent"] is not None:
        domains["endpoint"] = {"score": _clamp(edr["covered_percent"]), "measured": True, "reason": None, "factors": [
            _factor("Devices that should carry the EDR agent", edr["applicable"]),
            _factor("Devices without a reporting EDR agent", edr["short"], edr["covered_percent"] - 100,
                    action=f"Install or repair the EDR agent on {edr['short']} device(s)", link="#/controls")]}
    else:
        domains["endpoint"] = {"score": None, "measured": False, "factors": [],
                               "reason": "No endpoint tool and device baseline are connected yet."}

    dp = [by_control[c] for c in ("dlp_agent", "disk_encryption") if by_control.get(c, {}).get("covered_percent") is not None]
    if dp:
        base = sum(c["covered_percent"] for c in dp) / len(dp)
        mine = [f for f in health["findings"] if f["tool"] in DATA_PROTECTION_TOOLS]
        crit, warn = sum(f["severity"] == "critical" for f in mine), sum(f["severity"] == "warning" for f in mine)
        h_pen = min(20, 5 * crit + 2 * warn)
        cases = session.execute(select(func.count()).select_from(Case).where(
            Case.domain == "dlp", Case.status != "closed")).scalar() or 0
        c_pen = min(15, 3 * cases)
        # each control counts for its share of the mean, so the factors add up to the domain score
        domains["data_protection"] = {"score": _clamp(base - h_pen - c_pen), "measured": True, "reason": None, "factors": [
            *[_factor(f"{c['label']}: devices covered", f"{c['covered']} of {c['applicable']}",
                      (c["covered_percent"] - 100) / len(dp),
                      action=f"{c['label']}: fix {c['applicable'] - c['covered']} device(s)", link="#/controls")
              for c in dp],
            _factor("Tool-health findings on data-protection tools", f"{crit} critical, {warn} warning", -h_pen,
                    action="Clear the tool-health findings of the DLP and encryption tools", link="#/controls"),
            _factor("Open DLP cases", cases, -c_pen, action=f"Close or resolve {cases} open DLP case(s)", link="#/dlp")]}
    else:
        domains["data_protection"] = {"score": None, "measured": False, "factors": [],
                                      "reason": "No data-protection tool and device baseline are connected yet."}

    domains["identity"] = _identity(session)
    for d in ("privileged_access", "web"):
        domains[d] = {"score": None, "measured": False, "factors": [],
                      "reason": "No tool for this domain is connected yet."}

    measured = {d: v for d, v in domains.items() if v["measured"]}
    crit_cases = session.execute(select(func.count()).select_from(Case).where(
        Case.status != "closed", Case.severity == "critical")).scalar() or 0
    case_pen, health_pen = min(20, 4 * crit_cases), min(10, 2 * health["counts"]["critical"])
    score = None
    weighted = None
    if measured:
        total = sum(WEIGHTS[d] for d in measured)
        weighted = sum(WEIGHTS[d] * v["score"] for d, v in measured.items()) / total
        score = round(max(0.0, min(100.0, weighted - case_pen - health_pen)))
    ordered = [{"id": d, "label": LABELS[d], "weight": WEIGHTS[d], **domains[d]} for d in WEIGHTS]
    levers = _levers(ordered, measured, case_pen, health_pen, crit_cases, health["counts"]["critical"])
    movers = sorted((f | {"domain": LABELS[d["id"]]} for d in ordered for f in d["factors"] if (f["effect"] or 0) < 0),
                    key=lambda f: (f["effect"], f["label"]))
    return {"score": score, "band": band(score), "bands": [{"from": f, "band": b} for f, b in BANDS],
            "formula_version": FORMULA_VERSION,
            "weights_status": "draft - to be agreed with the CISO", "domains": ordered,
            "weighted_mean": None if weighted is None else round(weighted, 1),
            "penalties": [_factor("Open critical cases", crit_cases, -case_pen,
                                  action=f"Resolve {crit_cases} open critical case(s)", link="#/cases"),
                          _factor("Critical tool-health findings", health["counts"]["critical"], -health_pen,
                                  action="Fix the critical tool-health findings", link="#/controls")],
            "largest_reductions": movers[:6], "levers": levers, "measured_domains": sorted(measured),
            "coverage_percent": cov.get("coverage_percent")}


def _levers(ordered: list[dict[str, Any]], measured: dict[str, Any], case_pen: float, health_pen: float,
            crit_cases: int, crit_findings: int) -> list[dict[str, Any]]:
    """What would raise the score most: each reduction with the points the whole score would regain if it were
    removed (a domain factor counts by its domain's share of the measured weight). An upper bound - a domain score
    held at 0 or 100 regains less."""
    total = sum(WEIGHTS[d] for d in measured)
    out = []
    for d in ordered:
        if not d["measured"]:
            continue
        for f in d["factors"]:
            if (f["effect"] or 0) < 0 and f.get("action"):
                out.append({"domain": d["label"], "label": f["label"], "value": f["value"], "action": f["action"],
                            "link": f["link"], "gain": round(-f["effect"] * WEIGHTS[d["id"]] / total, 1)})
    for label, n, pen, action, link in (("Open critical cases", crit_cases, case_pen, f"Resolve {crit_cases} open critical case(s)", "#/cases"),
                                        ("Critical tool-health findings", crit_findings, health_pen, "Fix the critical tool-health findings", "#/controls")):
        if pen:
            out.append({"domain": "Whole score", "label": label, "value": n, "action": action, "link": link,
                        "gain": round(float(pen), 1)})
    return sorted(out, key=lambda x: (-x["gain"], x["label"]))


def snapshot(session: Session) -> dict[str, Any]:
    """Store today's score (one row per day; a second run the same day replaces it)."""
    doc = posture(session)
    day = utcnow().strftime("%Y-%m-%d")
    row = session.get(PostureSnapshot, day)
    slim = {"formula_version": doc["formula_version"],
            "domains": {d["id"]: d["score"] for d in doc["domains"]}, "coverage_percent": doc["coverage_percent"]}
    if row is None:
        session.add(PostureSnapshot(day=day, score=doc["score"], document=slim))
    else:
        row.score, row.document = doc["score"], slim
    session.flush()
    return {"day": day, "score": doc["score"]}


def trend(session: Session, *, days: int = 30) -> dict[str, Any]:
    """The stored daily scores and the change since the oldest one in the window (None until two days exist)."""
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    rows = session.execute(select(PostureSnapshot).where(PostureSnapshot.day >= since)
                           .order_by(PostureSnapshot.day)).scalars().all()
    points = [{"day": r.day, "score": r.score} for r in rows]
    scored = [p for p in points if p["score"] is not None]
    change = round(scored[-1]["score"] - scored[0]["score"], 1) if len(scored) >= 2 else None
    return {"days": days, "points": points, "change": change}
