"""Regulatory evidence (Dome Comply, M12): a control catalogue for SEBI CSCRF, DPDP and CERT-In, each control mapped to
evidence tests the platform computes, and the share of controls with current evidence.

Wording rules (CLAUDE.md §0.4 rule 5): the platform maps evidence and names gaps; it never says NAM "is compliant".
The catalogue is **data** - a versioned document NAM's compliance team validates and changes (proposed, then approved
by a second person) - not constants in code. The built-in catalogue is a DRAFT of control areas worded by us, to be
replaced by NAM's own control list; it quotes no clause. Regulatory facts (deadlines) appear only in its ``clocks``,
each with its source named and ``verified: false`` until NAM's compliance team confirms it against the source text.

A test answers ``pass``, ``fail`` or ``no_evidence`` (the platform cannot see it - say what would show it), with the
figures it used and when. A control is ``fail`` when any of its tests fails, ``pass`` when all pass, otherwise
``no_evidence``. "Current evidence" = a control whose tests all produced a result (pass or fail).
"""

from __future__ import annotations

import copy
import csv
import io
import json
import math
import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, func, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal, same_person
from soc_platform.core.db import Base, BoundedText, UTCDateTime, claim
from soc_platform.core.models import utcnow

DRAFT_NOTE = ("DRAFT control areas worded by the platform team, to be replaced or validated by NAM's compliance team. "
              "No clause is quoted; the mapping to evidence is a proposal.")

DRAFT_CATALOGUE: dict[str, Any] = {
    "title": "CyberDome regulatory evidence catalogue (draft)",
    "note": DRAFT_NOTE,
    "regimes": {
        "SEBI_CSCRF": {"name": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)",
                       "source": "SEBI CSCRF circular - the reference and the applicable clauses to be entered by NAM's compliance team"},
        "DPDP": {"name": "Digital Personal Data Protection Act, 2023 and its Rules",
                 "source": "DPDP Act 2023 and the DPDP Rules - the applicable provisions to be entered by NAM's compliance team"},
        "CERT_IN": {"name": "CERT-In Directions on information security practices",
                    "source": "CERT-In Directions under section 70B(6) of the IT Act, 2000, dated 28 April 2022"},
    },
    # Deadlines run from the moment a person decides an incident is reportable. hours: null = not set yet.
    "clocks": [
        {"id": "cert_in_report", "regime": "CERT_IN", "label": "Report the incident to CERT-In", "hours": 6,
         "source": "CERT-In Directions, 28 April 2022 (as stated in the CyberDome proposal)", "verified": False},
        {"id": "dpdp_board", "regime": "DPDP", "label": "Intimate the Data Protection Board and the people affected",
         "hours": None, "source": "DPDP Act 2023 and Rules - the time limit to be set by NAM's compliance team",
         "verified": False},
        {"id": "sebi_report", "regime": "SEBI_CSCRF", "label": "Report the incident to SEBI", "hours": None,
         "source": "SEBI CSCRF - the time limit to be set by NAM's compliance team", "verified": False},
    ],
    "log_retention_days": 180,
    "controls": [
        {"id": "DC-01", "regimes": ["SEBI_CSCRF"], "area": "Protect", "title": "Endpoint detection and response runs on every device in the baseline",
         "tests": ["edr_coverage"]},
        {"id": "DC-02", "regimes": ["SEBI_CSCRF", "DPDP"], "area": "Protect", "title": "Devices that handle personal data are encrypted",
         "tests": ["encryption_coverage"]},
        {"id": "DC-03", "regimes": ["SEBI_CSCRF", "DPDP"], "area": "Protect", "title": "Data-loss prevention watches every device",
         "tests": ["dlp_agent_coverage"]},
        {"id": "DC-04", "regimes": ["SEBI_CSCRF"], "area": "Detect", "title": "Security tools are healthy and reporting",
         "tests": ["tool_health_no_critical", "platform:no connector stale for more than 2 days"]},
        {"id": "DC-05", "regimes": ["SEBI_CSCRF", "CERT_IN"], "area": "Detect", "title": "Logs are kept for the required period",
         "tests": ["log_retention"]},
        {"id": "DC-06", "regimes": ["SEBI_CSCRF"], "area": "Protect", "title": "Privileged access requires multi-factor authentication",
         "tests": ["mfa_privileged", "platform:step-up MFA enforced for approvals"]},
        {"id": "DC-07", "regimes": ["SEBI_CSCRF"], "area": "Identify", "title": "Changes to security tools are recorded and approved",
         "tests": ["changes_recorded", "platform:no policy version approved by its proposer"]},
        {"id": "DC-08", "regimes": ["SEBI_CSCRF", "CERT_IN"], "area": "Respond", "title": "Escalated data-loss alerts are triaged promptly",
         "tests": ["dlp_triage_timely"]},
        {"id": "DC-09", "regimes": ["DPDP", "CERT_IN"], "area": "Respond", "title": "Every personal-data incident gets a reportability decision by a person",
         "tests": ["breach_assessed", "reports_on_time"]},
        {"id": "DC-10", "regimes": ["SEBI_CSCRF"], "area": "Govern", "title": "Security actions are approved, high-impact ones by two people",
         "tests": ["platform:four-eyes actions approved by two different people", "platform:no destructive action executed without approval"]},
        {"id": "DC-11", "regimes": ["SEBI_CSCRF", "CERT_IN"], "area": "Govern", "title": "An append-only, verified audit trail of security operations",
         "tests": ["audit_chain_verified"]},
        {"id": "DC-12", "regimes": ["DPDP"], "area": "Protect", "title": "Personal data is pseudonymised before any AI model sees it",
         "tests": ["platform:PII redaction before model calls enabled", "platform:model calls only to approved endpoints"]},
    ],
}
STATUSES = ("pass", "fail", "no_evidence")


class ComplianceCatalogue(Base):
    __tablename__ = "compliance_catalogues"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(16), index=True)        # proposed | active | superseded | rejected | withdrawn
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(BoundedText(2000), default="")
    proposed_by: Mapped[str] = mapped_column(String(256))
    proposed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")


def _aware(v: datetime | None) -> datetime | None:
    from datetime import UTC

    return None if v is None else (v if v.tzinfo else v.replace(tzinfo=UTC))


# ---------------------------------------------------------------------------------------------- the catalogue


_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_MAX_TEXT = 4000


def _bounded(v: Any, depth: int = 0) -> None:
    """Every text in the catalogue is bounded and the nesting shallow: it is stored, audited, shown and packed."""
    if depth > 6:
        raise ValueError("the catalogue is nested too deeply")
    if isinstance(v, str):
        if len(v) > _MAX_TEXT:
            raise ValueError(f"a text in the catalogue is longer than {_MAX_TEXT} characters")
    elif isinstance(v, dict):
        for k, x in v.items():
            if len(str(k)) > 64:
                raise ValueError("a key in the catalogue is longer than 64 characters")
            _bounded(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _bounded(x, depth + 1)
    elif isinstance(v, float) and not math.isfinite(v):
        raise ValueError("numbers in the catalogue must be finite")


def check_catalogue(doc: Any) -> dict[str, Any]:
    """A catalogue must name its regimes, its controls (unique ids, known regimes, known tests) and its clocks."""
    if not isinstance(doc, dict):
        raise ValueError("the catalogue must be an object")  # noqa: TRY004 - a malformed document is a bad request (400), like every other refusal here
    regimes, controls, clocks = doc.get("regimes"), doc.get("controls"), doc.get("clocks", [])
    if not isinstance(regimes, dict) or not regimes:
        raise ValueError("the catalogue needs its regimes")
    if any(not isinstance(r, str) or not _ID.fullmatch(r) for r in regimes):
        raise ValueError("a regime id is 1-64 letters, digits, '.', '_', ':' or '-'")
    if not isinstance(controls, list) or not controls or len(controls) > 500:
        raise ValueError("the catalogue needs 1 to 500 controls")
    if not isinstance(clocks, list):
        raise ValueError("clocks must be a list")  # noqa: TRY004 - a malformed document is a bad request (400), like every other refusal here
    _bounded(doc)
    seen: set[str] = set()
    for c in controls:
        if not isinstance(c, dict) or not str(c.get("id") or "").strip() or not str(c.get("title") or "").strip():
            raise ValueError("every control needs an id and a title")
        if not isinstance(c["id"], str) or not _ID.fullmatch(c["id"]):
            raise ValueError("a control id is 1-64 letters, digits, '.', '_', ':' or '-'")
        if not isinstance(c["title"], str) or len(c["title"]) > 300:
            raise ValueError(f"control {c['id']}: the title is text of at most 300 characters")
        if c["id"] in seen:
            raise ValueError(f"control {c['id']} appears twice")
        seen.add(c["id"])
        if not isinstance(c.get("regimes"), list) or set(c["regimes"]) - set(regimes):
            raise ValueError(f"control {c['id']} names a regime the catalogue does not define")
        tests = c.get("tests")
        if not isinstance(tests, list) or any(not isinstance(t, str) for t in tests):
            raise ValueError(f"control {c['id']} needs a list of tests")
        bad = [t for t in tests if t not in TESTS and not t.startswith("platform:")]
        if bad:
            raise ValueError(f"control {c['id']} names unknown test(s): {', '.join(bad)}")
    for k in clocks:
        if not isinstance(k, dict) or not k.get("id") or k.get("regime") not in regimes or not k.get("source"):
            raise ValueError("every clock needs an id, a known regime and its source")
        if not isinstance(k["id"], str) or not _ID.fullmatch(k["id"]):
            raise ValueError("a clock id is 1-64 letters, digits, '.', '_', ':' or '-'")
        h = k.get("hours")
        if h is not None and (isinstance(h, bool) or not isinstance(h, int | float) or not 0 < h <= 24 * 30):
            raise ValueError(f"clock {k['id']}: hours must be a positive number of hours, or null when not set")
    days = doc.get("log_retention_days")
    if days is not None and (isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650):
        raise ValueError("log_retention_days must be a whole number of days")
    if len(json.dumps(doc)) > 400_000:
        raise ValueError("the catalogue is too large")
    return copy.deepcopy(doc)


class CatalogueStore:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    def _active(self) -> ComplianceCatalogue | None:
        return self.s.execute(select(ComplianceCatalogue).where(ComplianceCatalogue.status == "active")
                              .order_by(ComplianceCatalogue.id.desc())).scalars().first()

    def active(self) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self._active()
        if row is None:
            return copy.deepcopy(DRAFT_CATALOGUE), {"version": None, "status": "draft - to be validated by NAM's compliance team"}
        return copy.deepcopy(row.document), {"version": row.id, "status": f"validated - version {row.id}",
                                             "approved_by": row.decided_by,
                                             "approved_at": _aware(row.decided_at).isoformat() if row.decided_at else None}

    def pending(self) -> ComplianceCatalogue | None:
        return self.s.execute(select(ComplianceCatalogue).where(ComplianceCatalogue.status == "proposed")
                              .order_by(ComplianceCatalogue.id.desc())).scalars().first()

    def propose(self, by: Principal, doc: Any, reason: str) -> ComplianceCatalogue:
        if by.is_service or not by.can(Perm.EXPORT_EVIDENCE) or not by.can(Perm.APPROVE_POLICY):
            raise PermissionError("a lead proposes the control catalogue")
        if not str(reason or "").strip():
            raise ValueError("say what the new catalogue changes")
        if self.pending() is not None:
            raise ValueError("a catalogue is already waiting for approval")
        row = ComplianceCatalogue(status="proposed", document=check_catalogue(doc), reason=reason.strip()[:2000],
                                  proposed_by=by.id, proposed_at=utcnow())
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="compliance.catalogue_proposed",
                          subject_type="compliance_catalogue", subject_id=str(row.id),
                          payload={"controls": len(row.document["controls"]), "reason": row.reason})
        return row

    def decide(self, cid: int, by: Principal, *, approve: bool, note: str = "") -> ComplianceCatalogue:
        row = self.s.get(ComplianceCatalogue, cid)
        if row is None:
            raise KeyError("unknown catalogue version")
        if row.status != "proposed":
            raise ValueError(f"version {row.id} is {row.status}, not waiting for approval")
        own = same_person(by.id, row.proposed_by)
        if approve:
            if by.is_service or not by.can(Perm.APPROVE_POLICY):
                raise PermissionError("a lead approves the control catalogue")
            if own:
                raise PermissionError("a second person approves: the proposer cannot approve their own catalogue")
            new = "active"
        else:
            if by.is_service or not (own or by.can(Perm.APPROVE_POLICY)):
                raise PermissionError("a lead rejects; the proposer may withdraw")
            if not own and not str(note or "").strip():
                raise ValueError("say why the catalogue is rejected")
            new = "withdrawn" if own else "rejected"
        if not claim(self.s, row, ("proposed",), status=new, decided_by=by.id, decided_at=utcnow(),
                     note=str(note or "")[:2000]):
            raise ValueError(f"version {row.id} was decided by someone else at the same moment ({row.status})")
        if new == "active":
            self.s.execute(update(ComplianceCatalogue).where(ComplianceCatalogue.status == "active",
                                                             ComplianceCatalogue.id != row.id)
                           .values(status="superseded").execution_options(synchronize_session=False))
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type=f"compliance.catalogue_{row.status}",
                          subject_type="compliance_catalogue", subject_id=str(row.id), payload={"note": row.note})
        return row


# ---------------------------------------------------------------------------------------------- evidence tests


def _r(status: str, detail: str, evidence: Any = None) -> dict[str, Any]:
    assert status in STATUSES
    return {"status": status, "detail": detail, "evidence": evidence, "as_of": _aware(utcnow()).isoformat()}


def _coverage_test(control: str):
    def test(ctx: dict[str, Any]) -> dict[str, Any]:
        cov = ctx["coverage"]
        if not cov.get("available"):
            return _r("no_evidence", cov.get("reason") or "no device baseline is connected")
        c = next((x for x in cov["controls"] if x["control"] == control), None)
        if c is None or c["covered_percent"] is None:
            return _r("no_evidence", "the tool for this control is not connected")
        short = c["applicable"] - c["covered"]
        return _r("pass" if short == 0 else "fail",
                  f"{c['covered']} of {c['applicable']} devices ({c['covered_percent']}%)" + (f"; {short} short" if short else ""),
                  {"covered": c["covered"], "applicable": c["applicable"]})
    return test


def t_tool_health(ctx: dict[str, Any]) -> dict[str, Any]:
    h = ctx["health"]
    if not h["tools"]:
        return _r("no_evidence", "no tool reports its health")
    crit = [f for f in h["findings"] if f["severity"] == "critical"]
    return _r("fail" if crit else "pass", f"{len(crit)} critical finding(s) on {len(h['tools'])} tool(s)",
              [{"tool": f["tool"], "title": f["title"]} for f in crit])


def t_log_retention(ctx: dict[str, Any]) -> dict[str, Any]:
    need = int(ctx["catalogue"].get("log_retention_days") or 180)
    platform = ctx["settings"].event_retention_days if hasattr(ctx["settings"], "event_retention_days") else None
    import os

    platform = platform or int(os.environ.get("SOC_EVENT_RETENTION_DAYS", "400"))
    reported = {t: d for t, d in ctx["tool_retention"].items() if d is not None}
    unknown = sorted(t for t in ctx["tools"] if t not in reported)
    short = sorted(t for t, d in reported.items() if d < need)
    detail = f"the platform keeps events {platform} days (needs {need})"
    if platform < need or short:
        return _r("fail", detail + (f"; under {need} days: {', '.join(short)}" if short else ""),
                  {"platform_days": platform, "tools": reported})
    if unknown:
        return _r("no_evidence", detail + f"; the tools' own retention is not reported: {', '.join(unknown)} - "
                  "export it with their configuration or attach the setting to the audit pack",
                  {"platform_days": platform, "tools": reported, "not_reported": unknown})
    return _r("pass", detail + "; every tool reports enough", {"platform_days": platform, "tools": reported})


def t_mfa_privileged(ctx: dict[str, Any]) -> dict[str, Any]:
    items = ctx["config"].get("silverfort")
    if items is None:
        return _r("no_evidence", "no configuration snapshot of the identity-protection tool yet")
    rules = [i for i in items if i.get("enabled") and str(i.get("action") or "").lower() == "mfa"
             and any(w in str(i.get("applies_to") or "").lower() for w in ("admin", "privileged"))]
    return _r("pass" if rules else "fail", f"{len(rules)} enabled MFA policy(ies) for privileged accounts in the newest snapshot",
              [i.get("name") for i in rules])


def t_changes_recorded(ctx: dict[str, Any]) -> dict[str, Any]:
    if not ctx["exporting"]:
        return _r("no_evidence", "no tool exports its configuration")
    n = ctx["unplanned_30d"]
    return _r("fail" if n else "pass", f"{n} unplanned configuration change(s) in 30 days on "
              f"{len(ctx['exporting'])} tool(s) that export their configuration")


def t_dlp_triage(ctx: dict[str, Any]) -> dict[str, Any]:
    from soc_platform.domains.dlp.models import DlpAlert

    s = ctx["session"]
    total = s.execute(select(func.count()).select_from(DlpAlert).where(DlpAlert.computed_outcome == "escalate")).scalar() or 0
    if not total:
        return _r("no_evidence", "no escalated DLP alert yet")
    limit = _aware(utcnow()) - timedelta(hours=24)
    late = s.execute(select(func.count()).select_from(DlpAlert).where(
        DlpAlert.computed_outcome == "escalate", DlpAlert.analyst_outcome.is_(None), DlpAlert.created_at < limit)).scalar() or 0
    return _r("fail" if late else "pass", f"{late} of {total} escalated alert(s) waited more than 24 h for a person")


def t_breach_assessed(ctx: dict[str, Any]) -> dict[str, Any]:
    rows = ctx["assessments"]
    if not rows:
        return _r("no_evidence", "no personal-data incident yet")
    limit = _aware(utcnow()) - timedelta(hours=24)
    late = [a for a in rows if a["status"] == "open" and _aware(datetime.fromisoformat(a["opened_at"])) < limit]
    return _r("fail" if late else "pass", f"{len(rows)} personal-data incident(s); {len(late)} undecided for more than 24 h",
              [a["case_id"] for a in late])


def t_reports_on_time(ctx: dict[str, Any]) -> dict[str, Any]:
    rows = [a for a in ctx["assessments"] if a["status"] in ("reportable", "reported")]
    if not rows:
        return _r("no_evidence", "no incident has been decided reportable")
    over = [a["case_id"] for a in rows for c in a["clocks"] if c.get("overdue")]
    unset = sorted({c["id"] for a in rows for c in a["clocks"] if c.get("hours") is None})
    if over:
        return _r("fail", f"{len(over)} report(s) overdue", over)
    if unset:
        return _r("no_evidence", f"no deadline set for: {', '.join(unset)} (set it in the catalogue)")
    return _r("pass", f"{len(rows)} reportable incident(s), no report overdue")


def t_audit_chain(ctx: dict[str, Any]) -> dict[str, Any]:
    cp = ctx["checkpoint"] or {}
    if cp.get("ok") is None:
        return _r("no_evidence", "the audit chain has not been verified yet (the hourly self-check verifies it)")
    at = _aware(datetime.fromisoformat(cp["at"])) if cp.get("at") else None
    if not cp["ok"]:
        return _r("fail", f"the chain failed verification at event {cp.get('first_bad_seq')}")
    if at is None or at < _aware(utcnow()) - timedelta(hours=26):
        return _r("no_evidence", "the last verification is older than a day")
    return _r("pass", f"verified up to event {cp.get('seq')} at {at.isoformat()[:16]}")


TESTS = {
    "edr_coverage": ("EDR agent on every baseline device", _coverage_test("edr")),
    "dlp_agent_coverage": ("DLP agent reporting on every device", _coverage_test("dlp_agent")),
    "encryption_coverage": ("Disk encryption on every workstation", _coverage_test("disk_encryption")),
    "tool_health_no_critical": ("No critical tool-health finding", t_tool_health),
    "log_retention": ("Logs kept for the required days", t_log_retention),
    "mfa_privileged": ("MFA policy for privileged accounts", t_mfa_privileged),
    "changes_recorded": ("No unplanned configuration change in 30 days", t_changes_recorded),
    "dlp_triage_timely": ("Escalated DLP alerts ruled on within 24 h", t_dlp_triage),
    "breach_assessed": ("Personal-data incidents decided within 24 h", t_breach_assessed),
    "reports_on_time": ("Reportable incidents reported within their deadline", t_reports_on_time),
    "audit_chain_verified": ("Audit chain verified in the last day", t_audit_chain),
}


def _context(s: Session, registry: Any, settings: Any, catalogue: dict[str, Any]) -> dict[str, Any]:
    from soc_platform.intelligence.config_snapshots import ConfigSnapshot, ConfigSnapshots
    from soc_platform.intelligence.control_coverage import coverage
    from soc_platform.intelligence.tool_health import tool_health
    from soc_platform.reporting.breach import BreachAssessments

    cfg = ConfigSnapshots(s, registry)
    newest: dict[str, list[dict[str, Any]]] = {}
    for snap in s.execute(select(ConfigSnapshot).order_by(ConfigSnapshot.id)).scalars():
        newest[snap.tool] = snap.items
    retention = {t: next((i.get("log_retention_days") for i in items if isinstance(i.get("log_retention_days"), int)), None)
                 for t, items in newest.items()}
    tools = sorted(n for n in registry.enabled_names()) if registry is not None else []
    ov = cfg.overview()
    return {"session": s, "settings": settings, "catalogue": catalogue, "coverage": coverage(s, limit=0),
            "health": tool_health(s), "config": newest, "tool_retention": retention,
            "tools": [t for t in tools if t not in ("generic_siem", "jira", "servicenow", "cmdb_csv")],
            "exporting": [t["tool"] for t in ov["tools"] if t["exports_config"]],
            "unplanned_30d": len([c for c in cfg.changes(limit=500) if c["planned"] is False
                                  and _aware(datetime.fromisoformat(c["at"])) >= _aware(utcnow()) - timedelta(days=30)]),
            "assessments": BreachAssessments(s).list(), "checkpoint": AuditLog(s).checkpoint()}


def evaluate(s: Session, registry: Any, settings: Any) -> dict[str, Any]:
    """Every control of the catalogue in force with its tests' results; the share with current evidence."""
    from soc_platform.reporting.compliance import build_evidence

    catalogue, source = CatalogueStore(s).active()
    ctx = _context(s, registry, settings, catalogue)
    platform: dict[str, dict[str, Any]] | None = None
    results: dict[str, dict[str, Any]] = {}
    for c in catalogue["controls"]:
        for t in c["tests"]:
            if t in results:
                continue
            if t.startswith("platform:"):
                if platform is None:
                    platform = {x["test"]: x for ctl in build_evidence(s, settings, period_days=90)["controls"] for x in ctl["tests"]}
                p = platform.get(t[len("platform:"):])
                results[t] = (_r("no_evidence", "the platform keeps no such test") if p is None else
                              _r(p["result"], str(p["detail"]), p.get("evidence")))
                results[t]["label"] = t[len("platform:"):].capitalize()
            else:
                label, fn = TESTS[t]
                try:
                    results[t] = {**fn(ctx), "label": label}
                except Exception as exc:
                    import logging

                    logging.getLogger(__name__).warning("compliance test %s failed", t, exc_info=True)
                    results[t] = {**_r("no_evidence", f"the test could not run: {type(exc).__name__}"), "label": label}
    controls = []
    for c in catalogue["controls"]:
        rs = [{"id": t, **results[t]} for t in c["tests"]]
        st = "fail" if any(r["status"] == "fail" for r in rs) else "pass" if rs and all(r["status"] == "pass" for r in rs) \
            else "no_evidence"
        controls.append({**{k: c.get(k) for k in ("id", "title", "area", "regimes")}, "status": st, "tests": rs,
                         "current_evidence": bool(rs) and all(r["status"] != "no_evidence" for r in rs)})
    by_regime = {}
    for rid, reg in catalogue["regimes"].items():
        mine = [c for c in controls if rid in (c["regimes"] or [])]
        by_regime[rid] = {"name": reg.get("name"), "source": reg.get("source"), "controls": len(mine),
                          "with_evidence": sum(c["current_evidence"] for c in mine),
                          "passing": sum(c["status"] == "pass" for c in mine),
                          "failing": sum(c["status"] == "fail" for c in mine)}
    n = len(controls)
    ev = sum(c["current_evidence"] for c in controls)
    return {"as_of": _aware(utcnow()).isoformat(), "catalogue": {"title": catalogue.get("title"), "note": catalogue.get("note"),
                                                                 **source},
            "summary": {"controls": n, "with_evidence": ev, "evidence_percent": round(100 * ev / n, 1) if n else None,
                        "passing": sum(c["status"] == "pass" for c in controls),
                        "failing": sum(c["status"] == "fail" for c in controls),
                        "no_evidence": [c["id"] for c in controls if c["status"] == "no_evidence"]},
            "regimes": by_regime, "controls": controls, "clocks": catalogue.get("clocks", []),
            "wording": "The platform maps evidence to controls and names the gaps; it does not state compliance."}


def pack(s: Session, registry: Any, settings: Any, out_dir: str) -> tuple[str, dict[str, Any]]:
    """The audit pack: the controls with their evidence, the personal-data assessments, the catalogue in force, the
    platform's own evidence pack and the full audit trail - one zip, stored like every generated file."""
    import zipfile
    from pathlib import Path

    from docx import Document

    from soc_platform.core.blobstore import BlobStore
    from soc_platform.core.retention import export_audit
    from soc_platform.reporting.breach import BreachAssessments

    ev = evaluate(s, registry, settings)
    catalogue, _ = CatalogueStore(s).active()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["control", "title", "regimes", "status", "test", "test status", "detail", "as of"])
    for c in ev["controls"]:
        for t in c["tests"]:
            w.writerow([c["id"], c["title"], " ".join(c["regimes"] or []), c["status"], t["label"], t["status"],
                        _guard(t["detail"]), t["as_of"]])
    doc = Document()
    doc.add_heading("CyberDome audit pack", 0)
    sm = ev["summary"]
    doc.add_paragraph(f"Generated {ev['as_of'][:16]} UTC. {sm['with_evidence']} of {sm['controls']} controls have current "
                      f"evidence; {sm['passing']} pass, {sm['failing']} fail. {ev['wording']}")
    doc.add_paragraph(f"Catalogue: {ev['catalogue']['title']} ({ev['catalogue']['status']}). {ev['catalogue'].get('note') or ''}")
    for c in ev["controls"]:
        doc.add_heading(f"{c['id']} {c['title']}", level=2)
        doc.add_paragraph(f"Regimes: {', '.join(c['regimes'] or [])}. Status: {c['status'].replace('_', ' ')}.")
        for t in c["tests"]:
            doc.add_paragraph(f"{t['label']}: {t['status'].replace('_', ' ')} - {t['detail']}", style="List Bullet")
    tmp = out / f".audit-pack-{stamp}.docx"
    doc.save(tmp)
    path = out / f"cyberdome_audit_pack_{stamp}.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("controls.json", json.dumps(ev, indent=1, default=str))
        z.writestr("controls.csv", buf.getvalue())
        z.writestr("assessments.json", json.dumps(BreachAssessments(s).list(), indent=1, default=str))
        z.writestr("catalogue.json", json.dumps(catalogue, indent=1))
        z.writestr("audit_log.jsonl", "".join(export_audit(s)))
        z.write(tmp, "summary.docx")
    tmp.unlink(missing_ok=True)
    ref = BlobStore(s, settings).store_generated(path, f"reports/{path.name}")
    return ref, ev


def _guard(v: Any) -> str:
    """A CSV cell that a spreadsheet would read as a formula is prefixed so it stays text."""
    t = str(v or "")
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t
