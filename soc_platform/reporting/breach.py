"""Personal-data incidents (Dome Comply, M12): a breach assessment for every DLP case with personal data, a person's
reportability decision, the regulatory clocks that start from it, and a draft report the AI may write.

Who decides what (CLAUDE.md §0.4): whether an incident is reportable is decided by a **person** (a lead, in person,
with a reason) - never by the platform or the model. The clocks (``clocks`` of the catalogue in force) start at that
decision; a clock without hours shows "deadline not set". The draft is written from the structured facts of the case
(data classes, destination, tools that agree, times) - never from the message text an insider could write - by the
model when allowed (every sentence cited) or by rule. A person records each submission with its reference.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import Case, utcnow

STATUSES = ("open", "not_reportable", "reportable", "reported")


class BreachAssessment(Base):
    __tablename__ = "compliance_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(32), unique=True)
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    data_classes: Mapped[list[str]] = mapped_column(JSON, default=list)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    reason: Mapped[str] = mapped_column(BoundedText(2000), default="")
    clocks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)      # copied from the catalogue at the decision
    draft: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reports: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    revision: Mapped[int | None] = mapped_column(Integer, nullable=True)        # compare-and-swap for every change


def _aware(v: datetime | None) -> datetime | None:
    from datetime import UTC

    return None if v is None else (v if v.tzinfo else v.replace(tzinfo=UTC))


class BreachAssessments:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    def sync(self) -> int:
        """Open an assessment for every DLP case that carries personal data (idempotent)."""
        from soc_platform.domains.dlp.models import DlpAlert

        have = set(self.s.execute(select(BreachAssessment.case_id)).scalars())
        per: dict[str, list[DlpAlert]] = {}
        for a in self.s.execute(select(DlpAlert).where(DlpAlert.personal_data.is_(True), DlpAlert.case_id.is_not(None))
                                .order_by(DlpAlert.event_time, DlpAlert.id)).scalars():
            per.setdefault(a.case_id, []).append(a)
        n = 0
        for case_id, alerts in sorted(per.items()):
            row = self.s.execute(select(BreachAssessment).where(BreachAssessment.case_id == case_id)).scalars().first()
            classes = sorted({c for a in alerts for c in (a.facts or {}).get("data_classes") or []})
            ids = sorted(a.id for a in alerts)
            if case_id in have and row is not None:
                if row.alert_ids != ids or row.data_classes != classes:
                    row.alert_ids, row.data_classes = ids, classes
                continue
            self.s.add(BreachAssessment(case_id=case_id, data_classes=classes, alert_ids=ids, opened_at=utcnow()))
            self.s.flush()
            self.audit.append(actor_type="agent", actor_id="agent:comply", event_type="compliance.assessment_opened",
                              subject_type="case", subject_id=case_id, payload={"data_classes": classes})
            n += 1
        self.s.flush()
        return n

    def _swap(self, row: BreachAssessment, statuses: tuple[str, ...], **values: Any) -> bool:
        """Change ``row`` only if nobody changed it since it was read (its revision) and it is still in ``statuses``."""
        seen = row.revision
        cond = [BreachAssessment.id == row.id, BreachAssessment.status.in_(statuses),
                BreachAssessment.revision.is_(None) if seen is None else BreachAssessment.revision == seen]
        won = self.s.execute(update(BreachAssessment).where(*cond).values(revision=(seen or 0) + 1, **values)
                             .execution_options(synchronize_session=False)).rowcount == 1
        self.s.refresh(row)
        return won

    def _get(self, aid: int) -> BreachAssessment:
        row = self.s.get(BreachAssessment, aid)
        if row is None:
            raise KeyError("unknown assessment")
        return row

    @staticmethod
    def _may_decide(by: Principal) -> None:
        if by.is_service or not by.acting_in("dlp").can(Perm.APPROVE_HIGH_IMPACT):
            raise PermissionError("a lead decides, in person, whether a personal-data incident is reportable")

    def decide(self, aid: int, by: Principal, *, reportable: bool, reason: str) -> BreachAssessment:
        from soc_platform.reporting.regimes import CatalogueStore

        self._may_decide(by)
        row = self._get(aid)
        # once reportable, the decision stands: deciding again would restart the regulatory clocks
        if row.status not in ("open", "not_reportable"):
            raise ValueError(f"the assessment is already {row.status.replace('_', ' ')}; the decision and its deadlines stand")
        if not str(reason or "").strip():
            raise ValueError("say why")
        now = utcnow()
        clocks: list[dict[str, Any]] = []
        if reportable:
            catalogue, src = CatalogueStore(self.s).active()
            clocks = [{"id": c["id"], "regime": c["regime"], "label": c["label"], "hours": c.get("hours"),
                       "source": c.get("source"), "verified": bool(c.get("verified")),
                       "catalogue_version": src.get("version")} for c in catalogue.get("clocks", [])]
        # two leads deciding at the same moment: only one decision is made (the other is told it stands)
        if not self._swap(row, ("open", "not_reportable"), status="reportable" if reportable else "not_reportable",
                          decided_by=by.id, decided_at=now, reason=reason.strip()[:2000], clocks=clocks):
            raise ValueError(f"the assessment was decided by someone else at the same moment ({row.status.replace('_', ' ')})")
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="compliance.reportability_decided",
                          subject_type="case", subject_id=row.case_id,
                          payload={"reportable": reportable, "reason": row.reason,
                                   "clocks": [c["id"] for c in row.clocks]})
        return row

    def record_report(self, aid: int, by: Principal, *, clock: str, reference: str) -> BreachAssessment:
        self._may_decide(by)
        row = self._get(aid)
        if row.status not in ("reportable", "reported"):
            raise ValueError("only a reportable incident is reported")
        if clock not in {c["id"] for c in row.clocks}:
            raise ValueError("unknown deadline for this incident")
        if any(r["clock"] == clock for r in row.reports):
            raise ValueError("this report is already recorded")
        if not str(reference or "").strip():
            raise ValueError("enter the submission's reference")
        reports = [*row.reports, {"clock": clock, "reference": reference.strip()[:120], "by": by.id,
                                  "at": _aware(utcnow()).isoformat()}]
        done = {c["id"] for c in row.clocks} <= {r["clock"] for r in reports}
        if not self._swap(row, ("reportable", "reported"), reports=reports, status="reported" if done else row.status):
            raise ValueError("the assessment changed at the same moment; reload it and record the report again")
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="compliance.report_recorded",
                          subject_type="case", subject_id=row.case_id, payload={"clock": clock, "reference": reference[:120]})
        return row

    # ------------------------------------------------------------------ the draft

    def facts(self, row: BreachAssessment) -> list[dict[str, Any]]:
        """The structured facts a draft may state, numbered F1, F2 ... (no message text, no file names)."""
        from soc_platform.domains.dlp.models import DlpAlert

        case = self.s.get(Case, row.case_id)
        out: list[dict[str, Any]] = []

        def add(claim: str) -> None:
            out.append({"id": f"F{len(out) + 1}", "claim": claim, "source": "platform"})

        add(f"Case {row.case_id[:8]}: {case.title if case else 'data-protection case'}, severity {case.severity if case else 'unknown'}.")
        add(f"Personal data involved: {', '.join(row.data_classes) or 'not classified'}.")
        for a in self.s.execute(select(DlpAlert).where(DlpAlert.id.in_(row.alert_ids)).order_by(DlpAlert.event_time)).scalars():
            f = a.facts or {}
            add(f"At {_aware(a.event_time).isoformat()[:16].replace('T', ' ')} UTC the DLP tool reported data sent by "
                f"{(f.get('user') or {}).get('name') or 'an unidentified person'} over {f.get('channel') or 'an unknown channel'} "
                f"to a {str(f.get('destination_class') or 'unknown').replace('_', ' ')} destination"
                + (f" ({f.get('destination_domain')})" if f.get("destination_domain") else "")
                + f"; the tool's action: {f.get('action') or 'not reported'}; matches: {f.get('max_matches')}.")
        if row.decided_at:
            add(f"{row.decided_by} decided it reportable at {_aware(row.decided_at).isoformat()[:16].replace('T', ' ')} UTC.")
        return out

    def draft(self, aid: int, by: Principal, gw: Any | None) -> BreachAssessment:
        self._may_decide(by)
        row = self._get(aid)
        if row.status not in ("reportable", "reported"):
            raise ValueError("a report is drafted once a person decided the incident reportable")
        ev = self.facts(row)
        text, claims, source = None, [], "deterministic"
        if gw is not None:
            out = gw.grounded("compliance.draft", "Draft the incident report a regulator would receive: what happened, "
                              "when, which personal data, what was done. Plain, factual, no speculation. Use only the "
                              "evidence.", ev, tier="large")
            if out.get("source") != "deterministic" and out.get("claims"):
                text, claims, source = out["summary"], out["claims"], "llm"
        if text is None:
            text = " ".join(e["claim"] for e in ev)
            claims = [{"text": e["claim"], "kind": "fact", "evidence_ids": [e["id"]]} for e in ev]
        row.draft = {"text": text, "claims": claims, "evidence": ev, "source": source, "by": by.id,
                     "at": _aware(utcnow()).isoformat(),
                     "note": "A draft for a person to review and send; the platform sends nothing."}
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="compliance.report_drafted",
                          subject_type="case", subject_id=row.case_id, payload={"source": source})
        return row

    # ------------------------------------------------------------------ read

    def view(self, row: BreachAssessment) -> dict[str, Any]:
        now = _aware(utcnow())
        clocks = []
        for c in row.clocks:
            done = next((r for r in row.reports if r["clock"] == c["id"]), None)
            due = _aware(row.decided_at) + timedelta(hours=c["hours"]) if c.get("hours") and row.decided_at else None
            left = None if due is None or done else round((due - now).total_seconds() / 3600, 2)
            clocks.append({**c, "due": due.isoformat() if due else None, "hours_left": left, "reported": done,
                           "overdue": bool(due and not done and now > due)})
        case = self.s.get(Case, row.case_id)
        return {"id": row.id, "case_id": row.case_id, "case_title": case.title if case else None,
                "severity": case.severity if case else None, "opened_at": _aware(row.opened_at).isoformat(),
                "data_classes": row.data_classes, "alerts": len(row.alert_ids), "status": row.status,
                "decided_by": row.decided_by, "decided_at": _aware(row.decided_at).isoformat() if row.decided_at else None,
                "reason": row.reason, "clocks": clocks, "draft": row.draft, "reports": row.reports}

    def list(self) -> list[dict[str, Any]]:
        rows = self.s.execute(select(BreachAssessment).order_by(BreachAssessment.opened_at.desc(), BreachAssessment.id.desc())).scalars()
        return [self.view(r) for r in rows]
