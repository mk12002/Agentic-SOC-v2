"""The Dome Score's weights as a governed document: adjustable, versioned, previewed, approved by a second person.

What can be set:

* ``weights``    the weight of each of the five domains (identity, privileged access, endpoint, data protection, web),
                 whole numbers 0-100; only measured domains count, and their weights are renormalised (a domain of
                 weight 0 is left out of the score)
* ``penalties``  points taken off: per open critical case and per critical tool-health finding (whole score); per open
                 DLP case and per critical / warning health finding of a data-protection tool (data-protection
                 domain) - each with its cap

A lead (or an automation admin) proposes a change with a reason, sees the score it would give now, and a *different*
lead approves it (``approve_policy``, in person). Until an approved version exists the built-in draft applies and the
screens say "draft - to be agreed with the CISO". Every step is audited; the daily score records the version it used,
so "why the score moved" tells a change of weights from a change in the estate.
"""

from __future__ import annotations

import copy
import math
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal, same_person
from soc_platform.core.db import Base, BoundedText, UTCDateTime, claim
from soc_platform.core.models import utcnow

DOMAINS = ("identity", "privileged_access", "endpoint", "data_protection", "web")
DEFAULT: dict[str, Any] = {
    "weights": {"identity": 20, "privileged_access": 20, "endpoint": 20, "data_protection": 25, "web": 15},
    "penalties": {
        "critical_case": {"points": 4, "cap": 20},          # whole score, per open critical case
        "critical_health": {"points": 2, "cap": 10},        # whole score, per critical tool-health finding
        "dlp_case": {"points": 3, "cap": 15},               # data protection, per open DLP case
        "dp_health_critical": {"points": 5, "cap": 20},     # data protection, per critical health finding of its tools
        "dp_health_warning": {"points": 2, "cap": 20},      # ... per warning (shares the cap above)
    },
}
PENALTY_LABELS = {"critical_case": "Open critical case (whole score)",
                  "critical_health": "Critical tool-health finding (whole score)",
                  "dlp_case": "Open DLP case (data protection)",
                  "dp_health_critical": "Critical health finding of a DLP / encryption tool (data protection)",
                  "dp_health_warning": "Warning health finding of a DLP / encryption tool (data protection)"}


class PostureWeights(Base):
    __tablename__ = "posture_weights"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(16), index=True)        # proposed | active | superseded | rejected | withdrawn
    document: Mapped[dict[str, Any]] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(BoundedText(2000), default="")
    proposed_by: Mapped[str] = mapped_column(String(256))
    proposed_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")
    preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


def _int(v: Any, lo: int, hi: int, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v) or v != int(v):
        raise ValueError(f"{what} must be a whole number")
    if not lo <= int(v) <= hi:
        raise ValueError(f"{what} must be between {lo} and {hi}")
    return int(v)


def clean(doc: Any) -> dict[str, Any]:
    """A complete, checked document: missing parts take the draft's values; anything else is refused."""
    if not isinstance(doc, dict):
        raise ValueError("the weights document must be an object")  # noqa: TRY004 - a malformed document is a bad request (400), like every other refusal here
    unknown = set(doc) - {"weights", "penalties"}
    if unknown:
        raise ValueError(f"unknown part(s): {', '.join(sorted(unknown))}")
    w_in = doc.get("weights") if doc.get("weights") is not None else {}
    p_in = doc.get("penalties") if doc.get("penalties") is not None else {}
    if not isinstance(w_in, dict) or not isinstance(p_in, dict):
        raise ValueError("weights and penalties must be objects")  # noqa: TRY004 - a malformed document is a bad request (400), like every other refusal here
    if set(w_in) - set(DOMAINS):
        raise ValueError(f"unknown domain(s): {', '.join(sorted(set(w_in) - set(DOMAINS)))}")
    if set(p_in) - set(DEFAULT["penalties"]):
        raise ValueError(f"unknown penalty: {', '.join(sorted(set(p_in) - set(DEFAULT['penalties'])))}")
    out = copy.deepcopy(DEFAULT)
    for d, v in w_in.items():
        out["weights"][d] = _int(v, 0, 100, f"the weight of {d}")
    if not any(out["weights"].values()):
        raise ValueError("at least one domain needs a weight above 0")
    for k, v in p_in.items():
        if not isinstance(v, dict) or set(v) - {"points", "cap"}:
            raise ValueError(f"{k} takes points and cap")
        if "points" in v:
            out["penalties"][k]["points"] = _int(v["points"], 0, 25, f"{k} points")
        if "cap" in v:
            out["penalties"][k]["cap"] = _int(v["cap"], 0, 50, f"{k} cap")
    return out


class WeightsStore:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    def _active_row(self) -> PostureWeights | None:
        return self.s.execute(select(PostureWeights).where(PostureWeights.status == "active")
                              .order_by(PostureWeights.id.desc())).scalars().first()

    def active(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """The document in force and where it comes from (an approved version, or the built-in draft)."""
        row = self._active_row()
        if row is None:
            return copy.deepcopy(DEFAULT), {"version": None, "status": "draft - to be agreed with the CISO",
                                            "approved_by": None, "approved_at": None}
        return clean(row.document), {"version": row.id, "status": f"agreed - version {row.id}",
                                     "approved_by": row.decided_by, "approved_at": row.decided_at.isoformat()
                                     if row.decided_at else None}

    def pending(self) -> PostureWeights | None:
        return self.s.execute(select(PostureWeights).where(PostureWeights.status == "proposed")
                              .order_by(PostureWeights.id.desc())).scalars().first()

    def preview(self, doc: Any) -> dict[str, Any]:
        """The score now under the current and the proposed weights (nothing stored)."""
        from soc_platform.intelligence.posture import posture

        new = clean(doc)
        cur, prop = posture(self.s), posture(self.s, config=new)
        return {"current": {"score": cur["score"], "domains": {d["id"]: d["score"] for d in cur["domains"]}},
                "proposed": {"score": prop["score"], "domains": {d["id"]: d["score"] for d in prop["domains"]}},
                "change": None if cur["score"] is None or prop["score"] is None else prop["score"] - cur["score"],
                "document": new}

    def propose(self, by: Principal, doc: Any, reason: str) -> PostureWeights:
        if by.is_service or not (by.can(Perm.APPROVE_POLICY) or by.can(Perm.PROPOSE_POLICY)) or not by.in_domain("*"):
            raise PermissionError("a lead or automation admin with all-domain scope proposes the Dome Score weights")
        if not str(reason or "").strip():
            raise ValueError("say why the weights should change")
        if self.pending() is not None:
            raise ValueError("a change of weights is already waiting for approval")
        pv = self.preview(doc)
        if pv["document"] == self.active()[0]:
            raise ValueError("the proposed weights are the ones in force")
        row = PostureWeights(status="proposed", document=pv["document"], reason=reason.strip()[:2000], proposed_by=by.id,
                             proposed_at=utcnow(), preview={k: pv[k] for k in ("current", "proposed", "change")})
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="posture.weights_proposed",
                          subject_type="posture_weights", subject_id=str(row.id),
                          payload={"document": row.document, "reason": row.reason, "preview": row.preview})
        return row

    def _get(self, wid: int) -> PostureWeights:
        row = self.s.get(PostureWeights, wid)
        if row is None:
            raise KeyError("unknown weights version")
        return row

    def approve(self, wid: int, by: Principal, note: str = "") -> PostureWeights:
        row = self._get(wid)
        if by.is_service or not by.can(Perm.APPROVE_POLICY) or not by.in_domain("*"):
            raise PermissionError("a lead with all-domain scope approves the Dome Score weights")
        if row.status != "proposed":
            raise ValueError(f"version {row.id} is {row.status}, not waiting for approval")
        if same_person(by.id, row.proposed_by):
            raise PermissionError("a second person approves: the proposer cannot approve their own weights")
        old = self._active_row()
        if not claim(self.s, row, ("proposed",), status="active", decided_by=by.id, decided_at=utcnow(),
                     note=str(note or "")[:2000]):
            raise ValueError(f"version {row.id} was decided by someone else at the same moment ({row.status})")
        self.s.execute(update(PostureWeights).where(PostureWeights.status == "active", PostureWeights.id != row.id)
                       .values(status="superseded").execution_options(synchronize_session=False))
        if old is not None:
            self.s.refresh(old)
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type="posture.weights_approved",
                          subject_type="posture_weights", subject_id=str(row.id),
                          payload={"document": row.document, "replaces": old.id if old else None, "note": row.note})
        return row

    def reject(self, wid: int, by: Principal, note: str) -> PostureWeights:
        row = self._get(wid)
        if row.status != "proposed":
            raise ValueError(f"version {row.id} is {row.status}, not waiting for approval")
        own = same_person(by.id, row.proposed_by)
        if by.is_service or not (own or (by.can(Perm.APPROVE_POLICY) and by.in_domain("*"))):
            raise PermissionError("a lead with all-domain scope rejects; the proposer may withdraw")
        if not own and not str(note or "").strip():
            raise ValueError("say why the weights are rejected")
        if not claim(self.s, row, ("proposed",), status="withdrawn" if own else "rejected", decided_by=by.id,
                     decided_at=utcnow(), note=str(note or "")[:2000]):
            raise ValueError(f"version {row.id} was decided by someone else at the same moment ({row.status})")
        self.s.flush()
        self.audit.append(actor_type="human", actor_id=by.id, event_type=f"posture.weights_{row.status}",
                          subject_type="posture_weights", subject_id=str(row.id), payload={"note": row.note})
        return row

    @staticmethod
    def view(row: PostureWeights) -> dict[str, Any]:
        return {"id": row.id, "status": row.status, "document": row.document, "reason": row.reason,
                "proposed_by": row.proposed_by, "proposed_at": row.proposed_at.isoformat(),
                "decided_by": row.decided_by, "decided_at": row.decided_at.isoformat() if row.decided_at else None,
                "note": row.note, "preview": row.preview}

    def overview(self) -> dict[str, Any]:
        doc, src = self.active()
        rows = self.s.execute(select(PostureWeights).order_by(PostureWeights.id.desc()).limit(20)).scalars().all()
        p = self.pending()
        return {"active": doc, "source": src, "pending": self.view(p) if p else None,
                "history": [self.view(r) for r in rows], "domains": list(DOMAINS), "penalty_labels": PENALTY_LABELS,
                "default": DEFAULT}
