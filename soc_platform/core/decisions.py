"""Earned autonomy: how the AI comes to decide a disposition, one narrow decision type at a time.

A *decision type* is narrow ("close or escalate a DLP alert on outbound e-mail"). Each one sits at a stage:

* ``shadow``     the AI decides every item; nothing happens; its decision is stored beside the computed one and, when
                 a person rules, beside the analyst's. Agreement is measured here.
* ``recommend``  the AI's decision is pre-filled for the analyst; accepting is one click, overriding needs a reason.
* ``decide``     the AI closes or escalates on its own. NOT AVAILABLE IN THIS VERSION: it is refused in code until the
                 adversarial-content test set and the Decide-stage guardrail tests exist (see CLAUDE.md, section 0).

Rules that hold at every stage, in code:

* The AI may escalate alone. It may close only when the computed disposition also says close and nothing puts the
  item on the never-automatic list (``effective``). Otherwise a person decides.
* A promotion is a policy change: proposed by one lead, approved by another, audited, and only possible once the
  measured agreement with analysts meets the target the SOC lead set over at least the minimum sample. There is no
  default target: until one is set, nothing can be promoted.
* Drift demotes without a person: agreement below the target over the newest decided items, or the mix of the AI's
  outcomes moving away from what it was promoted on (PSI above ``PSI_LIMIT``).
* A lead can demote at any time, alone (the safe direction).

Every AI decision is stored replayably: decision type, stage, the model and the prompt version, a hash of the
evidence it was given, its outcome and cited reasons, the computed outcome and the analyst's.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal, same_person
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import SystemFlag, new_id, utcnow

STAGES = ("shadow", "recommend", "decide")
AVAILABLE_STAGES = ("shadow", "recommend")
OUTCOMES = ("close_benign", "escalate")
PSI_LIMIT = 0.25
DRIFT_MIN_SAMPLE = 20
TARGET_BOUNDS = {"agreement_percent": (50, 100), "min_sample": (20, 100_000)}
TARGETS_FLAG = "decision_targets"
AGENT = "agent:decisions"


@dataclass(frozen=True)
class DecisionType:
    name: str
    domain: str
    label: str


TYPES: dict[str, DecisionType] = {t.name: t for t in (
    DecisionType("dlp.email", "dlp", "Close or escalate a DLP alert on outbound e-mail"),
    DecisionType("dlp.web", "dlp", "Close or escalate a DLP alert on a web upload"),
    DecisionType("dlp.removable_media", "dlp", "Close or escalate a DLP alert on removable media"),
    DecisionType("dlp.other", "dlp", "Close or escalate a DLP alert on another channel (print, application, cloud)"),
)}


class AiDecision(Base):
    """One AI decision on one item, with what it was compared against."""

    __tablename__ = "ai_decisions"
    __table_args__ = (UniqueConstraint("subject_type", "subject_id", "evidence_hash", name="uq_ai_decision"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    decision_type: Mapped[str] = mapped_column(String(64), index=True)
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    stage: Mapped[str] = mapped_column(String(16))
    ai_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ai_source: Mapped[str] = mapped_column(String(24))        # model | no_model | refused | failed | uncited
    computed_outcome: Mapped[str] = mapped_column(String(24))
    effective_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)   # None: a person decides
    analyst_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    analyst_source: Mapped[str | None] = mapped_column(String(16), nullable=True)      # platform | tool
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str] = mapped_column(String(32))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class DecisionStage(Base):
    """The stage of a decision type, versioned: the newest ``active`` row is in force."""

    __tablename__ = "decision_stages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_type: Mapped[str] = mapped_column(String(64), index=True)
    stage: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)   # pending|active|rejected|superseded
    proposed_by: Mapped[str] = mapped_column(String(256))
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reason: Mapped[str] = mapped_column(BoundedText(1000), default="")
    baseline: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)             # what was measured at the time
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


def effective(ai_outcome: str | None, computed_outcome: str, never_auto: list[Any]) -> str | None:
    """What the AI's decision may do by itself. Escalating is always allowed; closing needs the computed disposition
    to agree and the item to be off the never-automatic list. None: a person decides."""
    if ai_outcome == "escalate":
        return "escalate"
    if ai_outcome == "close_benign" and computed_outcome == "close_benign" and not never_auto:
        return "close_benign"
    return None


def psi(base: dict[str, float], cur: dict[str, float]) -> float:
    """Population stability index between two outcome mixes (shares or counts)."""
    keys = sorted(set(base) | set(cur))
    b_total, c_total = sum(base.values()) or 1.0, sum(cur.values()) or 1.0
    out = 0.0
    for k in keys:
        b = max(base.get(k, 0) / b_total, 1e-4)
        c = max(cur.get(k, 0) / c_total, 1e-4)
        out += (c - b) * math.log(c / b)
    return round(out, 4)


def _whole(v: Any) -> int | None:
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and float(v).is_integer() else None


class DecisionStore:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    # ------------------------------------------------------------------ stage

    def _active(self, decision_type: str) -> DecisionStage | None:
        return self.s.execute(select(DecisionStage).where(
            DecisionStage.decision_type == decision_type, DecisionStage.status == "active")
            .order_by(DecisionStage.id.desc()).limit(1)).scalars().first()

    def stage_of(self, decision_type: str) -> str:
        row = self._active(decision_type)
        return row.stage if row is not None and row.stage in AVAILABLE_STAGES else "shadow"

    def stages(self) -> dict[str, str]:
        return {name: self.stage_of(name) for name in TYPES}

    def history(self, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.s.execute(select(DecisionStage).order_by(DecisionStage.id.desc()).limit(limit)).scalars()
        return [{"id": r.id, "decision_type": r.decision_type, "stage": r.stage, "status": r.status,
                 "proposed_by": r.proposed_by, "approved_by": r.approved_by, "reason": r.reason, "baseline": r.baseline,
                 "created_at": r.created_at.isoformat(), "decided_at": r.decided_at.isoformat() if r.decided_at else None}
                for r in rows]

    # ------------------------------------------------------------------ targets (set by the SOC lead)

    def targets(self) -> dict[str, dict[str, int]]:
        f = self.s.get(SystemFlag, TARGETS_FLAG)
        v = f.value if f is not None and isinstance(f.value, dict) else {}
        return {k: x for k, x in v.items() if k in TYPES and isinstance(x, dict)}

    def set_target(self, decision_type: str, agreement_percent: Any, min_sample: Any, by: Principal) -> dict[str, int]:
        dt = _type(decision_type)
        _may_change(by, dt)
        target = {"agreement_percent": _whole(agreement_percent), "min_sample": _whole(min_sample)}
        for k, (lo, hi) in TARGET_BOUNDS.items():
            if target[k] is None or not lo <= target[k] <= hi:
                raise ValueError(f"{k} must be a whole number between {lo} and {hi}")
        doc = {**self.targets(), dt.name: target}
        f = self.s.get(SystemFlag, TARGETS_FLAG)
        if f is None:
            self.s.add(SystemFlag(name=TARGETS_FLAG, value=doc, updated_by=by.id, updated_at=utcnow()))
        else:
            f.value, f.updated_by, f.updated_at = doc, by.id, utcnow()
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="decision.target_set",
                          subject_type="decision_type", subject_id=dt.name, payload=target)
        return target

    # ------------------------------------------------------------------ the record

    def record(self, decision_type: str, subject_type: str, subject_id: str, *, ai_outcome: str | None, ai_source: str,
               computed_outcome: str, never_auto: list[Any], evidence_hash: str, prompt_version: str,
               model: str | None = None, reasons: list[dict[str, Any]] | None = None,
               analyst: tuple[str, str] | None = None) -> AiDecision:
        """Store one decision; the same item on the same evidence is one row (a re-run changes nothing)."""
        dt = _type(decision_type)
        row = self.s.execute(select(AiDecision).where(
            AiDecision.subject_type == subject_type, AiDecision.subject_id == subject_id,
            AiDecision.evidence_hash == evidence_hash)).scalars().first()
        if row is not None:
            return row
        outcome = ai_outcome if ai_outcome in OUTCOMES else None
        row = AiDecision(decision_type=dt.name, subject_type=subject_type, subject_id=subject_id,
                         stage=self.stage_of(dt.name), ai_outcome=outcome, ai_source=ai_source,
                         computed_outcome=computed_outcome,
                         effective_outcome=effective(outcome, computed_outcome, never_auto),
                         model=model, prompt_version=prompt_version, evidence_hash=evidence_hash,
                         reasons=reasons or [], analyst_outcome=analyst[0] if analyst else None,
                         analyst_source=analyst[1] if analyst else None, decided_at=utcnow() if analyst else None)
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type="agent", actor_id=AGENT, event_type="decision.recorded",
                          subject_type=subject_type, subject_id=subject_id,
                          payload={"decision_type": dt.name, "stage": row.stage, "ai_outcome": outcome,
                                   "ai_source": ai_source, "computed_outcome": computed_outcome,
                                   "effective_outcome": row.effective_outcome, "model": model,
                                   "prompt_version": prompt_version, "evidence_hash": evidence_hash,
                                   "citations": sorted({c for r in (reasons or []) for c in r.get("evidence_ids", [])})})
        return row

    def latest(self, subject_type: str, subject_ids: list[str]) -> dict[str, AiDecision]:
        """The newest decision per item."""
        out: dict[str, AiDecision] = {}
        ids = sorted(set(subject_ids))
        for i in range(0, len(ids), 500):
            rows = self.s.execute(select(AiDecision).where(
                AiDecision.subject_type == subject_type, AiDecision.subject_id.in_(ids[i:i + 500]))
                .order_by(AiDecision.created_at, AiDecision.id)).scalars()
            for r in rows:
                out[r.subject_id] = r
        return out

    def set_analyst(self, subject_type: str, subject_id: str, outcome: str, source: str) -> None:
        """A person ruled on the item: every decision recorded for it now carries the ruling."""
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome; use one of: {', '.join(OUTCOMES)}")
        for r in self.s.execute(select(AiDecision).where(AiDecision.subject_type == subject_type,
                                                         AiDecision.subject_id == subject_id)).scalars():
            r.analyst_outcome, r.analyst_source, r.decided_at = outcome, source, utcnow()
        self.s.flush()

    # ------------------------------------------------------------------ measurement

    def _decided(self, decision_type: str, *, since_id: datetime | None = None) -> list[AiDecision]:
        """Per item, its newest decision that has both an AI outcome and an analyst's, oldest item first."""
        q = select(AiDecision).where(AiDecision.decision_type == decision_type, AiDecision.ai_outcome.is_not(None),
                                     AiDecision.analyst_outcome.is_not(None))
        if since_id is not None:
            q = q.where(AiDecision.decided_at >= since_id)
        newest: dict[str, AiDecision] = {}
        for r in self.s.execute(q.order_by(AiDecision.created_at, AiDecision.id)).scalars():
            newest[r.subject_id] = r
        return sorted(newest.values(), key=lambda r: (r.decided_at or r.created_at, r.id))

    @staticmethod
    def _measure(rows: list[AiDecision]) -> dict[str, Any]:
        n = len(rows)
        agree = sum(r.ai_outcome == r.analyst_outcome for r in rows)
        computed = sum(r.computed_outcome == r.analyst_outcome for r in rows)
        wrong_close = sum(r.ai_outcome == "close_benign" and r.analyst_outcome == "escalate" for r in rows)
        return {"sample": n, "agreement_percent": round(100 * agree / n, 1) if n else None,
                "computed_agreement_percent": round(100 * computed / n, 1) if n else None,
                "ai_closed_what_analysts_escalated": wrong_close,
                "mix": dict(sorted(Counter(r.ai_outcome for r in rows).items()))}

    def evaluate(self) -> list[dict[str, Any]]:
        """Per decision type: its stage, what was measured against analysts, the target, and whether it may move up."""
        targets = self.targets()
        out = []
        for name, dt in TYPES.items():
            stage = self.stage_of(name)
            m = self._measure(self._decided(name))
            total = len({r for (r,) in self.s.execute(select(AiDecision.subject_id).where(
                AiDecision.decision_type == name, AiDecision.ai_outcome.is_not(None)))})
            target = targets.get(name)
            nxt = STAGES[STAGES.index(stage) + 1] if stage != STAGES[-1] else None
            blocked = None
            if nxt is None:
                blocked = "already at the last stage"
            elif nxt not in AVAILABLE_STAGES:
                blocked = "the Decide stage is not available in this version"
            elif target is None:
                blocked = "no agreement target has been set for this decision type"
            elif m["sample"] < target["min_sample"]:
                blocked = f"{m['sample']} decided item(s); the target needs at least {target['min_sample']}"
            elif (m["agreement_percent"] or 0) < target["agreement_percent"]:
                blocked = f"agreement {m['agreement_percent']}% is below the target {target['agreement_percent']}%"
            pending = self.s.execute(select(DecisionStage).where(
                DecisionStage.decision_type == name, DecisionStage.status == "pending")
                .order_by(DecisionStage.id.desc()).limit(1)).scalars().first()
            out.append({"decision_type": name, "label": dt.label, "domain": dt.domain, "stage": stage,
                        "ai_decisions": total, **m, "target": target, "next_stage": nxt,
                        "eligible": blocked is None, "blocked_by": blocked,
                        "pending": {"id": pending.id, "stage": pending.stage, "proposed_by": pending.proposed_by,
                                    "reason": pending.reason} if pending else None})
        return out

    def _evaluation(self, name: str) -> dict[str, Any]:
        return next(e for e in self.evaluate() if e["decision_type"] == name)

    # ------------------------------------------------------------------ promote / demote

    def propose(self, decision_type: str, stage: str, by: Principal, *, reason: str = "") -> DecisionStage:
        dt = _type(decision_type)
        _may_change(by, dt)
        if stage not in STAGES:
            raise ValueError(f"stage must be one of {', '.join(STAGES)}")
        if stage not in AVAILABLE_STAGES:
            raise ValueError("the Decide stage is not available in this version")
        current = self.stage_of(dt.name)
        ev = self._evaluation(dt.name)
        if STAGES.index(stage) < STAGES.index(current):                      # down: one lead, at once
            return self._activate(dt.name, stage, by.id, by.id, reason or "demoted by a lead", ev, by.actor_type,
                                  "decision.demoted")
        if stage == current:
            raise ValueError(f"{dt.name} is already at {stage}")
        if STAGES.index(stage) != STAGES.index(current) + 1:
            raise ValueError("a decision type moves up one stage at a time")
        if not ev["eligible"]:
            raise ValueError(f"not ready for {stage}: {ev['blocked_by']}")
        if ev["pending"]:
            raise ValueError("a promotion of this decision type is already waiting for approval")
        row = DecisionStage(decision_type=dt.name, stage=stage, status="pending", proposed_by=by.id, reason=reason,
                            baseline=_baseline(ev))
        self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="decision.promotion_proposed",
                          subject_type="decision_type", subject_id=dt.name,
                          payload={"proposal": row.id, "stage": stage, "reason": reason, **_baseline(ev)})
        return row

    def _pending(self, proposal_id: int) -> DecisionStage:
        row = self.s.get(DecisionStage, proposal_id)
        if row is None:
            raise KeyError("unknown proposal")
        if row.status != "pending":
            raise ValueError("this proposal is not waiting for a decision")
        return row

    def approve(self, proposal_id: int, by: Principal) -> DecisionStage:
        row = self._pending(proposal_id)
        dt = _type(row.decision_type)
        _may_change(by, dt)
        if same_person(row.proposed_by, by.id):
            raise PermissionError("separation of duties: a second lead must approve a promotion")
        ev = self._evaluation(dt.name)
        if not ev["eligible"] or ev["next_stage"] != row.stage:              # measured again at approval
            raise ValueError(f"no longer ready for {row.stage}: {ev['blocked_by'] or 'the stage has changed'}")
        return self._activate(dt.name, row.stage, row.proposed_by, by.id, row.reason, ev, by.actor_type,
                              "decision.promoted", proposal=row)

    def reject(self, proposal_id: int, by: Principal, *, reason: str = "") -> DecisionStage:
        row = self._pending(proposal_id)
        _may_change(by, _type(row.decision_type))
        row.status, row.decided_at, row.approved_by = "rejected", utcnow(), by.id
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type="decision.promotion_rejected",
                          subject_type="decision_type", subject_id=row.decision_type,
                          payload={"proposal": row.id, "reason": reason})
        self.s.flush()
        return row

    def _activate(self, name: str, stage: str, proposed_by: str, approved_by: str, reason: str, ev: dict[str, Any],
                  actor_type: str, event: str, *, proposal: DecisionStage | None = None) -> DecisionStage:
        for old in self.s.execute(select(DecisionStage).where(DecisionStage.decision_type == name,
                                                              DecisionStage.status.in_(("active", "pending")))).scalars():
            if proposal is None or old.id != proposal.id:
                old.status = "superseded"
        if proposal is not None:
            row = proposal
            row.status, row.approved_by, row.decided_at = "active", approved_by, utcnow()
        else:
            row = DecisionStage(decision_type=name, stage=stage, status="active", proposed_by=proposed_by,
                                approved_by=approved_by, reason=reason, baseline=_baseline(ev), decided_at=utcnow())
            self.s.add(row)
        self.s.flush()
        self.audit.append(actor_type=actor_type, actor_id=approved_by, event_type=event, subject_type="decision_type",
                          subject_id=name, payload={"stage": stage, "proposed_by": proposed_by, "reason": reason,
                                                    "version": row.id, **_baseline(ev)})
        return row

    def check_drift(self) -> list[dict[str, Any]]:
        """Demote, without a person, every decision type above shadow whose quality slipped since it was promoted."""
        targets = self.targets()
        demoted = []
        for name in TYPES:
            active = self._active(name)
            stage = self.stage_of(name)
            if active is None or stage == "shadow":
                continue
            target = targets.get(name)
            rows = self._decided(name, since_id=active.decided_at)
            window = rows[-max(DRIFT_MIN_SAMPLE, (target or {}).get("min_sample", DRIFT_MIN_SAMPLE)):]
            if len(window) < DRIFT_MIN_SAMPLE:
                continue
            m = self._measure(window)
            why = None
            if target and m["agreement_percent"] < target["agreement_percent"]:
                why = (f"agreement with analysts fell to {m['agreement_percent']}% over the newest {m['sample']} decided "
                       f"item(s) (target {target['agreement_percent']}%)")
            else:
                shift = psi((active.baseline or {}).get("mix") or {}, m["mix"]) if (active.baseline or {}).get("mix") else 0.0
                if shift > PSI_LIMIT:
                    why = f"the mix of its outcomes shifted from what it was promoted on (PSI {shift})"
            if why:
                lower = STAGES[STAGES.index(stage) - 1]
                self._activate(name, lower, AGENT, AGENT, why, {**self._evaluation(name), **m}, "agent",
                               "decision.demoted")
                demoted.append({"decision_type": name, "from": stage, "to": lower, "reason": why})
        return demoted


def _type(name: str) -> DecisionType:
    if name not in TYPES:
        raise KeyError(f"unknown decision type {name}")
    return TYPES[name]


def _may_change(by: Principal, dt: DecisionType) -> None:
    acting = by.acting_in(dt.domain)
    if acting.is_agent or acting.is_service or not acting.can(Perm.APPROVE_POLICY):
        raise PermissionError(f"approve_policy for {dt.domain} data is required (a lead, in person)")


def _baseline(ev: dict[str, Any]) -> dict[str, Any]:
    return {"sample": ev.get("sample"), "agreement_percent": ev.get("agreement_percent"), "mix": ev.get("mix") or {},
            "target": ev.get("target")}
