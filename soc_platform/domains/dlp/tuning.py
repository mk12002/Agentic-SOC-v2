"""DLP rule-change proposals (Dome Agents): the platform proposes a change to a noisy DLP rule, shows its effect on
past alerts, a second lead approves it, an engineer makes it in the DLP tool, and the platform checks it took effect.

The platform never edits a rule in the DLP tool. The lifecycle:

``proposed`` (a lead, from a suggestion or by hand; the preview is computed and kept)
  -> ``approved`` by a second lead (the preview is computed again) | ``rejected`` | ``withdrawn``
  -> ``applied``: an engineer (connector management) records that the change was made in the tool, with its reference
  -> verified on read: the tool's configuration snapshot shows the change, and no matching alert arrived since.

Two kinds of change, both a fixed shape (no free text reaches the tool):

* ``exclude_destination`` - the rule no longer fires for one destination domain (a known partner)
* ``raise_threshold``     - the rule fires only from N matches of its classifiers

The preview looks at the rule's alerts in the 90 days up to the newest alert. A change is refused - at proposal and
again at approval - when it would have hidden an alert an analyst escalated, an alert with personal data in bulk, a
high or critical alert, or an alert on the never-automatic list; or when it would have hidden nothing.
Suggestions come from analysts' rulings: a rule closed as benign at least four times in five, where the closures
share one destination or stay under a match count the escalations do not.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Perm, Principal, same_person
from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import utcnow
from soc_platform.domains.dlp.models import DlpAlert

KINDS = {"exclude_destination": "Exclude a destination from the rule", "raise_threshold": "Raise the rule's match threshold"}
PREVIEW_DAYS = 90
SUGGEST_DAYS = 30
SUGGEST_MIN_DECIDED, SUGGEST_BENIGN_SHARE, SUGGEST_DOMAIN_SHARE = 3, 0.8, 0.8
MAX_THRESHOLD = 100_000
_DOMAIN = re.compile(r"^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
OPEN = ("proposed",)


class DlpRuleProposal(Base):
    __tablename__ = "dlp_rule_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule: Mapped[str] = mapped_column(BoundedText(256), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(BoundedText(2000), default="")
    drafted_by: Mapped[str] = mapped_column(String(16), default="lead")          # suggestion | lead
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    proposed_by: Mapped[str] = mapped_column(String(256))
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    note: Mapped[str] = mapped_column(BoundedText(2000), default="")
    applied_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    change_reference: Mapped[str] = mapped_column(BoundedText(120), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


# ---------------------------------------------------------------------------------------------- the change itself


def clean(kind: str, params: Any) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    p = params if isinstance(params, dict) else {}
    if kind == "exclude_destination":
        d = str(p.get("destination") or "").strip().lower().rstrip(".")
        if not _DOMAIN.match(d):
            raise ValueError("destination must be a domain name, e.g. partner.example")
        return {"destination": d}
    n = p.get("min_matches")
    if not isinstance(n, int) or isinstance(n, bool) or not 2 <= n <= MAX_THRESHOLD:
        raise ValueError(f"min_matches must be a whole number from 2 to {MAX_THRESHOLD}")
    return {"min_matches": n}


def describe(rule: str, kind: str, p: dict[str, Any]) -> str:
    if kind == "exclude_destination":
        return f"Stop '{rule}' firing for data sent to {p['destination']}"
    return f"Make '{rule}' fire only from {p['min_matches']} matches"


def hides(alert: DlpAlert, kind: str, p: dict[str, Any]) -> bool:
    """Whether the changed rule would not have fired on this alert."""
    if kind == "exclude_destination":
        d = (alert.destination_domain or "").lower()
        return bool(d) and (d == p["destination"] or d.endswith("." + p["destination"]))
    return int((alert.facts or {}).get("max_matches") or 0) < p["min_matches"]


def _window_start(session: Session, days: int) -> datetime | None:
    newest = session.execute(select(func.max(DlpAlert.event_time))).scalar()
    return newest - timedelta(days=days) if newest else None


def known_rules(session: Session) -> list[str]:
    return sorted(r for (r,) in session.execute(select(DlpAlert.rule).distinct()).all() if r)


def preview(session: Session, rule: str, kind: str, params: Any, *, days: int = PREVIEW_DAYS) -> dict[str, Any]:
    """What the change would have done to the rule's alerts in the window: how many it hides, how analysts ruled on
    those, and whether any of them must never be hidden. Stores nothing."""
    p = clean(kind, params)
    since = _window_start(session, days)
    rows = list(session.execute(select(DlpAlert).where(DlpAlert.rule == rule, DlpAlert.event_time >= since)
                                .order_by(DlpAlert.event_time, DlpAlert.id)).scalars()) if since else []
    hidden = [a for a in rows if hides(a, kind, p)]
    ruled = Counter(a.analyst_outcome for a in hidden if a.analyst_outcome)
    bulk_personal = sum(1 for a in hidden if a.personal_data and (a.facts or {}).get("bulk"))
    severe = sum(1 for a in hidden if a.severity in ("high", "critical"))
    never = sum(1 for a in hidden if a.never_auto)
    blocked = []
    if not hidden:
        blocked.append(f"it would have hidden no alert in the last {days} days")
    if ruled.get("escalate"):
        blocked.append(f"it would have hidden {ruled['escalate']} alert(s) an analyst escalated")
    if bulk_personal:
        blocked.append(f"it would have hidden {bulk_personal} alert(s) with personal data in bulk")
    if severe:
        blocked.append(f"it would have hidden {severe} high or critical alert(s)")
    if never:
        blocked.append(f"it would have hidden {never} alert(s) on the never-automatic list")
    return {"rule": rule, "kind": kind, "params": p, "change": describe(rule, kind, p), "days": days,
            "since": since.isoformat() if since else None, "rule_alerts": len(rows), "hidden": len(hidden),
            "hidden_closed_benign": ruled.get("close_benign", 0), "hidden_escalated": ruled.get("escalate", 0),
            "hidden_undecided": len(hidden) - sum(ruled.values()), "still_firing": len(rows) - len(hidden),
            "hidden_alerts": [a.id for a in hidden][:200], "blocked_by": blocked, "allowed": not blocked}


# ---------------------------------------------------------------------------------------------- suggestions


def suggestions(session: Session) -> list[dict[str, Any]]:
    """Changes worth proposing, computed from how analysts ruled on each rule's alerts in the last 30 days."""
    since = _window_start(session, SUGGEST_DAYS)
    if since is None:
        return []
    out = []
    # a rule with a change in progress or already made gets no other suggestion until that one is settled
    busy = {r for (r,) in session.execute(select(DlpRuleProposal.rule).where(
        DlpRuleProposal.status.in_(("proposed", "approved", "applied")))).all()}
    for rule in known_rules(session):
        if rule in busy:
            continue
        rows = list(session.execute(select(DlpAlert).where(DlpAlert.rule == rule, DlpAlert.event_time >= since)).scalars())
        decided = [a for a in rows if a.analyst_outcome]
        benign = [a for a in decided if a.analyst_outcome == "close_benign"]
        if len(decided) < SUGGEST_MIN_DECIDED or len(benign) / len(decided) < SUGGEST_BENIGN_SHARE:
            continue
        overrides = [a.analyst_reason for a in rows if a.ai_outcome and a.analyst_outcome
                     and a.ai_outcome != a.analyst_outcome and a.analyst_reason][:3]
        evidence = {"alerts": len(rows), "decided": len(decided), "closed_benign": len(benign),
                    "overrides_with_reasons": overrides}
        drafts = []
        domains = Counter(a.destination_domain for a in benign if a.destination_domain)
        if domains:
            dom, n = min(domains.items(), key=lambda x: (-x[1], x[0]))
            if n / len(benign) >= SUGGEST_DOMAIN_SHARE:
                drafts.append(("exclude_destination", {"destination": dom},
                               (f"Analysts closed {len(benign)} of {len(decided)} decided alerts of this rule as benign in "
                               f"{SUGGEST_DAYS} days; {n} of those closures were data sent to {dom}")))
        top = max(int((a.facts or {}).get("max_matches") or 0) for a in benign) + 1
        if 2 <= top <= MAX_THRESHOLD:
            drafts.append(("raise_threshold", {"min_matches": top},
                           (f"Analysts closed {len(benign)} of {len(decided)} decided alerts of this rule as benign in "
                           f"{SUGGEST_DAYS} days; none of the closed ones had {top} or more matches")))
        for kind, params, why in drafts:
            pv = preview(session, rule, kind, params)
            if pv["allowed"]:
                out.append({"rule": rule, "kind": kind, "params": params, "change": pv["change"], "reason": why,
                            "evidence": evidence, "preview": pv})
                break                                                    # the most specific change per rule
    return out


# ---------------------------------------------------------------------------------------------- lifecycle


def _may_tune(by: Principal) -> None:
    acting = by.acting_in("dlp")
    if acting.is_agent or acting.is_service or not acting.can(Perm.TUNE_DETECTIONS):
        raise PermissionError("tune_detections for dlp data is required (a lead, in person)")


def _may_apply(by: Principal) -> None:
    if by.is_agent or by.is_service or not by.can(Perm.MANAGE_CONNECTORS):
        raise PermissionError("manage_connectors is required to record a change made in the tool (an engineer)")


class DlpTuning:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.audit = AuditLog(session)

    def _get(self, pid: int) -> DlpRuleProposal:
        row = self.s.get(DlpRuleProposal, pid)
        if row is None:
            raise KeyError("unknown proposal")
        return row

    def propose(self, by: Principal, *, rule: str, kind: str, params: Any, reason: str,
                drafted_by: str = "lead") -> DlpRuleProposal:
        _may_tune(by)
        if rule not in known_rules(self.s):
            raise ValueError("unknown rule: a proposal must name a rule the DLP tool has reported")
        if not reason.strip():
            raise ValueError("a proposal needs its reason")
        pv = preview(self.s, rule, kind, params)
        if not pv["allowed"]:
            raise ValueError("refused: " + "; ".join(pv["blocked_by"]))
        same = self.s.execute(select(DlpRuleProposal).where(DlpRuleProposal.rule == rule, DlpRuleProposal.kind == kind,
                                                            DlpRuleProposal.status.in_(("proposed", "approved")))).scalars()
        if any(r.params == pv["params"] for r in same):
            raise ValueError("the same change is already proposed or approved")
        row = DlpRuleProposal(rule=rule, kind=kind, params=pv["params"], reason=reason.strip(), proposed_by=by.id,
                              drafted_by="suggestion" if drafted_by == "suggestion" else "lead", preview=pv)
        self.s.add(row)
        self.s.flush()
        self._audit(by, "dlp.rule_change_proposed", row, {"preview": {k: pv[k] for k in (
            "hidden", "hidden_closed_benign", "hidden_escalated", "hidden_undecided", "still_firing")}})
        return row

    def approve(self, pid: int, by: Principal, note: str = "") -> DlpRuleProposal:
        _may_tune(by)
        row = self._get(pid)
        if row.status not in OPEN:
            raise ValueError("this proposal is not waiting for approval")
        if same_person(row.proposed_by, by.id):
            raise PermissionError("separation of duties: a second lead must approve the change")
        pv = preview(self.s, row.rule, row.kind, row.params)                # measured again: new alerts may have come
        if not pv["allowed"]:
            raise ValueError("no longer allowed: " + "; ".join(pv["blocked_by"]))
        row.status, row.decided_by, row.decided_at, row.note, row.preview = "approved", by.id, utcnow(), note, pv
        self._audit(by, "dlp.rule_change_approved", row, {"note": note})
        return row

    def reject(self, pid: int, by: Principal, note: str) -> DlpRuleProposal:
        row = self._get(pid)
        if row.status not in ("proposed", "approved"):
            raise ValueError("this proposal can no longer be rejected or withdrawn")
        withdraw = same_person(row.proposed_by, by.id)
        _may_tune(by)
        if not note.strip():
            raise ValueError("a reason is required")
        row.status = "withdrawn" if withdraw else "rejected"
        row.decided_by, row.decided_at, row.note = by.id, utcnow(), note
        self._audit(by, f"dlp.rule_change_{row.status}", row, {"note": note})
        return row

    def mark_applied(self, pid: int, by: Principal, reference: str) -> DlpRuleProposal:
        _may_apply(by)
        row = self._get(pid)
        if row.status != "approved":
            raise ValueError("only an approved change can be recorded as made in the tool")
        if not reference.strip():
            raise ValueError("record the change's reference (ticket or name)")
        row.status, row.applied_by, row.applied_at, row.change_reference = "applied", by.id, utcnow(), reference.strip()
        self._audit(by, "dlp.rule_change_applied", row, {"reference": row.change_reference})
        return row

    def _audit(self, by: Principal, event: str, row: DlpRuleProposal, extra: dict[str, Any]) -> None:
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type=event, subject_type="dlp_rule_proposal",
                          subject_id=str(row.id), payload={"rule": row.rule, "kind": row.kind, "params": row.params, **extra})
        self.s.flush()

    # ------------------------------------------------------------------ did it take effect?

    def verify(self, row: DlpRuleProposal, tool: str = "forcepoint_dlp") -> dict[str, Any] | None:
        """For an applied change: does the tool's configuration show it, and have matching alerts stopped?"""
        if row.status != "applied" or row.applied_at is None:
            return None
        from soc_platform.intelligence.config_snapshots import ConfigSnapshot

        snap = self.s.execute(select(ConfigSnapshot).where(ConfigSnapshot.tool == tool,
                                                           ConfigSnapshot.taken_at >= row.applied_at)
                              .order_by(ConfigSnapshot.id.desc()).limit(1)).scalars().first()
        config = "no configuration snapshot since the change was recorded"
        if snap is not None:
            item = next((i for i in snap.items if str(i.get("name")) == row.rule), None)
            if item is None:
                config = "the rule is not in the newest configuration snapshot"
            elif row.kind == "exclude_destination":
                shown = row.params["destination"] in [str(x).lower() for x in item.get("excluded_destinations") or []]
                config = "confirmed in the tool's configuration" if shown else "the configuration does not show the exclusion"
            else:
                t = item.get("threshold")
                shown = isinstance(t, int) and not isinstance(t, bool) and t >= row.params["min_matches"]
                config = "confirmed in the tool's configuration" if shown else f"the configuration shows threshold {t}"
        later = [a for a in self.s.execute(select(DlpAlert).where(DlpAlert.rule == row.rule,
                                                                  DlpAlert.event_time > row.applied_at)).scalars()
                 if hides(a, row.kind, row.params)]
        return {"configuration": config, "confirmed": config.startswith("confirmed"),
                "snapshot": snap.id if snap else None, "matching_alerts_since": len(later)}

    def view(self, row: DlpRuleProposal) -> dict[str, Any]:
        iso = lambda v: v.isoformat() if v else None
        return {"id": row.id, "rule": row.rule, "kind": row.kind, "kind_label": KINDS[row.kind], "params": row.params,
                "change": describe(row.rule, row.kind, row.params), "reason": row.reason, "drafted_by": row.drafted_by,
                "status": row.status, "preview": row.preview, "proposed_by": row.proposed_by,
                "created_at": iso(row.created_at), "decided_by": row.decided_by, "decided_at": iso(row.decided_at),
                "note": row.note, "applied_by": row.applied_by, "applied_at": iso(row.applied_at),
                "change_reference": row.change_reference, "verification": self.verify(row)}

    def overview(self) -> dict[str, Any]:
        rows = self.s.execute(select(DlpRuleProposal).order_by(DlpRuleProposal.id.desc()).limit(200)).scalars()
        return {"kinds": KINDS, "suggestions": suggestions(self.s), "proposals": [self.view(r) for r in rows]}
