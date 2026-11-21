"""DLP rule-change proposals (Dome Agents): the platform proposes a change to a noisy DLP rule, shows its effect on
past alerts, a second lead approves it, an engineer makes it in the DLP tool, and the platform checks it took effect.

The platform never edits a rule in the DLP tool. The lifecycle:

``proposed`` (a lead, from a suggestion or by hand; the preview is computed and kept)
  -> ``approved`` by a second lead (the preview is computed again) | ``rejected`` | ``withdrawn``
  -> ``applied``: an engineer (connector management) records that the change was made in the tool, with its reference
  -> verified on read: the tool's configuration snapshot shows the change, and no matching alert arrived since.

Five kinds of change, each a fixed shape (no free text reaches the tool). Three narrow what the rule fires on:

* ``exclude_destination`` - the rule no longer fires for one destination domain (a known partner)
* ``raise_threshold``     - the rule fires only from N matches of its classifiers
* ``exclude_ocr``         - text read out of images (OCR) no longer counts toward the rule: scanned invoices whose
  numbers read like card or PAN numbers

and two change how it recognises the data (classification quality: they hide nothing by themselves; the preview
shows the alerts the classifier matched, and the effect is measured after the change):

* ``use_edm``             - replace a pattern classifier (a number shape) with an exact data match against the real
  data set (the investor database): numbers that merely look like a PAN stop matching
* ``use_fingerprint``     - replace a keyword classifier (a marking, a word list) with fingerprints of the documents
  the rule protects

The preview looks at the rule's alerts in the 90 days up to the newest alert. A change is refused - at proposal and
again at approval - when it would have hidden an alert an analyst escalated, an alert with personal data in bulk, a
high or critical alert, or an alert on the never-automatic list; or when it would have hidden nothing.
Suggestions come from analysts' rulings: a rule closed as benign at least four times in five, where the closures
share one destination or stay under a match count the escalations do not. Classification-quality findings come from
the same rulings and each classifier's type and OCR origin as the tool reports them (never from message text or file
names): closures whose matches were all read from images, or that one pattern or keyword classifier produced.
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
from soc_platform.core.db import Base, BoundedText, UTCDateTime, claim
from soc_platform.core.models import utcnow
from soc_platform.domains.dlp.models import DlpAlert

KINDS = {"exclude_destination": "Exclude a destination from the rule", "raise_threshold": "Raise the rule's match threshold",
         "exclude_ocr": "Stop text read from images (OCR) counting toward the rule",
         "use_edm": "Replace a pattern classifier with an exact data match (EDM)",
         "use_fingerprint": "Replace a keyword classifier with document fingerprints"}
RECLASSIFY = {"use_edm": ("pattern", "edm"), "use_fingerprint": ("dictionary", "fingerprint")}   # replaces -> with
QUALITY_SHARE = 0.8
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
    if kind == "exclude_ocr":
        if set(p):
            raise ValueError("exclude_ocr takes no parameters")
        return {}
    if kind in RECLASSIFY:
        c = p.get("classifier")
        if set(p) - {"classifier"} or not isinstance(c, str) or not c.strip() or len(c) > 120:
            raise ValueError(f"{kind} names the classifier it replaces (classifier: its name, as the tool reports it)")
        return {"classifier": c.strip()}
    n = p.get("min_matches")
    if not isinstance(n, int) or isinstance(n, bool) or not 2 <= n <= MAX_THRESHOLD:
        raise ValueError(f"min_matches must be a whole number from 2 to {MAX_THRESHOLD}")
    return {"min_matches": n}


def describe(rule: str, kind: str, p: dict[str, Any]) -> str:
    if kind == "exclude_destination":
        return f"Stop '{rule}' firing for data sent to {p['destination']}"
    if kind == "exclude_ocr":
        return f"Stop text read from images (OCR) counting toward '{rule}'"
    if kind == "use_edm":
        return f"In '{rule}', replace the pattern classifier '{p['classifier']}' with an exact data match against the real data set"
    if kind == "use_fingerprint":
        return f"In '{rule}', replace the keyword classifier '{p['classifier']}' with fingerprints of the documents it protects"
    return f"Make '{rule}' fire only from {p['min_matches']} matches"


def _matched(alert: DlpAlert) -> list[dict[str, Any]]:
    return [c for c in (alert.facts or {}).get("classifiers") or [] if isinstance(c, dict) and int(c.get("matches") or 0) > 0]


def ocr_only(alert: DlpAlert) -> bool:
    """Every match of the alert came from text read out of an image."""
    m = _matched(alert)
    return bool(m) and all(c.get("ocr") is True for c in m)


def matched_by(alert: DlpAlert, classifier: str) -> bool:
    return any(c.get("name") == classifier for c in _matched(alert))


def hides(alert: DlpAlert, kind: str, p: dict[str, Any]) -> bool:
    """Whether the changed rule would not have fired on this alert (a classification change hides nothing itself)."""
    if kind == "exclude_destination":
        d = (alert.destination_domain or "").lower()
        return bool(d) and (d == p["destination"] or d.endswith("." + p["destination"]))
    if kind == "exclude_ocr":
        return ocr_only(alert)
    if kind in RECLASSIFY:
        return False
    return int((alert.facts or {}).get("max_matches") or 0) < p["min_matches"]


def _types(rows: list[DlpAlert]) -> dict[str, str]:
    """Each classifier's type as the tool reported it on the rule's alerts (the most recent report wins)."""
    out: dict[str, str] = {}
    for a in rows:
        for c in _matched(a):
            out[str(c.get("name"))] = str(c.get("type") or "unknown")
    return out


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
    if kind in RECLASSIFY:
        return _preview_reclassify(rule, kind, p, rows, since, days)
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
            "hidden_alerts": [a.id for a in hidden][:200], "blocked_by": blocked, "allowed": not blocked,
            "effect": "hides", "warnings": []}


def _preview_reclassify(rule: str, kind: str, p: dict[str, Any], rows: list[DlpAlert], since: datetime | None,
                        days: int) -> dict[str, Any]:
    """A classification change hides nothing by itself: the preview shows the alerts the replaced classifier matched
    and how analysts ruled on them. Whether each would still match depends on the data set (EDM) or the documents
    (fingerprints) the engineer loads, so that is measured after the change - never estimated as a figure here."""
    want = RECLASSIFY[kind][0]
    seen = _types(rows).get(p["classifier"])
    affected = [a for a in rows if matched_by(a, p["classifier"])]
    ruled = Counter(a.analyst_outcome for a in affected if a.analyst_outcome)
    blocked, warnings = [], []
    if seen is None:
        blocked.append(f"the classifier '{p['classifier']}' matched none of this rule's alerts in the last {days} days")
    elif seen != want:
        blocked.append(f"'{p['classifier']}' is reported as a {seen} classifier, not a {want} one")
    if ruled.get("escalate"):
        warnings.append(f"{ruled['escalate']} alert(s) it matched were escalated: check that the "
                        + ("data set" if kind == "use_edm" else "fingerprinted documents") + " cover what they found")
    severe = sum(1 for a in affected if a.severity in ("high", "critical"))
    if severe:
        warnings.append(f"{severe} high or critical alert(s) relied on it: keep it until the replacement is verified")
    return {"rule": rule, "kind": kind, "params": p, "change": describe(rule, kind, p), "days": days,
            "since": since.isoformat() if since else None, "rule_alerts": len(rows), "hidden": 0,
            "hidden_closed_benign": 0, "hidden_escalated": 0, "hidden_undecided": 0, "still_firing": len(rows),
            "affected": len(affected), "affected_closed_benign": ruled.get("close_benign", 0),
            "affected_escalated": ruled.get("escalate", 0), "affected_undecided": len(affected) - sum(ruled.values()),
            "hidden_alerts": [], "blocked_by": blocked, "allowed": not blocked, "effect": "reclassifies",
            "warnings": warnings}


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


def quality(session: Session) -> list[dict[str, Any]]:
    """Classification-quality findings: a noisy rule (closed as benign at least four times in five over 30 days) whose
    closures came from text read out of images, or from one pattern or keyword classifier - with the change that
    would fix it, previewed. Read from each classifier's type and OCR origin as the tool reports them, never from
    message text or file names."""
    since = _window_start(session, SUGGEST_DAYS)
    if since is None:
        return []
    busy = {r for (r,) in session.execute(select(DlpRuleProposal.rule).where(
        DlpRuleProposal.status.in_(("proposed", "approved", "applied")))).all()}
    out = []
    for rule in known_rules(session):
        if rule in busy:
            continue
        rows = list(session.execute(select(DlpAlert).where(DlpAlert.rule == rule, DlpAlert.event_time >= since)
                                    .order_by(DlpAlert.event_time, DlpAlert.id)).scalars())
        decided = [a for a in rows if a.analyst_outcome]
        benign = [a for a in decided if a.analyst_outcome == "close_benign"]
        if len(decided) < SUGGEST_MIN_DECIDED or len(benign) / len(decided) < SUGGEST_BENIGN_SHARE:
            continue
        lead_in = f"Analysts closed {len(benign)} of {len(decided)} decided alerts of this rule as benign in {SUGGEST_DAYS} days"
        drafts: list[tuple[str, dict[str, Any], str]] = []
        ocr = sum(1 for a in benign if ocr_only(a))
        escalated_ocr = sum(1 for a in decided if a.analyst_outcome == "escalate" and ocr_only(a))
        if ocr / len(benign) >= QUALITY_SHARE and not escalated_ocr:
            drafts.append(("exclude_ocr", {}, f"{lead_in}; in {ocr} of them every match was text read from an image (OCR)"))
        types = _types(rows)
        for kind, (want, _with) in RECLASSIFY.items():
            for name in sorted(n for n, ty in types.items() if ty == want):
                n = sum(1 for a in benign if matched_by(a, name))
                if n / len(benign) >= QUALITY_SHARE:
                    drafts.append((kind, {"classifier": name},
                                   f"{lead_in}; {n} of them were matched by the {want} classifier '{name}'"))
        for kind, params, why in drafts:
            pv = preview(session, rule, kind, params)
            if pv["allowed"]:
                out.append({"rule": rule, "kind": kind, "kind_label": KINDS[kind], "params": params,
                            "change": pv["change"], "reason": why, "preview": pv,
                            "evidence": {"alerts": len(rows), "decided": len(decided), "closed_benign": len(benign)}})
    return out


def _types_in(item: dict[str, Any]) -> set[str]:
    """The classifier types a configured rule lists, in our words (the export's own vocabulary is a placeholder)."""
    from soc_platform.connectors.tools.forcepoint_dlp import CLASSIFIER_TYPES

    kinds = item.get("classifier_types") if isinstance(item.get("classifier_types"), dict) else {}
    return {CLASSIFIER_TYPES.get(str(v).strip().lower().replace(" ", "_"), "unknown") for v in kinds.values()}


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
        if not claim(self.s, row, OPEN, status="approved", decided_by=by.id, decided_at=utcnow(), note=note, preview=pv):
            raise ValueError("this proposal was decided by someone else at the same moment")
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
        if not claim(self.s, row, ("proposed", "approved"), status="withdrawn" if withdraw else "rejected",
                     decided_by=by.id, decided_at=utcnow(), note=note):
            raise ValueError("this proposal was decided by someone else at the same moment")
        self._audit(by, f"dlp.rule_change_{row.status}", row, {"note": note})
        return row

    def mark_applied(self, pid: int, by: Principal, reference: str) -> DlpRuleProposal:
        _may_apply(by)
        row = self._get(pid)
        if row.status != "approved":
            raise ValueError("only an approved change can be recorded as made in the tool")
        if not reference.strip():
            raise ValueError("record the change's reference (ticket or name)")
        if not claim(self.s, row, ("approved",), status="applied", applied_by=by.id, applied_at=utcnow(),
                     change_reference=reference.strip()):
            raise ValueError("this proposal was decided by someone else at the same moment")
        self._audit(by, "dlp.rule_change_applied", row, {"reference": row.change_reference})
        return row

    def _audit(self, by: Principal, event: str, row: DlpRuleProposal, extra: dict[str, Any]) -> None:
        self.audit.append(actor_type=by.actor_type, actor_id=by.id, event_type=event, subject_type="dlp_rule_proposal",
                          subject_id=str(row.id), payload={"rule": row.rule, "kind": row.kind, "params": row.params, **extra})
        self.s.flush()

    # ------------------------------------------------------------------ did it take effect?

    def verify(self, row: DlpRuleProposal, tool: str | None = None) -> dict[str, Any] | None:
        """For an applied change: does the tool's configuration show it, and have matching alerts stopped? ``tool``:
        the DLP tool whose rule it is - by default the tool that raised the rule's alerts."""
        if row.status != "applied" or row.applied_at is None:
            return None
        if tool is None:
            from soc_platform.domains.dlp.models import DlpAlert

            tool = self.s.execute(select(DlpAlert.tool).where(DlpAlert.rule == row.rule).order_by(DlpAlert.id)
                                  .limit(1)).scalar() or ""
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
            elif row.kind == "exclude_ocr":
                shown = item.get("ocr_enabled") is False
                config = ("confirmed in the tool's configuration" if shown
                          else "the configuration still counts text read from images")
            elif row.kind in RECLASSIFY:
                new = RECLASSIFY[row.kind][1]
                gone = row.params["classifier"] not in [str(x) for x in item.get("classifiers") or []]
                added = new in _types_in(item)
                shown = gone and added
                config = ("confirmed in the tool's configuration" if shown
                          else f"the configuration still lists '{row.params['classifier']}'" if not gone
                          else f"the configuration shows no {new} classifier in the rule")
            else:
                t = item.get("threshold")
                shown = isinstance(t, int) and not isinstance(t, bool) and t >= row.params["min_matches"]
                config = "confirmed in the tool's configuration" if shown else f"the configuration shows threshold {t}"
        later = [a for a in self.s.execute(select(DlpAlert).where(DlpAlert.rule == row.rule,
                                                                  DlpAlert.event_time > row.applied_at)).scalars()
                 if (matched_by(a, row.params["classifier"]) if row.kind in RECLASSIFY else hides(a, row.kind, row.params))]
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
        return {"kinds": KINDS, "suggestions": suggestions(self.s), "quality": quality(self.s),
                "proposals": [self.view(r) for r in rows]}
