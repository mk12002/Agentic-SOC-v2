"""Earned autonomy: a decision type starts at shadow, moves up only on measured agreement with analysts against a
target the SOC lead set, by two leads - and comes back down by itself when its quality slips."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from soc_platform.core.auth import Principal, Role
from soc_platform.core.decisions import (
    AVAILABLE_STAGES,
    DRIFT_MIN_SAMPLE,
    PSI_LIMIT,
    STAGES,
    TYPES,
    AiDecision,
    DecisionStore,
    effective,
    psi,
)
from soc_platform.core.models import AuditRecord
from soc_platform.tests.conftest import person

LEAD1 = person("lead.one@example.com", Role.LEAD)
LEAD2 = person("lead.two@example.com", Role.LEAD)
ANALYST = person("ana@example.com", Role.ANALYST)
SERVICE_LEAD = Principal("svc", "svc", frozenset({Role.LEAD}), is_service=True)
OTHER_DOMAIN_LEAD = Principal("vm.lead@example.com", "vm", frozenset({Role.LEAD}), domains=frozenset({"vulnerability"}))
T = "dlp.email"


def decided(store: DecisionStore, n: int, *, ai: str = "close_benign", analyst: str = "close_benign", start: int = 0,
            computed: str = "close_benign", decision_type: str = T) -> None:
    """``n`` items the AI decided and an analyst then ruled on."""
    for i in range(start, start + n):
        store.record(decision_type, "dlp_alert", f"item-{decision_type}-{i}", ai_outcome=ai, ai_source="model",
                     computed_outcome=computed, never_auto=[], evidence_hash=f"h{i}", prompt_version="p1", model="m",
                     reasons=[{"text": "r", "evidence_ids": ["F1"]}])
        store.set_analyst("dlp_alert", f"item-{decision_type}-{i}", analyst, "platform")


def events(session, kind: str) -> list[AuditRecord]:
    return list(session.execute(select(AuditRecord).where(AuditRecord.event_type == kind).order_by(AuditRecord.seq)).scalars())


def test_the_ai_may_escalate_alone_but_closes_only_with_the_computed_check_and_off_the_never_list():
    assert effective("escalate", "close_benign", []) == "escalate"
    assert effective("escalate", "review", ["privileged sender"]) == "escalate"
    assert effective("close_benign", "close_benign", []) == "close_benign"
    assert effective("close_benign", "review", []) is None
    assert effective("close_benign", "escalate", []) is None
    assert effective("close_benign", "close_benign", ["high severity"]) is None
    assert effective(None, "close_benign", []) is None


def test_every_decision_type_starts_at_shadow_and_cannot_move_without_a_target(session):
    store = DecisionStore(session)
    assert store.stages() == dict.fromkeys(TYPES, "shadow")
    decided(store, 60)
    ev = next(e for e in store.evaluate() if e["decision_type"] == T)
    assert (ev["sample"], ev["agreement_percent"], ev["target"], ev["eligible"]) == (60, 100.0, None, False)
    assert "no agreement target" in ev["blocked_by"]                    # there is no default target to promote on
    with pytest.raises(ValueError, match="no agreement target"):
        store.propose(T, "recommend", LEAD1)


def test_a_target_is_set_by_a_lead_within_bounds_and_is_audited(session):
    store = DecisionStore(session)
    for bad in ((49, 50), (101, 50), (90, 19), (90.5, 50), ("90", 50), (True, 50), (None, None)):
        with pytest.raises(ValueError):
            store.set_target(T, *bad, LEAD1)
    for nobody in (ANALYST, SERVICE_LEAD, OTHER_DOMAIN_LEAD):
        with pytest.raises(PermissionError):
            store.set_target(T, 90, 50, nobody)
    with pytest.raises(KeyError):
        store.set_target("dlp.everything", 90, 50, LEAD1)
    assert store.set_target(T, 90, 50, LEAD1) == {"agreement_percent": 90, "min_sample": 50}
    store.set_target("dlp.web", 80, 20, LEAD2)                          # one type's target never replaces another's
    assert store.targets() == {T: {"agreement_percent": 90, "min_sample": 50}, "dlp.web": {"agreement_percent": 80, "min_sample": 20}}
    assert [(e.actor_id, e.subject_id) for e in events(session, "decision.target_set")] == [(LEAD1.id, T), (LEAD2.id, "dlp.web")]


def test_promotion_needs_the_sample_the_agreement_and_a_second_lead(session):
    store = DecisionStore(session)
    store.set_target(T, 90, 40, LEAD1)
    decided(store, 30)
    with pytest.raises(ValueError, match="at least 40"):
        store.propose(T, "recommend", LEAD1)
    decided(store, 10, ai="close_benign", analyst="escalate", start=30)             # 30 of 40 agree: 75 %
    with pytest.raises(ValueError, match="below the target"):
        store.propose(T, "recommend", LEAD1)
    decided(store, 80, start=40)                                                    # 110 of 120: 91.7 %
    for nobody in (ANALYST, SERVICE_LEAD, OTHER_DOMAIN_LEAD):
        with pytest.raises(PermissionError):
            store.propose(T, "recommend", nobody)
    row = store.propose(T, "recommend", LEAD1, reason="agreement held for a month")
    assert row.status == "pending" and store.stage_of(T) == "shadow"                # nothing changes until approved
    with pytest.raises(ValueError, match="already waiting"):
        store.propose(T, "recommend", LEAD2)
    with pytest.raises(PermissionError, match="second lead"):
        store.approve(row.id, LEAD1)
    with pytest.raises(PermissionError, match="second lead"):
        store.approve(row.id, person("Lead.One@Example.com", Role.LEAD))            # the same person, written differently
    for nobody in (ANALYST, SERVICE_LEAD):
        with pytest.raises(PermissionError):
            store.approve(row.id, nobody)
    live = store.approve(row.id, LEAD2)
    assert live.status == "active" and store.stage_of(T) == "recommend"
    assert store.stage_of("dlp.web") == "shadow"                                    # each type climbs on its own
    assert live.baseline["sample"] == 120 and live.baseline["agreement_percent"] == 91.7 and live.baseline["mix"]
    promoted = events(session, "decision.promoted")
    assert len(promoted) == 1 and promoted[0].actor_id == LEAD2.id and promoted[0].payload["proposed_by"] == LEAD1.id
    with pytest.raises(ValueError, match="not waiting"):
        store.approve(row.id, LEAD2)
    with pytest.raises(KeyError):
        store.approve(10**6, LEAD2)


def test_agreement_is_measured_again_when_the_second_lead_approves(session):
    store = DecisionStore(session)
    store.set_target(T, 90, 20, LEAD1)
    decided(store, 20)
    row = store.propose(T, "recommend", LEAD1)
    decided(store, 20, analyst="escalate", start=20)                                # it slipped while waiting: 50 %
    with pytest.raises(ValueError, match="no longer ready"):
        store.approve(row.id, LEAD2)
    assert store.stage_of(T) == "shadow"
    assert store.reject(row.id, LEAD2, reason="quality slipped").status == "rejected"
    assert events(session, "decision.promotion_rejected")[0].payload["reason"] == "quality slipped"


def test_the_decide_stage_is_refused_in_this_version_whatever_was_measured(session):
    store = DecisionStore(session)
    store.set_target(T, 50, 20, LEAD1)
    decided(store, 200)
    assert "decide" in STAGES and "decide" not in AVAILABLE_STAGES
    with pytest.raises(ValueError, match="not available"):
        store.propose(T, "decide", LEAD1)
    store.approve(store.propose(T, "recommend", LEAD1).id, LEAD2)
    ev = next(e for e in store.evaluate() if e["decision_type"] == T)
    assert ev["stage"] == "recommend" and ev["next_stage"] == "decide" and not ev["eligible"]
    assert "not available" in ev["blocked_by"]
    with pytest.raises(ValueError, match="not available"):
        store.propose(T, "decide", LEAD1)
    with pytest.raises(ValueError):
        store.propose(T, "autopilot", LEAD1)


def test_a_lead_demotes_alone_and_at_once(session):
    store = DecisionStore(session)
    store.set_target(T, 90, 20, LEAD1)
    decided(store, 20)
    store.approve(store.propose(T, "recommend", LEAD1).id, LEAD2)
    with pytest.raises(PermissionError):
        store.propose(T, "shadow", ANALYST)
    row = store.propose(T, "shadow", LEAD1, reason="new rule set in the DLP tool")
    assert row.status == "active" and store.stage_of(T) == "shadow"
    assert events(session, "decision.demoted")[0].payload["reason"] == "new rule set in the DLP tool"
    with pytest.raises(ValueError, match="already at"):
        store.propose(T, "shadow", LEAD1)


def test_falling_agreement_demotes_without_a_person(session):
    store = DecisionStore(session)
    store.set_target(T, 90, DRIFT_MIN_SAMPLE, LEAD1)
    decided(store, DRIFT_MIN_SAMPLE)
    store.approve(store.propose(T, "recommend", LEAD1).id, LEAD2)
    decided(store, DRIFT_MIN_SAMPLE - 1, analyst="escalate", start=100)
    assert store.check_drift() == []                                                # too few decided since the promotion
    decided(store, 1, analyst="escalate", start=500)
    out = store.check_drift()
    assert [(d["decision_type"], d["from"], d["to"]) for d in out] == [(T, "recommend", "shadow")]
    assert "agreement with analysts fell to 0.0%" in out[0]["reason"] and store.stage_of(T) == "shadow"
    ev = events(session, "decision.demoted")
    assert len(ev) == 1 and ev[0].actor_type == "agent" and ev[0].payload["stage"] == "shadow"
    assert store.check_drift() == []                                                # already down: nothing more to do


def test_a_shift_in_what_the_ai_decides_demotes_even_while_it_agrees(session):
    store = DecisionStore(session)
    store.set_target(T, 80, DRIFT_MIN_SAMPLE, LEAD1)
    decided(store, 2 * DRIFT_MIN_SAMPLE)                                            # promoted on a mix of closures only
    store.approve(store.propose(T, "recommend", LEAD1).id, LEAD2)
    decided(store, DRIFT_MIN_SAMPLE, start=100)
    assert store.check_drift() == []                                                # same mix, same agreement
    decided(store, DRIFT_MIN_SAMPLE, ai="escalate", analyst="escalate", computed="escalate", start=200)
    out = store.check_drift()                                                       # it still agrees - on other things
    assert len(out) == 1 and "mix of its outcomes shifted" in out[0]["reason"] and store.stage_of(T) == "shadow"
    assert psi({"close_benign": 1.0}, {"escalate": 1.0}) > PSI_LIMIT > psi({"close_benign": 9, "escalate": 1}, {"close_benign": 8, "escalate": 2})


def test_the_same_item_on_the_same_evidence_is_one_decision_and_new_evidence_is_a_new_one(session):
    store = DecisionStore(session)
    kw = {"ai_outcome": "escalate", "ai_source": "model", "computed_outcome": "review", "never_auto": [],
          "prompt_version": "p1", "model": "m"}
    a = store.record(T, "dlp_alert", "x", evidence_hash="h1", **kw)
    assert store.record(T, "dlp_alert", "x", evidence_hash="h1", **(kw | {"ai_outcome": "close_benign"})).id == a.id
    b = store.record(T, "dlp_alert", "x", evidence_hash="h2", **(kw | {"ai_outcome": "close_benign"}))
    assert b.id != a.id and store.latest("dlp_alert", ["x"])["x"].id == b.id
    assert len(events(session, "decision.recorded")) == 2
    store.set_analyst("dlp_alert", "x", "escalate", "platform")
    assert {r.analyst_outcome for r in session.execute(select(AiDecision)).scalars()} == {"escalate"}
    m = next(e for e in store.evaluate() if e["decision_type"] == T)
    assert (m["sample"], m["agreement_percent"], m["ai_closed_what_analysts_escalated"]) == (1, 0.0, 1)   # the newest counts
    with pytest.raises(ValueError):
        store.set_analyst("dlp_alert", "x", "maybe", "platform")
    with pytest.raises(KeyError):
        store.record("dlp.nothing", "dlp_alert", "y", evidence_hash="h", **kw)
    odd = store.record(T, "dlp_alert", "z", evidence_hash="h", **(kw | {"ai_outcome": "delete"}))
    assert odd.ai_outcome is None and odd.effective_outcome is None
