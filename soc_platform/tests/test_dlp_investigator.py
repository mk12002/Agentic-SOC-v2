"""The AI investigator: the model picks read-only look-ups from a fixed menu within a budget; anything else it names is
dropped; without the model the platform picks them; findings are cited and never change a computed outcome."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.models import AuditRecord, Entity
from soc_platform.domains.dlp import investigator as inv
from soc_platform.domains.dlp.models import DlpAlert
from soc_platform.tests.test_dlp import alerts, service, the


class Planner:
    """A stand-in model: answers each round from a list, records what it was shown."""

    def __init__(self, *rounds, decide=None):
        self.rounds, self.prompts, self.decide = list(rounds), [], decide

    def complete_json(self, workflow, system, user, **kw):
        self.prompts.append((workflow, user))
        if workflow == inv.PLAN_WORKFLOW:
            r = self.rounds.pop(0) if self.rounds else {"lookups": [], "done": True}
            if isinstance(r, Exception):
                raise r
            return r
        return self.decide(user) if self.decide else None


@pytest.fixture()
def world(session):
    from soc_platform.domains.incident.service import IncidentService

    svc = service(session)
    svc.sync_inventory()
    IncidentService(session, ConnectorRegistry.all_fake()).ingest()       # endpoint alerts and deception hits
    svc.ingest()
    svc.process()
    return svc


def worst(session) -> DlpAlert:
    return the(session, "escalate", destination_class="personal_mail", bulk=True)


def test_without_the_model_the_platform_runs_its_own_checks_and_cites_every_finding(world, session):
    a = worst(session)
    before = (a.computed_outcome, a.severity, a.never_auto, list(a.evidence), a.status)
    rec = world.investigate(a)
    assert rec["planned_by"] == "rules" and rec["model"] is None
    assert [s["lookup"] for s in rec["steps"]] == inv.rule_plan(a) and len(rec["steps"]) <= inv.MAX_STEPS
    assert [f["id"] for f in rec["findings"]] == [f"I{i + 1}" for i in range(len(rec["findings"]))]
    assert all(f["claim"] and f["source"] for f in rec["findings"])
    assert {i for s in rec["steps"] for i in s["findings"]} == {f["id"] for f in rec["findings"]}
    text = " ".join(f["claim"] for f in rec["findings"])
    assert "high" in text and "unmanaged device" in text                       # the risky sign-in before the alert
    assert "deception hit" in text                                             # what the endpoint tools saw on the laptop
    assert (a.computed_outcome, a.severity, a.never_auto, list(a.evidence), a.status) == before
    audit = session.execute(select(AuditRecord).where(AuditRecord.event_type == "dlp.investigated")).scalars().one()
    assert audit.payload["planned_by"] == "rules" and audit.payload["findings"] == len(rec["findings"])


def test_look_ups_only_read(world, session, monkeypatch):
    """No look-up reaches a tool: every connector's transport is replaced by one that fails the test if called."""
    called = []
    reg = world.registry
    for name in reg.enabled_names():
        conn = reg.get(name)
        monkeypatch.setattr(conn.http, "request", lambda *a, _n=name, **k: called.append(_n))
    flushed = []
    monkeypatch.setattr(session, "commit", lambda: flushed.append(1))
    world.llm = Planner({"lookups": [{"name": n} for n in inv.MENU], "done": True})
    for a in alerts(session):
        world.investigate(a)
    assert called == [] and flushed == []


def test_the_model_chooses_from_the_menu_and_everything_else_is_dropped(world, session):
    a = worst(session)
    world.llm = Planner(
        {"lookups": [{"name": "sign_in_history", "why": "risky sign-in?"}, {"name": "https://evil.example/x"},
                     {"name": "delete_mailbox"}, "device_alerts", {"name": "sign_in_history"}, {"name": ["x"]}],
         "done": False},
        {"lookups": [{"name": "privileged_access"}, {"name": "open_cases"}, {"name": "watch_lists"},
                     {"name": "sender_history"}], "done": True})
    rounds = []
    rec = inv.investigate(world, a, untrusted=world._untrusted(session.get(Entity, a.event_id)),
                          between_rounds=lambda: rounds.append(1))
    assert rec["planned_by"] == "model"
    assert [s["lookup"] for s in rec["steps"]] == ["sign_in_history", "device_alerts", "privileged_access", "open_cases",
                                                   "watch_lists"]                     # five: the step budget
    assert rec["steps"][0]["why"] == "risky sign-in?" and all(s["chosen_by"] == "model" for s in rec["steps"])
    assert any("not on the menu" in n for n in rec["notes"]) and "step budget reached" in rec["notes"]
    assert rounds == [1, 1]                                                         # saved between the model's rounds
    second = world.llm.prompts[1][1]
    assert "FINDINGS SO FAR" in second and "[I1]" in second and "sign_in_history" not in second.split("MENU")[1]


def test_the_second_round_is_skipped_when_the_model_is_done(world, session):
    a = worst(session)
    world.llm = Planner({"lookups": [{"name": "sender_history"}], "done": True}, {"lookups": [{"name": "open_cases"}]})
    rec = world.investigate(a)
    assert [s["lookup"] for s in rec["steps"]] == ["sender_history"] and len(world.llm.prompts) == 1


@pytest.mark.parametrize("answer", [None, "not json", {"lookups": "everything"}, {"lookups": [{"name": "rm -rf"}]},
                                    "refuse"])
def test_a_useless_or_refused_plan_falls_back_to_the_platforms_own(world, session, answer):
    from soc_platform.llm.gateway import BudgetExceeded

    a = worst(session)
    world.llm = Planner(BudgetExceeded("budget") if answer == "refuse" else answer)
    rec = world.investigate(a)
    assert rec["planned_by"] == "rules" and [s["lookup"] for s in rec["steps"]] == inv.rule_plan(a)
    if answer == "refuse":
        assert "the model was not used (AI usage policy)" in rec["notes"]


def test_the_time_budget_stops_the_look_ups(world, session, monkeypatch):
    a = worst(session)
    clock = iter(range(0, 1000, 15))                  # every reading of the clock is 15 s later
    monkeypatch.setattr(inv.time, "monotonic", lambda: float(next(clock)))
    monkeypatch.setenv("SOC_DLP_INVESTIGATION_SECONDS", "20")
    rec = world.investigate(a)
    assert 0 < len(rec["steps"]) < len(inv.rule_plan(a)) and any("time budget" in n for n in rec["notes"])


def test_the_sender_text_reaches_the_planner_only_inside_the_fence(world, session):
    a = worst(session)
    world.llm = Planner({"lookups": [], "done": True})
    world.investigate(a)
    _, user = world.llm.prompts[0]
    subject = session.get(Entity, a.event_id).attributes["subject"]
    assert user.count("<<<") == 1 and subject in user.split("<<<")[1].split(">>>")[0]


def test_the_ai_decision_may_cite_the_findings_and_is_asked_again_after_an_investigation(world, session):
    a = worst(session)
    world.llm = Planner({"lookups": [{"name": "sign_in_history"}], "done": True},
                        decide=lambda user: {"outcome": "escalate", "reasons": [
                            {"text": "a risky sign-in came first", "evidence_ids": ["I1"]},
                            {"text": "invented", "evidence_ids": ["I999"]}]})
    session.commit()
    assert world.investigate_committing(world.investigate_pending()) == len(alerts(session))
    assert world.investigate_pending() == []                                       # each alert once
    d = world.ai_decide(a)
    assert d.reasons == [{"text": "a risky sign-in came first", "evidence_ids": ["I1"]}]
    assert d.evidence_hash == a.evidence_hash and "INVESTIGATION FINDINGS" in world.llm.prompts[-1][1]
    world.llm.rounds = [{"lookups": [{"name": "open_cases"}], "done": True}]
    world.investigate(a)                                                           # new findings: a new decision is due
    assert a.id in world.ai_pending()


def test_every_alert_can_be_investigated_on_every_kind_of_record(world, session):
    for a in alerts(session):
        rec = world.investigate(a)
        assert rec["steps"] and rec["findings"] and {s["lookup"] for s in rec["steps"]} <= set(inv.usable(a))
    no_user = DlpAlert(source_ref="x:y", event_id=alerts(session)[0].event_id, tool="t", decision_type="dlp.other",
                       event_time=alerts(session)[0].event_time, computed_outcome="review", facts={}, evidence=[])
    assert inv.usable(no_user) == ["open_cases", "watch_lists"]
