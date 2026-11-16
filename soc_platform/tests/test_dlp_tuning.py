"""DLP rule-change proposals: suggested from analysts' rulings, previewed on past alerts, approved by a second lead,
refused when they would hide what must never be hidden, made by an engineer in the tool, and checked afterwards."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import AuditRecord
from soc_platform.domains.dlp.models import DlpAlert
from soc_platform.domains.dlp.tuning import DlpTuning, clean, preview, suggestions
from soc_platform.intelligence.config_snapshots import ConfigSnapshots
from soc_platform.tests.conftest import person
from soc_platform.tests.test_config_snapshots import change_rules
from soc_platform.tests.test_dlp import ANALYST, alerts, service, the
from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture

LEAD1, LEAD2 = person("lead.one@example.com", Role.LEAD), person("lead.two@example.com", Role.LEAD)
ENGINEER = person("eng@example.com", Role.AUTOMATION_ADMIN)
VM_LEAD = Principal("vm.lead@example.com", "vm", frozenset({Role.LEAD}), domains=frozenset({"vulnerability"}))
SERVICE_LEAD = Principal("svc", "svc", frozenset({Role.LEAD}), is_service=True)


@pytest.fixture()
def world(session):
    svc = service(session)
    svc.ingest()
    svc.process()
    return svc


def noisy(session) -> DlpAlert:
    """The rule analysts keep closing: the sample data's partner remittances (found by its rulings, not its name)."""
    return next(a for a in alerts(session) if a.analyst_source == "tool" and a.analyst_outcome == "close_benign")


def test_the_noisy_rule_gets_a_suggestion_with_its_evidence_and_preview(world, session):
    rule = noisy(session)
    sug = suggestions(session)
    assert [s["rule"] for s in sug] == [rule.rule]
    s = sug[0]
    assert s["kind"] == "exclude_destination" and s["params"] == {"destination": rule.destination_domain}
    rows = [a for a in alerts(session) if a.rule == rule.rule]
    pv = s["preview"]
    assert pv["allowed"] and pv["hidden"] == pv["rule_alerts"] == len(rows)
    assert pv["hidden_closed_benign"] == sum(a.analyst_outcome == "close_benign" for a in rows) and pv["hidden_escalated"] == 0
    assert pv["hidden_undecided"] == sum(a.analyst_outcome is None for a in rows) > 0
    assert s["evidence"]["decided"] == pv["hidden_closed_benign"] and str(s["evidence"]["decided"]) in s["reason"]


def test_a_change_that_would_hide_what_must_be_seen_is_refused(world, session):
    worst = the(session, "escalate", destination_class="personal_mail", bulk=True)
    pv = preview(session, worst.rule, "raise_threshold", {"min_matches": 100_000})
    assert not pv["allowed"] and {"high or critical", "personal data in bulk", "never-automatic"} <= {
        w for b in pv["blocked_by"] for w in ("high or critical", "personal data in bulk", "never-automatic") if w in b}
    with pytest.raises(ValueError, match="refused"):
        DlpTuning(session).propose(LEAD1, rule=worst.rule, kind="raise_threshold", params={"min_matches": 100_000}, reason="x")
    quiet = noisy(session)
    nothing = preview(session, quiet.rule, "exclude_destination", {"destination": "nowhere.example"})
    assert not nothing["allowed"] and "hidden no alert" in nothing["blocked_by"][0]
    # an analyst escalating one of the alerts makes the same change unsafe
    target = next(a for a in alerts(session) if a.rule == quiet.rule and a.analyst_outcome is None)
    world.decide(target.id, ANALYST, outcome="escalate", reason="this one was real")
    again = preview(session, quiet.rule, "exclude_destination", {"destination": quiet.destination_domain})
    assert not again["allowed"] and "1 alert(s) an analyst escalated" in again["blocked_by"][0]
    assert suggestions(session) == []                                  # and it is no longer suggested


@pytest.mark.parametrize("kind,params", [("exclude_destination", {"destination": "not a domain"}),
                                         ("exclude_destination", {"destination": "https://x.example/a"}),
                                         ("raise_threshold", {"min_matches": 1}), ("raise_threshold", {"min_matches": "5"}),
                                         ("raise_threshold", {"min_matches": True}), ("delete_rule", {})])
def test_only_the_fixed_shapes_of_change_are_accepted(kind, params):
    with pytest.raises(ValueError):
        clean(kind, params)


def test_two_leads_an_engineer_and_a_check_that_it_took_effect(world, session):
    rule = noisy(session)
    t = DlpTuning(session)
    s = suggestions(session)[0]
    for nobody in (ANALYST, VM_LEAD, SERVICE_LEAD, ENGINEER):
        with pytest.raises(PermissionError):
            t.propose(nobody, rule=s["rule"], kind=s["kind"], params=s["params"], reason=s["reason"])
    with pytest.raises(ValueError, match="unknown rule"):
        t.propose(LEAD1, rule="Made up rule", kind=s["kind"], params=s["params"], reason="x")
    row = t.propose(LEAD1, rule=s["rule"], kind=s["kind"], params=s["params"], reason=s["reason"], drafted_by="suggestion")
    assert row.status == "proposed" and row.preview["hidden"] == s["preview"]["hidden"] and suggestions(session) == []
    with pytest.raises(ValueError, match="already proposed"):
        t.propose(LEAD2, rule=s["rule"], kind=s["kind"], params=s["params"], reason="again")
    with pytest.raises(PermissionError, match="second lead"):
        t.approve(row.id, person("Lead.One@Example.com", Role.LEAD))
    with pytest.raises(ValueError, match="only an approved"):
        t.mark_applied(row.id, ENGINEER, "CHG-1")
    assert t.approve(row.id, LEAD2, "fine").status == "approved"
    with pytest.raises(PermissionError):
        t.mark_applied(row.id, LEAD2, "CHG-1")                         # leads approve; engineers make the change
    cfg = ConfigSnapshots(session, world.registry)
    assert t.mark_applied(row.id, ENGINEER, "CHG-1042").status == "applied"
    assert t.verify(row)["configuration"] == "no configuration snapshot since the change was recorded"
    cfg.take("forcepoint_dlp", reason="manual", by=ENGINEER.id)
    assert t.verify(row)["configuration"] == "the configuration does not show the exclusion"
    change_rules(cfg, lambda items: next(i for i in items if i["name"] == rule.rule)["excluded_destinations"].append(
        rule.destination_domain))
    cfg.take("forcepoint_dlp", reason="manual", by=ENGINEER.id)
    v = t.verify(row)
    assert v == {"configuration": "confirmed in the tool's configuration", "confirmed": True, "snapshot": v["snapshot"],
                 "matching_alerts_since": 0}
    events = [e.event_type for e in session.execute(select(AuditRecord).where(
        AuditRecord.subject_type == "dlp_rule_proposal").order_by(AuditRecord.seq)).scalars()]
    assert events == ["dlp.rule_change_proposed", "dlp.rule_change_approved", "dlp.rule_change_applied"]


def test_approval_measures_the_effect_again(world, session):
    rule = noisy(session)
    t = DlpTuning(session)
    row = t.propose(LEAD1, rule=rule.rule, kind="exclude_destination", params={"destination": rule.destination_domain},
                    reason="partner remittances")
    target = next(a for a in alerts(session) if a.rule == rule.rule and a.analyst_outcome is None)
    world.decide(target.id, ANALYST, outcome="escalate", reason="real this time")
    with pytest.raises(ValueError, match="no longer allowed"):
        t.approve(row.id, LEAD2)
    with pytest.raises(ValueError, match="reason"):
        t.reject(row.id, LEAD2, "  ")
    assert t.reject(row.id, LEAD2, "an escalation came in").status == "rejected"
    other = t.propose(LEAD1, rule=rule.rule, kind="raise_threshold", params={"min_matches": 2}, reason="x") \
        if preview(session, rule.rule, "raise_threshold", {"min_matches": 2})["allowed"] else None
    if other is not None:
        assert t.reject(other.id, LEAD1, "changed my mind").status == "withdrawn"   # the proposer withdraws


def test_the_api_runs_the_whole_lifecycle(client):  # noqa: F811 - the imported fixture
    lead1, lead2 = tok(client, "lead.one", "lead"), tok(client, "lead.two", "lead")
    eng, analyst = tok(client, "eng", "automation_admin"), tok(client, "dana", "analyst", "dlp")
    assert client.post("/api/v1/dlp/run", headers=lead1).status_code == 200
    view = client.get("/api/v1/dlp/tuning", headers=analyst).json()
    s = view["suggestions"][0]
    body = {"rule": s["rule"], "kind": s["kind"], "params": s["params"], "reason": s["reason"], "drafted_by": "suggestion"}
    assert client.post("/api/v1/dlp/tuning/preview", headers=analyst, json=body).json()["hidden"] == s["preview"]["hidden"]
    assert client.post("/api/v1/dlp/tuning/preview", headers=analyst,
                       json={**body, "params": {"min_matches": 1}, "kind": "raise_threshold"}).status_code == 400
    assert client.post("/api/v1/dlp/tuning", headers=analyst, json=body).status_code == 403
    assert client.post("/api/v1/dlp/tuning", headers=lead1, json={**body, "kind": "drop_rule"}).status_code == 422
    row = client.post("/api/v1/dlp/tuning", headers=lead1, json=body).json()
    assert row["status"] == "proposed" and row["drafted_by"] == "suggestion"
    assert client.post(f"/api/v1/dlp/tuning/{row['id']}/approve", headers=lead1, json={}).status_code == 403
    assert client.post(f"/api/v1/dlp/tuning/{row['id']}/approve", headers=lead2, json={}).json()["status"] == "approved"
    assert client.post(f"/api/v1/dlp/tuning/{row['id']}/applied", headers=lead2, json={"reference": "CHG-1"}).status_code == 403
    assert client.post(f"/api/v1/dlp/tuning/{row['id']}/applied", headers=eng, json={}).status_code == 400
    done = client.post(f"/api/v1/dlp/tuning/{row['id']}/applied", headers=eng, json={"reference": "CHG-1"}).json()
    assert done["status"] == "applied" and done["verification"]["matching_alerts_since"] == 0
    assert client.post(f"/api/v1/dlp/tuning/{row['id']}/frobnicate", headers=lead2, json={}).status_code == 404
    assert client.post("/api/v1/dlp/tuning/999999/approve", headers=lead2, json={}).status_code == 404
    assert client.get("/api/v1/dlp/tuning", headers=tok(client, "pia", "analyst", "phishing")).status_code == 403
