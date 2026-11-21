"""The CISO view: what would raise the Dome Score most and why it moved are computed from the score's own factors, the
DLP week and the people to look at come from the alerts, governance from the audit chain and the approvals, and the
plain-words brief states only computed figures (the model's version cites them)."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from sqlalchemy import select

from soc_platform.config import get_settings
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.audit import AuditLog
from soc_platform.domains.dlp.models import DlpAlert
from soc_platform.intelligence.ciso import ciso, evidence, explain, health_tools
from soc_platform.intelligence.models import PostureSnapshot
from soc_platform.intelligence.posture import WEIGHTS, posture
from soc_platform.reporting import builder
from soc_platform.tests.test_controls_posture import HEALTH, load
from soc_platform.tests.test_dlp import service
from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture


@pytest.fixture()
def world(session):
    svc = service(session)
    svc.ingest()
    load(session, HEALTH)
    svc.process()
    return svc


def doc(session) -> dict:
    reg = ConnectorRegistry.all_fake()
    return ciso(session, reg, health_tools=health_tools(reg.enabled_names()), settings=get_settings(), model_on=False)


def test_what_raises_the_score_most_is_each_reduction_weighted_by_its_domains_share(world, session):
    p = posture(session)
    measured = [d for d in p["domains"] if d["measured"]]
    total = sum(WEIGHTS[d["id"]] for d in measured)
    expected = sorted([round(-f["effect"] * WEIGHTS[d["id"]] / total, 1) for d in measured for f in d["factors"]
                       if (f["effect"] or 0) < 0] + [-f["effect"] for f in p["penalties"] if f["effect"]], reverse=True)
    assert [lv["gain"] for lv in p["levers"]] == expected
    assert all(lv["action"] and lv["link"].startswith("#/") for lv in p["levers"])
    dp = next(d for d in p["domains"] if d["id"] == "data_protection")
    assert dp["score"] == round(100 + sum(f["effect"] for f in dp["factors"]), 1)        # the factors add up to it
    assert p["band"] == ("strong" if p["score"] >= 85 else "fair" if p["score"] >= 70 else "weak" if p["score"] >= 50 else "poor")


def test_why_the_score_moved_is_computed_against_the_oldest_stored_day(world, session):
    d0 = doc(session)
    assert d0["posture"]["movement"] is None                                        # nothing stored yet: nothing claimed
    p = d0["posture"]
    earlier = {d["id"]: (d["score"] + 10 if d["id"] == "data_protection" else d["score"]) for d in p["domains"]}
    session.add(PostureSnapshot(day="2000-01-01", score=p["score"] + 5, document={"domains": earlier}))
    from soc_platform.core.models import utcnow

    day = (utcnow() - timedelta(days=3)).strftime("%Y-%m-%d")
    session.add(PostureSnapshot(day=day, score=p["score"] + 5, document={"domains": earlier}))
    session.flush()
    mv = doc(session)["posture"]["movement"]
    total = sum(WEIGHTS[d["id"]] for d in p["domains"] if d["measured"])
    assert mv["since"] == day and mv["change"] == -5                                # the 30-day window, not year 2000
    top = mv["domains"][0]
    assert top["id"] == "data_protection" and top["change"] == -10 and top["contribution"] == round(-10 * 25 / total, 1)
    assert mv["other"] == round(-5 - sum(r["contribution"] or 0 for r in mv["domains"]), 1)


def test_the_dlp_week_and_the_people_to_look_at_come_from_the_alerts(world, session):
    d = doc(session)["dlp"]
    rows = list(session.execute(select(DlpAlert)).scalars())
    w = d["week"]
    newest = max(a.event_time for a in rows)
    recent = [a for a in rows if a.event_time > newest - timedelta(days=7)]          # the week up to the newest alert
    assert w["alerts"] == len(recent) and w["previous"] == sum(
        newest - timedelta(days=14) < a.event_time <= newest - timedelta(days=7) for a in rows)
    assert w["needs_a_person"] == sum(a.computed_outcome != "close_benign" for a in recent)
    assert sum(w["by_channel"].values()) == w["alerts"]
    esc = [a for a in rows if a.computed_outcome == "escalate" and a.user_entity_id]
    assert sum(p["escalated"] for p in d["people"]) <= len(esc) and d["people"]
    assert [p["escalated"] for p in d["people"]] == sorted((p["escalated"] for p in d["people"]), reverse=True)


def test_governance_shows_the_audit_chain_as_last_verified(world, session):
    g = doc(session)["governance"]
    assert g["audit"]["verified"] is None and g["audit"]["events"] > 0              # never claimed before a check
    v = AuditLog(session).verify()
    AuditLog(session).save_checkpoint(v)
    g = doc(session)["governance"]
    assert g["audit"]["verified"] is True and g["audit"]["verified_up_to"] == v["head_seq"]
    assert g["model"] == "off" and g["kill_switch"] is False


def test_the_brief_states_only_computed_figures(world, session):
    d = doc(session)
    ev = evidence(d)
    b = explain(d, None)
    assert b["source"] == "deterministic" and b["summary"].startswith("The Dome Score is")
    allowed = " ".join(e["claim"] for e in ev)
    for n in re.findall(r"\d+(?:\.\d+)?", b["summary"] + " ".join(c["text"] for c in b["claims"])):
        assert n in allowed
    assert {i for c in b["claims"] for i in c["evidence_ids"]} <= {e["id"] for e in ev}

    class Model:                                       # the gateway's guardrail is tested elsewhere; here: it is used
        def grounded(self, workflow, question, evidence, **kw):
            assert workflow == "posture.explain" and evidence == ev
            return {"summary": "Posture is weak.", "claims": [{"text": "Score is weak.", "evidence_ids": ["P1"]}],
                    "source": "llm", "grounded": True}

    assert explain(d, Model())["summary"] == "Posture is weak."

    class Down:
        def grounded(self, *a, **kw):
            return {"summary": "", "claims": [], "source": "deterministic"}

    assert explain(d, Down())["summary"] == b["summary"]                            # a failing model reads like none


def test_the_cyberdome_reports_are_built_from_the_same_figures(world, session, tmp_path):
    d = doc(session)
    for tid in ("cyberdome_ciso_weekly", "cyberdome_board_monthly"):
        rep = builder.build_report(session, ConnectorRegistry.all_fake(), {"id": tid, **builder.STANDARD[tid]}, tmp_path,
                                   llm=None, by="agent:test")
        assert not rep["skipped"] and rep["format"] == builder.STANDARD[tid]["format"]
        posture_facts = dict(next(s for s in rep["sections"] if s["source"] == "posture")["facts"])
        assert posture_facts["Dome Score"] == str(d["posture"]["score"])


def test_the_ciso_screen_needs_all_domain_access_and_matches_the_screens_behind_it(client):  # noqa: F811
    lead, dlp_only = tok(client, "lena", "lead"), tok(client, "dana", "analyst", "dlp")
    client.post("/api/v1/dlp/run", headers=lead)
    for path in ("/api/v1/dashboard/ciso",):
        assert client.get(path, headers=dlp_only).status_code == 403
    assert client.post("/api/v1/dashboard/ciso/explain", headers=dlp_only).status_code == 403
    d = client.get("/api/v1/dashboard/ciso", headers=lead).json()
    p = client.get("/api/v1/dashboard/posture", headers=lead).json()
    assert d["posture"]["score"] == p["score"] and d["posture"]["levers"] == p["levers"]
    assert d["brief"]["source"] == "deterministic" and d["brief"]["summary"]
    ex = client.post("/api/v1/dashboard/ciso/explain", headers=lead).json()
    assert ex["summary"] == d["brief"]["summary"]                                    # no model configured: the same text
