"""Adjustable Dome Score weights: a checked document, previewed, proposed with a reason, approved by a second lead,
audited; the score follows the weights in force and can be recomputed from them."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import AuditRecord
from soc_platform.intelligence.posture import posture, snapshot
from soc_platform.intelligence.posture_weights import DEFAULT, WeightsStore, clean
from soc_platform.tests.conftest import person
from soc_platform.tests.test_controls_posture import HEALTH, load
from soc_platform.tests.test_dlp import service
from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture

LEAD1, LEAD2 = person("lead.one@example.com", Role.LEAD), person("lead.two@example.com", Role.LEAD)
ANALYST = person("ann@example.com", Role.ANALYST)
DLP_LEAD = Principal("dl@example.com", "dl", frozenset({Role.LEAD}), domains=frozenset({"dlp"}))
AUTO = person("max@example.com", Role.AUTOMATION_ADMIN)


@pytest.fixture()
def world(session):
    svc = service(session)
    svc.ingest()
    load(session, HEALTH)
    svc.process()


def recompute(p: dict) -> int:
    W = p["weights"]
    m = [d for d in p["domains"] if d["measured"] and W[d["id"]] > 0]
    mean = sum(W[d["id"]] * d["score"] for d in m) / sum(W[d["id"]] for d in m)
    return round(max(0.0, min(100.0, mean + sum(f["effect"] for f in p["penalties"]))))


@pytest.mark.parametrize("doc,msg", [
    ({"weights": {"identity": -1}}, "between"), ({"weights": {"identity": 1.5}}, "whole"),
    ({"weights": {"identity": True}}, "whole"), ({"weights": {"crypto": 10}}, "unknown domain"),
    ({"weights": dict.fromkeys(DEFAULT["weights"], 0)}, "at least one"),
    ({"penalties": {"critical_case": {"points": 99}}}, "between"), ({"penalties": {"bonus": {}}}, "unknown penalty"),
    ({"penalties": {"critical_case": {"weight": 1}}}, "points and cap"), ({"extra": 1}, "unknown part"), ([], "object")])
def test_only_a_well_formed_document_is_accepted(doc, msg):
    with pytest.raises(ValueError, match=msg):
        clean(doc)
    assert clean({"weights": {"web": 0}})["weights"]["identity"] == DEFAULT["weights"]["identity"]   # the rest: the draft


def test_the_score_follows_the_weights_and_is_recomputable(world, session):
    p = posture(session)
    assert p["weights"] == DEFAULT["weights"] and p["weights_version"] is None and "draft" in p["weights_status"]
    assert p["score"] == recompute(p)
    only_endpoint = clean({"weights": {"identity": 0, "privileged_access": 0, "data_protection": 0, "web": 0, "endpoint": 50}})
    q = posture(session, config=only_endpoint)
    ep = next(d for d in q["domains"] if d["id"] == "endpoint")
    assert q["score"] == recompute(q) == round(max(0.0, ep["score"] + sum(f["effect"] for f in q["penalties"])))
    assert {lv["domain"] for lv in q["levers"]} <= {"Endpoint", "Whole score"}             # weight 0: not a lever
    assert next(d for d in q["domains"] if d["id"] == "identity").get("note", "").startswith("weight 0")
    no_pen = clean({"penalties": {k: {"points": 0} for k in DEFAULT["penalties"]}})
    r = posture(session, config=no_pen)
    assert all(f["effect"] == 0 for f in r["penalties"]) and r["score"] >= p["score"]


def test_two_leads_change_the_weights_and_every_step_is_audited(world, session):
    st = WeightsStore(session)
    doc = {"weights": {"data_protection": 40, "web": 0}}
    for nobody in (ANALYST, DLP_LEAD):
        with pytest.raises(PermissionError):
            st.propose(nobody, doc, "x")
    with pytest.raises(ValueError, match="why"):
        st.propose(LEAD1, doc, "  ")
    with pytest.raises(ValueError, match="in force"):
        st.propose(LEAD1, {}, "no change")
    row = st.propose(AUTO, doc, "data protection matters most for an asset manager")
    assert row.preview["proposed"]["score"] == posture(session, config=clean(doc))["score"]
    assert posture(session)["weights"] == DEFAULT["weights"]                               # not in force yet
    with pytest.raises(ValueError, match="already waiting"):
        st.propose(LEAD1, doc, "again")
    with pytest.raises(PermissionError):
        st.approve(row.id, AUTO)                                                            # cannot approve at all
    with pytest.raises(PermissionError, match="second person"):
        st.approve(row.id, person("MAX@example.com", Role.LEAD))                            # the proposer, any case
    st.approve(row.id, LEAD2, "agreed with the CISO")
    p = posture(session)
    assert p["weights"]["data_protection"] == 40 and p["weights"]["web"] == 0 and p["weights_version"] == row.id
    assert p["weights_status"] == f"agreed - version {row.id}" and p["score"] == recompute(p)
    snap = snapshot(session)
    assert snap["score"] == p["score"]
    row2 = st.propose(LEAD1, {"weights": {"identity": 30}}, "identity first")
    with pytest.raises(ValueError, match="say why"):
        st.reject(row2.id, LEAD2, "")
    assert st.reject(row2.id, LEAD1, "").status == "withdrawn"
    events = [e.event_type for e in session.execute(select(AuditRecord).where(
        AuditRecord.subject_type == "posture_weights").order_by(AuditRecord.seq)).scalars()]
    assert events == ["posture.weights_proposed", "posture.weights_approved", "posture.weights_proposed",
                      "posture.weights_withdrawn"]


def test_the_api_previews_proposes_and_approves(client):  # noqa: F811
    lead1, lead2, analyst = tok(client, "lead.one", "lead"), tok(client, "lead.two", "lead"), tok(client, "ann", "analyst")
    client.post("/api/v1/dlp/run", headers=lead1)
    body = {"document": {"weights": {"endpoint": 35}}, "reason": "EDR first"}
    pv = client.post("/api/v1/posture/weights/preview", headers=analyst, json=body).json()
    assert pv["document"]["weights"]["endpoint"] == 35
    assert client.post("/api/v1/posture/weights/preview", headers=analyst,
                       json={"document": {"weights": {"endpoint": 500}}}).status_code == 400
    assert client.post("/api/v1/posture/weights", headers=analyst, json=body).status_code == 403
    row = client.post("/api/v1/posture/weights", headers=lead1, json=body).json()
    assert client.post(f"/api/v1/posture/weights/{row['id']}/approve", headers=lead1, json={}).status_code == 403
    assert client.post(f"/api/v1/posture/weights/{row['id']}/approve", headers=lead2, json={}).json()["status"] == "active"
    assert client.get("/api/v1/dashboard/posture", headers=lead1).json()["weights"]["endpoint"] == 35
    assert client.get("/api/v1/posture/weights", headers=analyst).json()["source"]["version"] == row["id"]
    assert client.post("/api/v1/posture/weights/999999/approve", headers=lead2, json={}).status_code == 404
    assert client.post(f"/api/v1/posture/weights/{row['id']}/frob", headers=lead2, json={}).status_code == 404
