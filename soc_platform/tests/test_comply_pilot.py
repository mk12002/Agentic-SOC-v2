"""Dome Comply (M12) and the pilot scorecard (M13): controls mapped to computed evidence, never "compliant"; the
catalogue is data changed by two people; a person decides reportability and the clocks start then; the AI only
drafts; the pilot's KPIs are measured from the records against a baseline and targets people set."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import timedelta

import pytest
from sqlalchemy import select

from soc_platform.config import get_settings
from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.audit import AuditLog
from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import AuditRecord, utcnow
from soc_platform.domains.dlp.models import DlpAlert
from soc_platform.reporting import pilot
from soc_platform.reporting.breach import BreachAssessments
from soc_platform.reporting.regimes import DRAFT_CATALOGUE, TESTS, CatalogueStore, check_catalogue, evaluate
from soc_platform.tests.conftest import person
from soc_platform.tests.test_controls_posture import HEALTH, load
from soc_platform.tests.test_dlp import service
from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture

LEAD1, LEAD2 = person("lead.one@example.com", Role.LEAD), person("lead.two@example.com", Role.LEAD)
ANALYST = person("ann@example.com", Role.ANALYST)
PHISH_LEAD = Principal("pl@example.com", "pl", frozenset({Role.LEAD}), domains=frozenset({"phishing"}))


@pytest.fixture()
def world(session):
    svc = service(session)
    svc.sync_inventory()
    svc.ingest()
    load(session, HEALTH)
    svc.process()
    return svc


def ev(session):
    return evaluate(session, ConnectorRegistry.all_fake(), get_settings())


# ---------------------------------------------------------------------------------------------- the catalogue


def test_the_draft_catalogue_is_well_formed_and_says_it_is_a_draft():
    doc = check_catalogue(DRAFT_CATALOGUE)
    assert "DRAFT" in doc["note"] and all(c.get("source") for c in doc["clocks"])
    assert all(c["verified"] is False for c in doc["clocks"])                  # no deadline presented as confirmed
    tests = {t for c in doc["controls"] for t in c["tests"]}
    assert {t for t in tests if not t.startswith("platform:")} <= set(TESTS)
    for bad, msg in ((dict(DRAFT_CATALOGUE, controls=[{"id": "A", "title": "t", "regimes": ["NOPE"], "tests": []}]), "regime"),
                     (dict(DRAFT_CATALOGUE, controls=[{"id": "A", "title": "t", "regimes": ["DPDP"], "tests": ["guess"]}]), "unknown test"),
                     (dict(DRAFT_CATALOGUE, clocks=[{"id": "c", "regime": "DPDP", "hours": -1, "source": "s"}]), "hours"),
                     (dict(DRAFT_CATALOGUE, controls=DRAFT_CATALOGUE["controls"][:1] * 2), "twice")):
        with pytest.raises(ValueError, match=msg):
            check_catalogue(bad)


def test_controls_carry_computed_evidence_and_never_claim_compliance(world, session):
    e = ev(session)
    assert "does not state compliance" in e["wording"] and "compliant" not in json.dumps(e["summary"]).lower()
    by = {c["id"]: c for c in e["controls"]}
    assert len(by) == len(DRAFT_CATALOGUE["controls"])
    assert by["DC-01"]["status"] == "fail"                                      # a laptop has no EDR agent
    assert by["DC-02"]["status"] == "fail"                                      # one laptop is not encrypted
    assert by["DC-11"]["status"] == "no_evidence"                               # the chain was never verified
    AuditLog(session).save_checkpoint(AuditLog(session).verify())
    assert {c["id"]: c for c in ev(session)["controls"]}["DC-11"]["status"] == "pass"
    sm = e["summary"]
    assert sm["with_evidence"] == sum(c["current_evidence"] for c in e["controls"])
    assert sm["no_evidence"] == [c["id"] for c in e["controls"] if c["status"] == "no_evidence"]
    for t in (t for c in e["controls"] for t in c["tests"]):
        assert t["status"] in ("pass", "fail", "no_evidence") and t["detail"] and t["as_of"]
    assert e["regimes"]["CERT_IN"]["controls"] == sum("CERT_IN" in c["regimes"] for c in DRAFT_CATALOGUE["controls"])


def test_the_catalogue_is_changed_by_two_people(world, session):
    st = CatalogueStore(session)
    doc = json.loads(json.dumps(DRAFT_CATALOGUE))
    doc["controls"] = doc["controls"][:3]
    doc["clocks"][1]["hours"] = 72
    with pytest.raises(PermissionError):
        st.propose(ANALYST, doc, "x")
    row = st.propose(LEAD1, doc, "NAM's own list, first three areas")
    with pytest.raises(PermissionError, match="second person"):
        st.decide(row.id, LEAD1, approve=True)
    st.decide(row.id, LEAD2, approve=True)
    e = ev(session)
    assert len(e["controls"]) == 3 and e["catalogue"]["version"] == row.id


# ---------------------------------------------------------------------------------------------- reportability


def test_a_person_decides_reportability_and_the_clocks_start_then(world, session):
    ba = BreachAssessments(session)
    n = ba.sync()
    assert n >= 1 and ba.sync() == 0                                             # idempotent
    rows = ba.list()
    personal_cases = {a.case_id for a in session.execute(select(DlpAlert).where(
        DlpAlert.personal_data.is_(True), DlpAlert.case_id.is_not(None))).scalars()}
    assert {r["case_id"] for r in rows} == personal_cases and all(r["status"] == "open" for r in rows)
    aid = rows[0]["id"]
    for nobody in (ANALYST, PHISH_LEAD):
        with pytest.raises(PermissionError):
            ba.decide(aid, nobody, reportable=True, reason="x")
    with pytest.raises(ValueError, match="why"):
        ba.decide(aid, LEAD1, reportable=True, reason=" ")
    with pytest.raises(ValueError, match="reportable"):
        ba.draft(aid, LEAD1, None)                                               # no draft before the decision
    ba.decide(aid, LEAD1, reportable=True, reason="investor PAN data left to a personal mailbox")
    with pytest.raises(ValueError, match="stand"):                              # deciding again would restart the clock
        ba.decide(aid, LEAD1, reportable=False, reason="changed my mind")
    v = {r["id"]: r for r in ba.list()}[aid]
    cert = next(c for c in v["clocks"] if c["id"] == "cert_in_report")
    assert v["status"] == "reportable" and cert["hours"] == 6 and 5.9 < cert["hours_left"] <= 6 and not cert["overdue"]
    assert next(c for c in v["clocks"] if c["id"] == "dpdp_board")["due"] is None   # not set: no deadline invented
    # the clock is computed from the decision: six hours later it is overdue
    row = ba._get(aid)
    row.decided_at = utcnow() - timedelta(hours=7)
    session.flush()
    assert next(c for c in ba.view(row)["clocks"] if c["id"] == "cert_in_report")["overdue"] is True
    ba.draft(aid, LEAD1, None)
    d = ba.view(row)["draft"]
    assert d["source"] == "deterministic" and d["claims"] and "sends nothing" in d["note"]
    subjects = {(a.facts or {}).get("subject") for a in session.execute(select(DlpAlert)).scalars()} - {None}
    assert not any(sub in d["text"] for sub in subjects)                         # message text never enters a draft
    with pytest.raises(ValueError, match="reference"):
        ba.record_report(aid, LEAD1, clock="cert_in_report", reference="")
    for c in v["clocks"]:
        ba.record_report(aid, LEAD1, clock=c["id"], reference=f"REF-{c['id']}")
    assert ba.view(row)["status"] == "reported"
    with pytest.raises(ValueError, match="already"):
        ba.record_report(aid, LEAD1, clock="cert_in_report", reference="again")
    events = [e.event_type for e in session.execute(select(AuditRecord).where(
        AuditRecord.event_type.like("compliance.%"), AuditRecord.subject_id == row.case_id).order_by(AuditRecord.seq)).scalars()]
    assert events[:3] == ["compliance.assessment_opened", "compliance.reportability_decided", "compliance.report_drafted"]


def test_the_ai_draft_cites_the_facts_and_a_failing_model_falls_back(world, session):
    ba = BreachAssessments(session)
    ba.sync()
    aid = ba.list()[0]["id"]
    ba.decide(aid, LEAD1, reportable=True, reason="r")

    class Model:
        def grounded(self, workflow, question, evidence, **kw):
            assert workflow == "compliance.draft" and all(e["id"].startswith("F") for e in evidence)
            return {"summary": "Investor data was sent outside.", "claims": [{"text": "x", "evidence_ids": ["F1"]}],
                    "source": "llm"}

    assert ba.view(ba.draft(aid, LEAD1, Model()))["draft"]["source"] == "llm"

    class Down:
        def grounded(self, *a, **kw):
            return {"summary": "", "claims": [], "source": "deterministic"}

    assert ba.view(ba.draft(aid, LEAD1, Down()))["draft"]["source"] == "deterministic"


def test_the_audit_pack_holds_controls_assessments_catalogue_and_the_trail(world, session, tmp_path):
    from soc_platform.core.blobstore import BlobStore
    from soc_platform.reporting.regimes import pack

    BreachAssessments(session).sync()
    ref, e = pack(session, ConnectorRegistry.all_fake(), get_settings(), str(tmp_path))
    data = BlobStore(session, get_settings()).get(ref)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert {"controls.json", "controls.csv", "assessments.json", "catalogue.json", "audit_log.jsonl", "summary.docx"} <= set(z.namelist())
    assert json.loads(z.read("controls.json"))["summary"] == e["summary"]


# ---------------------------------------------------------------------------------------------- pilot scorecard


def test_the_pilot_kpis_are_measured_from_the_records(world, session):
    m = pilot.measure(session)
    rows = list(session.execute(select(DlpAlert)).scalars())
    newest = max(a.event_time for a in rows)
    week = [a for a in rows if a.event_time > newest - timedelta(days=7)]
    assert m["dlp_reaching_analyst_pct"]["current"] == round(100 * sum(a.computed_outcome != "close_benign" for a in week) / len(week), 1)
    assert m["dlp_alerts_per_day"]["current"] == round(len(week) / 7, 1)
    assert m["model_share_pct"]["current"] == 0.0 and m["outages_found_by_users"]["current"] is None
    sc = pilot.scorecard(session)
    assert all(k["target"] is None for k in sc["kpis"])                          # no target is preset
    assert {k["status"] for k in sc["kpis"]} <= {"no_baseline", "no_data"}
    assert len(sc["ai_agreement"]) == 4 and all(a["target"] is None for a in sc["ai_agreement"])


def test_baseline_target_and_outages_drive_the_status(world, session):
    cur = pilot.measure(session)["dlp_reaching_analyst_pct"]["current"]
    pilot.capture_baseline(session, "dlp_reaching_analyst_pct", by=LEAD1.id)
    pilot.set_figure(session, "dlp_reaching_analyst_pct", "target", round(cur * 0.3, 1), note="70 % fewer", by=LEAD1.id)
    k = {r["id"]: r for r in pilot.scorecard(session)["kpis"]}["dlp_reaching_analyst_pct"]
    assert k["baseline"] == cur and k["status"] == "not_improved" and "captured from the week" in k["baseline_note"]
    pilot.set_figure(session, "dlp_reaching_analyst_pct", "target", 100, note="x", by=LEAD1.id)
    assert {r["id"]: r for r in pilot.scorecard(session)["kpis"]}["dlp_reaching_analyst_pct"]["status"] == "met"
    for bad in (-1, 101, float("nan"), True):
        with pytest.raises(ValueError):
            pilot.set_figure(session, "dlp_reaching_analyst_pct", "target", bad, note="", by=LEAD1.id)
    pilot.log_outage(session, tool="forcepoint_dlp", found_by="users", found_at=None, summary="agents offline", by=ANALYST.id)
    pilot.log_outage(session, tool="trellix_epo", found_by="platform", found_at=None, summary="", by=ANALYST.id)
    o = pilot.measure(session)["outages_found_by_users"]
    assert o["current"] == 1 and o["found_by_platform"] == 1
    with pytest.raises(ValueError):
        pilot.log_outage(session, tool="x", found_by="ghosts", found_at=None, summary="", by=ANALYST.id)
    with pytest.raises(ValueError, match="future"):
        pilot.log_outage(session, tool="trellix_epo", found_by="users", found_at=utcnow() + timedelta(days=1), summary="",
                         by=ANALYST.id)
    with pytest.raises(ValueError, match="400 days"):                       # nor a date long before the pilot
        pilot.log_outage(session, tool="trellix_epo", found_by="users", found_at=utcnow() - timedelta(days=401), summary="",
                         by=ANALYST.id)
    with pytest.raises(ValueError, match="unknown tool"):                   # only a tool the platform knows
        pilot.log_outage(session, tool="<b>x</b>' OR 1=1", found_by="users", found_at=None, summary="", by=ANALYST.id)


def test_the_api_runs_comply_and_the_pilot(client):  # noqa: F811
    lead1, lead2 = tok(client, "lead.one", "lead"), tok(client, "lead.two", "lead")
    analyst, dlp_analyst = tok(client, "ann", "analyst"), tok(client, "dana", "analyst", "dlp")
    auditor = tok(client, "audrey", "auditor")
    client.post("/api/v1/dlp/run", headers=lead1)
    d = client.get("/api/v1/comply", headers=auditor).json()
    assert d["evidence"]["summary"]["controls"] == len(DRAFT_CATALOGUE["controls"]) and d["assessments"]
    assert client.get("/api/v1/comply", headers=dlp_analyst).status_code == 403
    aid = d["assessments"][0]["id"]
    assert client.post(f"/api/v1/comply/assessments/{aid}/decide", headers=analyst, json={"reportable": True, "reason": "x"}).status_code == 403
    assert client.post(f"/api/v1/comply/assessments/{aid}/decide", headers=lead1, json={"reportable": True, "reason": ""}).status_code == 400
    v = client.post(f"/api/v1/comply/assessments/{aid}/decide", headers=lead1, json={"reportable": True, "reason": "PAN out"}).json()
    assert v["status"] == "reportable"
    assert client.post(f"/api/v1/comply/assessments/{aid}/draft", headers=lead1).json()["draft"]["source"] == "deterministic"
    assert client.post(f"/api/v1/comply/assessments/{aid}/report", headers=lead1,
                       json={"clock": "cert_in_report", "reference": "CERTIN-1"}).json()["reports"]
    assert client.post("/api/v1/comply/assessments/999999/decide", headers=lead1, json={"reportable": True, "reason": "x"}).status_code == 404
    assert client.post("/api/v1/comply/pack", headers=analyst).status_code == 403
    r = client.post("/api/v1/comply/pack", headers=auditor).json()
    assert client.get(f"/api/v1/reports/{r['id']}/download", headers=auditor).status_code == 200
    sc = client.get("/api/v1/pilot", headers=analyst).json()
    assert {k["id"] for k in sc["kpis"]} == set(pilot.KPIS)
    assert client.post("/api/v1/pilot/figures", headers=analyst, json={"kpi": "dlp_alerts_per_day", "kind": "target", "value": 1}).status_code == 403
    assert client.post("/api/v1/pilot/baseline/dlp_alerts_per_day", headers=lead2).json()["kind"] == "baseline"
    assert client.post("/api/v1/pilot/baseline/nope", headers=lead2).status_code == 404
    assert client.post("/api/v1/pilot/outages", headers=analyst, json={"tool": "trellix_epo", "found_by": "users"}).status_code == 200
    assert client.get("/api/v1/pilot/outages", headers=analyst).json()["items"][0]["found_by"] == "users"
