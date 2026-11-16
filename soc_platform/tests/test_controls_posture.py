"""Control coverage, tool health and the posture score: every device missing a control is named, problems with the
tools themselves are found from what the tools report, and one score is computed by a formula anyone can re-run."""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from soc_platform.connectors.http import FixtureTransport
from soc_platform.connectors.registry import FIXTURES_DIR, ConnectorRegistry
from soc_platform.core import controls
from soc_platform.core.models import Case, Entity, utcnow
from soc_platform.intelligence.control_coverage import coverage
from soc_platform.intelligence.models import PostureSnapshot
from soc_platform.intelligence.posture import FORMULA_VERSION, WEIGHTS, posture, snapshot, trend
from soc_platform.intelligence.tool_health import tool_health
from soc_platform.tests.conftest import ESTATES, estate_env
from soc_platform.tests.test_connector_conformance import sync
from soc_platform.tests.test_dlp import service

INVENTORY = (("directory_export", "devices"), ("directory_export", "users"), ("trend_micro", "endpoints"),
             ("forcepoint_dlp", "endpoints"), ("trellix_epo", "systems"))
HEALTH = (("forcepoint_dlp", "health"), ("trellix_epo", "health"))


def items(name: str, path: str) -> list[dict]:
    routes = json.loads((Path(FIXTURES_DIR) / f"{name}.json").read_text(encoding="utf-8"))["routes"]
    return next(r for r in routes if r["path"] == f"^{path}$")["body"]["items"]


def load(session, streams=INVENTORY + HEALTH, *, change=None) -> None:
    """Sync the given streams; ``change(name, stream, items)`` may edit the sample records first."""
    reg = ConnectorRegistry.all_fake()
    for name, stream in streams:
        conn = reg.get(name)
        if change is not None:
            routes = copy.deepcopy(json.loads((Path(FIXTURES_DIR) / f"{name}.json").read_text(encoding="utf-8"))["routes"])
            for r in routes:
                if r["path"] == f"^{conn.path_of(stream)}$":
                    change(name, stream, r["body"]["items"])
            conn.http = FixtureTransport(routes, name)
        rep, _ = sync(session, conn, stream)
        assert not rep.errors, rep.errors


# ---------------------------------------------------------------------------------------------- coverage


def test_every_device_in_the_baseline_is_checked_against_each_control_that_applies(session):
    load(session, INVENTORY)
    cov = coverage(session)
    devices = items("directory_export", "/api/v1/devices")
    servers = sum("server" in d["os"].lower() or "ubuntu" in d["os"].lower() for d in devices)
    by = {c["control"]: c for c in cov["controls"]}
    assert cov["available"] and cov["baseline"]["devices"] == len(devices) and not cov["not_measured"]
    assert by["edr"]["applicable"] == len(devices)                                   # on every device
    assert by["dlp_agent"]["applicable"] == by["disk_encryption"]["applicable"] == len(devices) - servers   # workstations
    for c in cov["controls"]:
        assert c["covered"] + c["missing"] + c["silent"] + c["off"] + c["unknown"] == c["applicable"]
        assert c["short"] == c["missing"] + c["silent"] + c["off"]
        assert c["covered_percent"] == round(100 * c["covered"] / c["applicable"], 1)
    # a device short of two controls is one device: the total is devices, not the sum of the controls' gaps
    short = cov["devices_short"]
    assert cov["devices_short_count"] == len(short) <= sum(c["short"] for c in cov["controls"])
    assert cov["fully_covered"] == len(devices) - len(short)
    assert cov["coverage_percent"] == round(100 * cov["fully_covered"] / len(devices), 1)
    assert {m["state"] for r in short for m in r["missing"]} == {"missing", "silent", "off"}     # each kind of gap is found
    assert all(m["detail"] for r in short for m in r["missing"]) and [r["rank"] for r in short] == list(range(1, len(short) + 1))


def test_a_device_a_tool_sees_that_the_directory_does_not_list_is_reported_not_counted(session):
    load(session, INVENTORY)
    cov = coverage(session)
    listed = {d["name"].lower() for d in items("directory_export", "/api/v1/devices")}
    seen = {e["endpoint_name"].lower() for e in items("trend_micro", "/api/v1/endpoints")}
    assert sorted(u["name"].split(".")[0] for u in cov["unlisted"]) == sorted(seen - listed) != []
    assert all(u["seen_by"] == ["trend_micro"] for u in cov["unlisted"])
    assert cov["baseline"]["devices"] == len(listed)


def test_a_control_whose_tool_is_not_connected_is_not_measured_never_missing_everywhere(session):
    load(session, [s for s in INVENTORY if s[0] != "trellix_epo"])
    cov = coverage(session)
    assert [c["control"] for c in cov["not_measured"]] == ["disk_encryption"]
    assert "disk_encryption" not in {c["control"] for c in cov["controls"]}
    assert not any(m["control"] == "disk_encryption" for r in cov["devices_short"] for m in r["missing"])
    assert posture(session)["domains"][3]["measured"]            # data protection is still scored, from the DLP agent


def test_without_a_baseline_coverage_says_so(session):
    empty = coverage(session)
    assert empty["available"] is False and "baseline" in empty["reason"] and empty["coverage_percent"] is None
    load(session, [("trend_micro", "endpoints")])                 # a tool's own list is not a baseline
    assert coverage(session)["available"] is False


def test_silent_is_measured_from_the_tools_newest_check_in_not_from_the_clock(session, monkeypatch):
    load(session, INVENTORY)
    before = coverage(session)
    silent = [r["name"] for r in before["devices_short"] if any(m["state"] == "silent" for m in r["missing"])]
    assert len(silent) == 1
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(400 * 86400))                 # the same data, looked at a year later
    later = coverage(session)
    assert later["devices_short"] == before["devices_short"] and later["coverage_percent"] == before["coverage_percent"]
    load(session, INVENTORY)                                                         # ... and read again a year later
    again = coverage(session)
    assert again["devices_short"] == before["devices_short"] and again["coverage_percent"] == before["coverage_percent"]
    monkeypatch.delenv("SOC_CLOCK_OFFSET_SECONDS")
    monkeypatch.setenv("SOC_AGENT_SILENT_HOURS", "2000")                             # a longer tolerance: no longer silent
    assert not any(m["state"] == "silent" for r in coverage(session)["devices_short"] for m in r["missing"])


def test_devices_are_ranked_by_the_personal_data_alerts_on_them_and_their_user(session):
    svc = service(session)
    svc.ingest()
    load(session, HEALTH)
    flat = coverage(session)["devices_short"]
    assert all(r["personal_data_alerts"] == 0 for r in flat)                         # nothing judged yet: by gaps, then name
    assert flat == sorted(flat, key=lambda r: (-len(r["missing"]), r["name"]))
    svc.process()
    ranked = coverage(session)["devices_short"]
    counts = [r["personal_data_alerts"] for r in ranked]
    assert counts == sorted(counts, reverse=True) and counts[0] > 0 and {r["name"] for r in ranked} == {r["name"] for r in flat}


@pytest.mark.parametrize("estate", ESTATES)
def test_coverage_names_devices_on_every_estate_without_the_built_in_names(estate, estate_configs, db):
    with estate_env(estate_configs[estate]) as cfg, db.session() as session:
        load_estate(session)
        cov = coverage(session)
        assert cov["available"] and 0 < cov["devices_short_count"] < cov["baseline"]["devices"]
        health = tool_health(session)
        assert health["counts"]["critical"] >= 1 and posture(session)["score"] is not None
        text = json.dumps([cov, health, posture(session)]).lower()
        assert not [t for t in cfg["original_tokens"] if t.lower() in text]


def load_estate(session) -> None:
    reg = ConnectorRegistry.all_fake()
    for name, stream in INVENTORY + HEALTH:
        rep, _ = sync(session, reg.get(name), stream)
        assert not rep.errors, rep.errors


# ---------------------------------------------------------------------------------------------- tool health


def test_what_the_tools_report_about_themselves_becomes_findings_with_a_next_step(session):
    load(session)
    h = tool_health(session, ["forcepoint_dlp", "trellix_epo", "trend_micro", "silverfort"])
    by = {t["tool"]: t for t in h["tools"]}
    assert by["forcepoint_dlp"]["status"] == "critical" and by["trellix_epo"]["status"] == "healthy"
    assert by["trend_micro"]["status"] == "healthy"                                  # its agents report: watched
    assert by["silverfort"]["status"] == "not_reported" and "not reported" in by["silverfort"]["headline"]
    checks = {(f["tool"], f["check"]): f for f in h["findings"]}
    cert = checks[("forcepoint_dlp", "certificate")]
    reported = next(i for i in items("forcepoint_dlp", "/api/v1/system/health") if i["type"] == "certificate")
    assert cert["severity"] == "critical" and f"{cert['data']['days_left']} day(s) left" in cert["title"]
    assert cert["data"]["days_left"] == 9 and reported["expires_at"][:10] in cert["detail"]
    people = checks[("forcepoint_dlp", "directory_sync")]["data"]["people"]
    assert len(people) == 2 and "no policy group" in checks[("forcepoint_dlp", "directory_sync")]["title"]
    agents = checks[("forcepoint_dlp", "agents")]
    assert agents["data"]["devices"] and "on approval" in agents["next_step"]
    assert all(f["next_step"] and f["detail"] for f in h["findings"])
    assert h["counts"] == {"critical": sum(f["severity"] == "critical" for f in h["findings"]),
                           "warning": sum(f["severity"] == "warning" for f in h["findings"])}
    assert [f["severity"] for f in h["findings"]] == sorted((f["severity"] for f in h["findings"]), key=["critical", "warning"].index)


def test_certificate_days_are_counted_from_the_tools_own_report_and_jobs_can_fail_or_run_late(session, monkeypatch):
    def change(name, stream, recs):
        if (name, stream) != ("forcepoint_dlp", "health"):
            return
        for r in recs:
            if r["id"] == "fp-sync-incident-db":
                r["status"] = "failed"
            if r["id"] == "fp-sync-policy-deploy":
                r["last_run"] = "2026-09-10T07:00:00Z"                               # ten days before the report, daily job
            if r["type"] == "certificate":
                r["expires_at"] = "2026-10-12T09:30:00Z"                             # 22 days after the report
        recs.append({"id": "fp-cert-old", "type": "certificate", "name": "Old signing certificate",
                     "expires_at": "2026-09-01T00:00:00Z", "reported_at": recs[0]["reported_at"]})

    load(session, HEALTH, change=change)
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(200 * 86400))                 # read long after the report
    f = {x["title"]: x for x in tool_health(session)["findings"]}
    assert f["Security Manager SSL certificate: 22 day(s) left"]["severity"] == "warning"
    assert f["Old signing certificate has expired"]["severity"] == "critical"
    assert f["Incident database replication failed"]["severity"] == "critical"
    assert f["Policy deployment to endpoints is late"]["severity"] == "warning"
    monkeypatch.setenv("SOC_CERT_WARN_DAYS", "10")
    assert not any("22 day(s)" in x["title"] for x in tool_health(session)["findings"])


def test_with_nothing_reported_health_says_so_and_never_invents_a_finding(session):
    assert tool_health(session) == {"tools": [], "findings": [], "counts": {"critical": 0, "warning": 0}}
    listed = tool_health(session, ["forcepoint_dlp"])["tools"]
    assert [(t["tool"], t["status"]) for t in listed] == [("forcepoint_dlp", "not_reported")]


# ---------------------------------------------------------------------------------------------- posture score


def test_the_score_can_be_recomputed_from_the_factors_it_returns(session):
    svc = service(session)
    svc.ingest()
    load(session, HEALTH)
    svc.process()
    p = posture(session)
    cov = coverage(session)
    by = {c["control"]: c for c in cov["controls"]}
    d = {x["id"]: x for x in p["domains"]}
    assert p["formula_version"] == FORMULA_VERSION and "draft" in p["weights_status"]
    assert d["endpoint"]["score"] == by["edr"]["covered_percent"]
    health = tool_health(session)
    mine = [f for f in health["findings"] if f["tool"] in ("forcepoint_dlp", "trellix_epo")]
    crit, warn = sum(f["severity"] == "critical" for f in mine), sum(f["severity"] == "warning" for f in mine)
    cases = len(session.execute(select(Case).where(Case.domain == "dlp", Case.status != "closed")).scalars().all())
    base = (by["dlp_agent"]["covered_percent"] + by["disk_encryption"]["covered_percent"]) / 2
    assert d["data_protection"]["score"] == round(max(0.0, base - min(20, 5 * crit + 2 * warn) - min(15, 3 * cases)), 1)
    people = [e for e in session.execute(select(Entity).where(Entity.kind == "identity")).scalars()
              if "directory_export" in (e.attributes or {}).get("by_tool", {})]
    assert d["identity"]["score"] == round(100 * (1 - 1 / len(people)), 1)           # one person with a high-risk sign-in
    assert [x["id"] for x in p["domains"] if not x["measured"]] == ["privileged_access", "web"]
    assert all(x["reason"] for x in p["domains"] if not x["measured"])
    measured = [x for x in p["domains"] if x["measured"]]
    mean = sum(WEIGHTS[x["id"]] * x["score"] for x in measured) / sum(WEIGHTS[x["id"]] for x in measured)
    assert p["weighted_mean"] == round(mean, 1)
    critical = len(session.execute(select(Case).where(Case.status != "closed", Case.severity == "critical")).scalars().all())
    assert critical >= 1
    assert p["score"] == round(max(0.0, min(100.0, mean - min(20, 4 * critical) - min(10, 2 * health["counts"]["critical"]))))
    assert [f["effect"] for f in p["penalties"]] == [-min(20, 4 * critical), -min(10, 2 * health["counts"]["critical"])]
    assert p["largest_reductions"] and all(f["effect"] < 0 for f in p["largest_reductions"])
    assert posture(session) == p                                                     # the same data, the same score


def test_fixing_a_gap_raises_the_score_and_an_empty_tenant_has_none(session):
    assert posture(session)["score"] is None and not posture(session)["measured_domains"]
    load(session)
    before, short_before = posture(session), coverage(session)["devices_short_count"]

    def fix(name, stream, recs):
        if (name, stream) == ("trellix_epo", "systems"):
            for r in recs:
                r["encryption"]["state"] = "Encrypted"

    load(session, [("trellix_epo", "systems")], change=fix)
    after = posture(session)
    dp = lambda p: next(x["score"] for x in p["domains"] if x["id"] == "data_protection")
    assert dp(after) > dp(before) and after["score"] > before["score"]
    assert coverage(session)["devices_short_count"] == short_before - 1


def test_one_score_is_stored_per_day_and_the_change_is_read_from_the_stored_days(session):
    load(session)
    assert trend(session) == {"days": 30, "points": [], "change": None}
    first = snapshot(session)
    assert snapshot(session) == first and len(session.execute(select(PostureSnapshot)).scalars().all()) == 1
    assert trend(session)["change"] is None                                          # one day is not a trend
    old = (utcnow() - timedelta(days=10)).strftime("%Y-%m-%d")
    session.add(PostureSnapshot(day=old, score=first["score"] - 3, document={}))
    session.add(PostureSnapshot(day=(utcnow() - timedelta(days=90)).strftime("%Y-%m-%d"), score=1, document={}))
    session.flush()
    t = trend(session)
    assert t["change"] == 3 and [p["day"] for p in t["points"]] == [old, first["day"]]   # the 90-day-old one is outside


def test_controls_read_each_tools_own_view_of_one_device(session):
    load(session, INVENTORY)
    snap = controls.snapshot(session)
    assert snap.connected == {"directory_export", "trend_micro", "forcepoint_dlp", "trellix_epo"}
    assert set(snap.newest) == {"trend_micro", "forcepoint_dlp"}                     # encryption has no check-in time
    server = next(a for a in snap.assets if controls.device_type(a, snap) == "server")
    assert [c["control"] for c in controls.device_controls(server, snap)] == ["edr"]
    off = next(a for a in snap.assets if (snap.view(a, "trellix_epo") or {}).get("disk_encrypted") is False)
    states = {c["control"]: c["state"] for c in controls.device_controls(off, snap)}
    assert states == {"edr": "ok", "dlp_agent": "ok", "disk_encryption": "off"}


def expected_gaps() -> dict[str, set[str]]:
    """What the sample data says is short, read from the fixtures themselves: device name -> controls."""
    devices = items("directory_export", "/api/v1/devices")
    workstations = {d["name"].lower() for d in devices if "server" not in d["os"].lower() and "ubuntu" not in d["os"].lower()}
    edr = {e["endpoint_name"].lower() for e in items("trend_micro", "/api/v1/endpoints")}
    agents = {e["hostname"].lower(): e["last_checkin"] for e in items("forcepoint_dlp", "/api/v1/endpoints")}
    newest = max(agents.values())[:10]
    enc = {x["name"].lower(): x["encryption"]["state"] for x in items("trellix_epo", "/api/v1/systems")}
    out: dict[str, set[str]] = {}
    for d in devices:
        n = d["name"].lower()
        gaps = set() if n in edr else {"edr"}
        if n in workstations:
            if n not in agents or agents[n][:10] < newest:
                gaps.add("dlp_agent")
            if enc.get(n) != "Encrypted":
                gaps.add("disk_encryption")
        if gaps:
            out[n] = gaps
    return out


def test_gaps_are_the_same_when_other_tools_already_know_the_devices_and_incidents_name_them(session):
    """Found by running the demo: (1) a device named in a DLP incident counted as listed by the DLP tool, so a missing
    agent read as "unknown"; (2) an agent record for a laptop other tools had just seen was left unresolved because
    it was dated by its last check-in. Coverage must equal what the inventories say, whatever was ingested before."""
    from soc_platform.core.models import SourceRecord, UnresolvedItem
    from soc_platform.domains.incident.service import IncidentService

    IncidentService(session, ConnectorRegistry.all_fake()).ingest()          # the same laptops, seen now by other tools
    svc = service(session)
    assert not svc.ingest()["errors"]
    svc.process()
    load(session, HEALTH)
    stack = ("directory_export", "trend_micro", "forcepoint_dlp", "trellix_epo")
    records = session.execute(select(SourceRecord).where(SourceRecord.tool.in_(stack), SourceRecord.kind == "asset")).scalars().all()
    assert records and all(r.entity_id for r in records), [r.source_id for r in records if not r.entity_id]
    stuck = {r.id for r in records}
    assert not [u for u in session.execute(select(UnresolvedItem)).scalars() if u.source_record_id in stuck]
    cov = coverage(session)
    got = {r["name"].split(".")[0]: {m["control"] for m in r["missing"]} for r in cov["devices_short"]}
    assert got == expected_gaps() and len(got) == 4
    assert {m["state"] for r in cov["devices_short"] for m in r["missing"]} == {"missing", "silent", "off"}
    assert not any(c["unknown"] for c in cov["controls"])


def test_a_device_a_tool_stops_listing_stops_counting_as_covered(session, monkeypatch):
    load(session, INVENTORY)
    before = coverage(session)
    gone = items("trend_micro", "/api/v1/endpoints")[0]["endpoint_name"].lower()
    monkeypatch.setenv("SOC_CLOCK_OFFSET_SECONDS", str(5 * 86400))                   # five days later ...

    def drop(name, stream, recs):
        if name == "trend_micro":
            recs[:] = [r for r in recs if r["endpoint_name"].lower() != gone]        # ... the agent is no longer listed

    load(session, [("trend_micro", "endpoints")], change=drop)
    after = coverage(session)
    edr = lambda c: next(x for x in c["controls"] if x["control"] == "edr")
    assert edr(after)["missing"] == edr(before)["missing"] + 1
    assert gone in {r["name"].split(".")[0] for r in after["devices_short"] if any(m["control"] == "edr" for m in r["missing"])}
    # the other tools were not read again: their older reads still stand (a tool that is down is not "missing everywhere")
    assert {c["control"]: c["covered"] for c in after["controls"] if c["control"] != "edr"} == \
           {c["control"]: c["covered"] for c in before["controls"] if c["control"] != "edr"}
