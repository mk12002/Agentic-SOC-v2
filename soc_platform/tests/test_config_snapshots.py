"""Configuration snapshots: each tool's configuration where it can export it, changes found field by field, recorded
changes told apart from unplanned ones, and the posture score before and after a change."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from soc_platform.connectors.base import ConnectorError, PermissionDenied
from soc_platform.connectors.http import FixtureTransport
from soc_platform.connectors.registry import FIXTURES_DIR, ConnectorRegistry
from soc_platform.core.auth import Principal, Role
from soc_platform.core.models import AuditRecord
from soc_platform.intelligence.config_snapshots import ConfigSnapshot, ConfigSnapshots, diff
from soc_platform.intelligence.tool_health import tool_health
from soc_platform.tests.conftest import person
from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture

ENGINEER = person("eng@example.com", Role.AUTOMATION_ADMIN)
LEAD = person("lead@example.com", Role.LEAD)
SERVICE = Principal("svc", "svc", frozenset({Role.AUTOMATION_ADMIN}), is_service=True)


def routes(name: str) -> list[dict]:
    return copy.deepcopy(json.loads((Path(FIXTURES_DIR) / f"{name}.json").read_text(encoding="utf-8"))["routes"])


def rules_route(rs: list[dict]) -> dict:
    return next(r for r in rs if r["path"] == "^/api/v1/policies/rules$")


@pytest.fixture()
def cfg(session):
    reg = ConnectorRegistry.all_fake()
    return ConfigSnapshots(session, reg)


def change_rules(cfg: ConfigSnapshots, edit) -> None:
    """The DLP tool now answers with an edited rule set (someone changed it in the tool)."""
    rs = routes("forcepoint_dlp")
    edit(rules_route(rs)["body"]["items"])
    cfg.registry.get("forcepoint_dlp").http = FixtureTransport(rs, "forcepoint_dlp")


def test_only_tools_that_export_their_configuration_are_read_and_the_rest_say_so(cfg):
    cap = cfg.capable()
    assert {n for n, ok in cap.items() if ok} == {"forcepoint_dlp", "silverfort", "trellix_epo"}
    assert cap["trend_micro"] is False and cap["directory_export"] is False and cap["crowdstrike"] is False
    out = cfg.snapshot_all()
    assert sorted(out["taken"]) == ["forcepoint_dlp", "silverfort", "trellix_epo"] and not out["failed"]
    view = {t["tool"]: t for t in cfg.overview()["tools"]}
    assert view["trend_micro"]["exports_config"] is False and view["trend_micro"]["latest"] is None
    with pytest.raises(KeyError, match="does not export"):
        cfg.take("trend_micro", reason="manual", by=ENGINEER.id)


def test_a_scheduled_read_with_nothing_new_only_confirms_the_newest_snapshot(cfg, session):
    first = cfg.take("forcepoint_dlp", reason="scheduled", by="agent:config")
    items = rules_route(routes("forcepoint_dlp"))["body"]["items"]
    assert first.item_count == len(items) and [i["id"] for i in first.items] == sorted(i["id"] for i in items)
    again = cfg.take("forcepoint_dlp", reason="scheduled", by="agent:config")
    assert again.id == first.id and len(session.execute(select(ConfigSnapshot)).scalars().all()) == 1
    assert cfg.change_of(first) is None                                                  # nothing to compare with


def test_a_change_made_outside_a_recorded_change_is_unplanned_and_shown_on_tool_health(cfg, session):
    cfg.snapshot_all()
    target = None

    def edit(items):
        nonlocal target
        target = items[0]
        items[0]["enabled"] = False
        items[0]["excluded_destinations"] = ["partner.example"]
        items.append({"id": "fp-rule-new", "name": "New rule", "enabled": True})
        del items[1]

    change_rules(cfg, edit)
    out = cfg.snapshot_all()
    assert out["taken"] == ["forcepoint_dlp"] and sorted(out["unchanged"]) == ["silverfort", "trellix_epo"]
    c = cfg.changes()[0]
    assert c["tool"] == "forcepoint_dlp" and c["planned"] is False and c["diff"]["count"] == 3
    assert [x["id"] for x in c["diff"]["added"]] == ["fp-rule-new"] and len(c["diff"]["removed"]) == 1
    fields = {f["field"]: f for f in c["diff"]["changed"][0]["fields"]}
    assert c["diff"]["changed"][0]["name"] == target["name"]
    assert fields["enabled"] == {"field": "enabled", "before": "true", "after": "false"}
    assert set(fields) == {"enabled", "excluded_destinations"}
    finding = next(f for f in tool_health(session)["findings"] if f["check"] == "configuration")
    assert finding["tool"] == "forcepoint_dlp" and finding["severity"] == "warning" and "3 item(s)" in finding["detail"]


def test_a_recorded_change_is_planned_and_reports_the_posture_before_and_after(cfg, session):
    cfg.snapshot_all()
    for nobody in (LEAD, SERVICE):
        with pytest.raises(PermissionError):
            cfg.before_change("forcepoint_dlp", nobody, reference="CHG-1")
    with pytest.raises(ValueError, match="reference"):
        cfg.before_change("forcepoint_dlp", ENGINEER, reference="  ")
    with pytest.raises(ValueError, match="before-change"):
        cfg.after_change("forcepoint_dlp", ENGINEER)
    before = cfg.before_change("forcepoint_dlp", ENGINEER, reference="CHG-1042 partner exception")
    assert cfg.open_window("forcepoint_dlp").id == before.id
    with pytest.raises(ValueError, match="already in progress"):
        cfg.before_change("forcepoint_dlp", ENGINEER, reference="CHG-2")
    change_rules(cfg, lambda items: items[0].update(threshold=5))
    cfg.snapshot_all()                                                  # the daily read lands inside the window
    out = cfg.after_change("forcepoint_dlp", ENGINEER, note="done")
    assert out["reference"] == "CHG-1042 partner exception" and out["diff"]["count"] == 1
    assert out["posture_change"] is None and out["posture_dipped"] is False       # no score yet: no comparison claimed
    assert cfg.open_window("forcepoint_dlp") is None and cfg.unplanned() == []
    assert all(c["planned"] for c in cfg.changes())
    kinds = [e.payload["reason"] for e in session.execute(select(AuditRecord).where(
        AuditRecord.event_type == "config.snapshot", AuditRecord.subject_id == "forcepoint_dlp").order_by(AuditRecord.seq)).scalars()]
    assert kinds == ["scheduled", "before_change", "scheduled", "after_change"]


def test_the_posture_dip_after_a_change_is_shown(cfg, session, monkeypatch):
    from soc_platform.intelligence import posture as P

    scores = iter([80, 74])
    monkeypatch.setattr(P, "posture", lambda s: {"score": next(scores)})
    cfg.before_change("trellix_epo", ENGINEER, reference="CHG-7 server policy")
    out = cfg.after_change("trellix_epo", ENGINEER)
    assert out["posture_change"] == -6 and out["posture_dipped"] is True


def test_diff_compares_items_by_id_field_by_field_and_items_without_an_id_are_left_out(cfg):
    a = [{"id": "1", "name": "x", "v": 1}, {"id": "2", "name": "y", "v": {"a": 1}}]
    b = [{"id": "2", "name": "y", "v": {"a": 2}, "new": True}, {"id": "3", "name": "z"}]
    d = diff(a, b)
    assert d["added"] == [{"id": "3", "name": "z"}] and d["removed"] == [{"id": "1", "name": "x"}]
    assert d["changed"] == [{"id": "2", "name": "y", "fields": [{"field": "new", "before": "null", "after": "true"},
                                                                {"field": "v", "before": '{"a": 1}', "after": '{"a": 2}'}]}]
    assert diff(a, a)["count"] == 0
    change_rules(cfg, lambda items: items.append({"name": "no id"}))
    snap = cfg.take("forcepoint_dlp", reason="manual", by=ENGINEER.id)
    assert all(i.get("id") for i in snap.items)


def test_the_export_is_read_page_by_page_in_full_and_never_kept_half_read(cfg):
    rs = routes("forcepoint_dlp")
    src = rules_route(rs)
    items = src["body"]["items"]
    paged = [{**src, "times": 1, "body": {"items": items[:3], "next_page_token": "p2"}}, {**src, "body": {"items": items[3:]}}]
    conn = cfg.registry.get("forcepoint_dlp")
    conn.http = FixtureTransport([r for r in rs if r is not src] + paged, "forcepoint_dlp")
    assert [i["id"] for i in conn.config_items()] == [i["id"] for i in items]
    assert [c["params"].get("page_token") for c in conn.http.calls if "rules" in c["path"]] == [None, "p2"]
    conn.http = FixtureTransport([{**src, "body": {"items": items[:1], "next_page_token": "again"}}], "forcepoint_dlp")
    conn.CONFIG_MAX_PAGES = 3
    with pytest.raises(ConnectorError, match="did not finish"):
        conn.config_items()


def test_a_tool_that_cannot_be_read_never_stops_the_others(cfg, session):
    cfg.registry.get("silverfort").http = FixtureTransport(
        [{"method": "GET", "path": ".*", "status": 403, "body": None}], "silverfort")
    out = cfg.snapshot_all()
    assert out["failed"] == ["silverfort"] and sorted(out["taken"]) == ["forcepoint_dlp", "trellix_epo"]
    with pytest.raises(PermissionDenied):
        cfg.take("silverfort", reason="manual", by=ENGINEER.id)


def test_the_api_records_a_change_and_reads_it_back(client):  # noqa: F811 - the imported fixture
    eng, lead = tok(client, "eng", "automation_admin"), tok(client, "lena", "lead")
    assert client.post("/api/v1/jobs/config_snapshot/run", headers=eng).json()["status"] == "ok"
    o = client.get("/api/v1/config-snapshots", headers=lead).json()
    assert {t["tool"] for t in o["tools"] if t["exports_config"]} == {"forcepoint_dlp", "silverfort", "trellix_epo"}
    assert client.post("/api/v1/config-snapshots/forcepoint_dlp/before-change", headers=lead,
                       json={"reference": "CHG-1"}).status_code == 403
    assert client.post("/api/v1/config-snapshots/forcepoint_dlp/before-change", headers=eng, json={}).status_code == 400
    b = client.post("/api/v1/config-snapshots/forcepoint_dlp/before-change", headers=eng, json={"reference": "CHG-1"}).json()
    assert b["reason"] == "before_change" and b["reference"] == "CHG-1"
    a = client.post("/api/v1/config-snapshots/forcepoint_dlp/after-change", headers=eng, json={}).json()
    assert a["reference"] == "CHG-1" and a["diff"]["count"] == 0
    assert client.get(f"/api/v1/config-snapshots/{a['after']['id']}", headers=lead).json()["change"]["planned"] is None
    assert client.post("/api/v1/config-snapshots/trend_micro/take", headers=eng, json={}).status_code == 404
    assert client.post("/api/v1/config-snapshots/forcepoint_dlp/frobnicate", headers=eng, json={}).status_code == 404
    for bogus in ("999999", "0", "99999999999999999999"):
        assert client.get(f"/api/v1/config-snapshots/{bogus}", headers=lead).status_code in (404, 422)

