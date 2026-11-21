"""Declared connectors (connectors/declarative.py): a plain REST tool connected by a definition file, no code. The
definition is checked completely, it can only read, it never names another host, an existing connector re-expressed
as a definition yields the same records as its code, and every workflow uses a declared tool through its capability."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from soc_platform.connectors import capabilities as caps
from soc_platform.connectors import declarative as dc
from soc_platform.connectors.base import ConnectorError, SyncRunner
from soc_platform.connectors.http import FixtureTransport, HttpTransport
from soc_platform.connectors.registry import ConnectorRegistry, discover
from soc_platform.core import controls
from soc_platform.core.context_store import ContextStore

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "config" / "connectors.d" / "examples"
FIXTURES = ROOT / "soc_platform" / "fixtures"

# The Trellix connector's systems stream, written as a definition (the "done when" proof of the plan)
TRELLIX_AS_DEFINITION = {
    "connector": "trellix_declared", "tool": "Trellix ePO (declared)", "category": "encryption",
    "sign_in": {"type": "bearer"}, "fixtures": str(FIXTURES / "trellix_epo.json"),
    "provides": {"encryption.inventory": {
        "stream": "systems", "path": "/api/v1/systems", "items": "items",
        "paging": {"style": "page_token", "field": "next_page_token", "param": "page_token", "limit_param": "limit"},
        "id": "node_id", "source_type": "system", "dimension": "endpoint", "observed_at": "last_communication",
        "keys": {"epo_node_id": "node_id", "serial_number": "serial_number"},
        "map": {"hostname": ["name", {"from": "fqdn", "as": "label"}], "fqdn": {"from": "fqdn", "as": "fqdn"},
                "ip": "ip", "os": "os", "device_type": {"from": "os", "as": "device_type"},
                "last_communication": "last_communication",
                "disk_encrypted": {"from": "encryption.state", "as": "bool"},
                "encryption_state": {"from": "encryption.state", "as": "lower"},
                "encryption_product_version": "encryption.product_version"}}},
}


@pytest.fixture()
def definitions(tmp_path, monkeypatch):
    """A definitions folder the platform reads (SOC_CONNECTOR_DEFINITIONS); the catalogue is reloaded around it."""
    monkeypatch.setenv("SOC_CONNECTOR_DEFINITIONS", str(tmp_path))
    caps.reset()
    yield tmp_path
    monkeypatch.delenv("SOC_CONNECTOR_DEFINITIONS")
    caps.reset()


def write(folder: Path, doc: dict, name: str | None = None) -> Path:
    p = folder / f"{name or doc['connector']}.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def records(conn, stream):
    out, cursor = [], None
    for _ in range(20):
        page = conn.fetch_page(stream, cursor)
        for raw in page.records:
            out += conn.normalize(stream, raw)
        if not page.has_more:
            return out, page
        cursor = page.next_cursor
    raise AssertionError("paging did not end")


def test_an_existing_connector_rewritten_as_a_definition_yields_the_same_records(definitions):
    write(definitions, TRELLIX_AS_DEFINITION)
    reg = ConnectorRegistry.all_fake()
    declared, _ = records(reg.get("trellix_declared"), "systems")
    coded, _ = records(reg.get("trellix_epo"), "systems")
    assert declared and len(declared) == len(coded)

    def comparable(r):
        d = r.model_dump(exclude={"tool", "raw"})
        return json.dumps(d, sort_keys=True, default=str)

    assert [comparable(r) for r in declared] == [comparable(r) for r in coded]


def test_the_example_definition_validates_and_reads_its_fixtures_across_pages():
    d = dc.read_file(EXAMPLES / "examplevendor_edr.yaml")
    m = dc.manifest(d)
    conn = dc.DeclarativeConnector(d, dict(m.fake_settings), m.fixture_transport())
    eps, last = records(conn, "endpoints")
    assert [r.attributes["hostname"] for r in eps] == ["ARUN-LT05", "WEB01", "JANE-LT01"]   # two pages, in order
    assert last.reset and last.next_cursor is None                  # an inventory is read in full, no resume token
    assert eps[1].attributes["device_type"] == "server" and eps[0].keys["examplevendor_agent_id"] == "ex-ep-0001"
    alerts, last = records(conn, "alerts")
    assert alerts[0].kind == "edr_alert" and alerts[0].severity == "medium"
    assert {r.role for r in alerts[0].refs} == {"host", "user"}
    assert last.next_cursor and last.next_cursor.startswith("since:")   # an event stream resumes from its watermark


def test_a_declared_tool_is_used_by_every_workflow_that_reads_its_capability(session, monkeypatch):
    """Plug-and-play end to end: the example EDR is switched on beside the directory, and coverage measures the EDR
    control from it - no workflow names it."""
    monkeypatch.setenv("SOC_CONNECTOR_DEFINITIONS", str(EXAMPLES))
    caps.reset()
    try:
        assert "examplevendor_edr" in caps.tools_for("edr.inventory", "edr.alerts")
        reg = ConnectorRegistry({"connectors": {n: {"enabled": True, "stage": "fake"}
                                                for n in ("directory_export", "examplevendor_edr")}})
        for rep in SyncRunner(session, ContextStore(session)).sync_many(reg.providers("directory.devices",
                                                                                    "edr.inventory")):
            assert not rep.errors, rep.errors
        snap = controls.snapshot(session)
        edr = next(c for c in controls.CONTROLS if c.id == "edr")
        assert snap.measured(edr) == ["examplevendor_edr"]
        listed = {a.display_name.upper().split(".")[0] for a in snap.assets
                  if snap.view(a, "examplevendor_edr") is not None}
        assert {"ARUN-LT05", "WEB01", "JANE-LT01"} <= listed
        m = caps.matrix(reg)
        assert any(p["tool"] == "examplevendor_edr" for c in m["capabilities"] if c["capability"] == "edr.inventory"
                   for p in c["provided_by"])
    finally:
        monkeypatch.delenv("SOC_CONNECTOR_DEFINITIONS")
        caps.reset()


def test_a_declared_connector_is_offered_in_every_product_scope(definitions, monkeypatch):
    write(definitions, TRELLIX_AS_DEFINITION)
    monkeypatch.setenv("SOC_PRODUCT_SCOPE", "nam")
    reg = ConnectorRegistry.all_fake()
    assert "trellix_declared" in reg.manifests and "crowdstrike" not in reg.manifests
    assert reg.manifests["trellix_declared"].origin == "definition"


# ------------------------------------------------------------------ what a definition may not do


def bad(**changes) -> dict:
    doc = json.loads(json.dumps(TRELLIX_AS_DEFINITION))
    stream = doc["provides"]["encryption.inventory"]
    for k, v in changes.items():
        if k.startswith("s_"):
            stream[k[2:]] = v
        else:
            doc[k] = v
    return doc


@pytest.mark.parametrize(("doc", "says"), [
    (bad(script="import os"), "unknown key"),
    (bad(category="toaster"), "category"),
    (bad(connector="Bad Name"), "lower-case"),
    (bad(sign_in={"type": "bearer", "api_key": "secret-in-the-file"}), "credentials are settings"),
    (bad(sign_in={"type": "kerberos"}), "sign_in.type"),
    (bad(s_path="https://elsewhere.example/api"), "path must start with /"),
    (bad(s_path="//elsewhere.example/api"), "path"),
    (bad(s_map={"hostname": "__import__('os').system('x')"}), "not a field path"),
    (bad(s_map={"hostname": "{{ raw.name }}"}), "not a field path"),
    (bad(s_map={"hostname": {"from": "name", "as": "eval"}}), "unknown converter"),
    (bad(s_map={"hostname": "name"}), "disk_encrypted"),
    (bad(s_paging={"style": "offset"}), "limit_param"),
    (bad(s_paging={"style": "next_link"}), "needs 'field'"),
    (bad(s_kind="alert"), "kind"),
    (bad(s_keys={}), "needs keys"),
    (bad(provides={"intel.kev": {"path": "/kev", "id": "id"}}), "needs code"),
    (bad(provides={"edr.inventry": {"path": "/x", "id": "id"}}), "unknown capability"),
])
def test_a_definition_that_breaks_a_rule_is_refused_with_why(doc, says):
    with pytest.raises(dc.DefinitionError, match=says):
        dc.parse(doc, source="t.yaml")


def test_a_declared_connector_has_no_actions_and_no_lookups():
    d = dc.parse(TRELLIX_AS_DEFINITION, source="t.yaml")
    m = dc.manifest(d)
    conn = m.factory(dict(m.fake_settings), m.fixture_transport())
    assert m.actions(conn) == [] and conn.lookups == ()
    assert not hasattr(conn, "isolate") and not hasattr(conn, "post_action")


def test_a_next_link_to_another_host_is_refused_before_any_call():
    doc = json.loads(json.dumps(TRELLIX_AS_DEFINITION))
    doc["provides"]["encryption.inventory"]["paging"] = {"style": "next_link", "field": "links.next"}
    d = dc.parse(doc, source="t.yaml")
    conn = dc.DeclarativeConnector(d, {"base_url": "https://epo.example.invalid"},
                                   HttpTransport("https://epo.example.invalid"))
    with pytest.raises(ConnectorError, match="not the connector's own host"):
        conn.fetch_page("systems", "https://elsewhere.example.invalid/api/v1/systems?page=2|")


def test_a_vendor_that_never_stops_paging_is_an_error_not_a_loop(monkeypatch):
    monkeypatch.setattr(dc, "MAX_PAGES", 3)
    d = dc.parse(TRELLIX_AS_DEFINITION, source="t.yaml")
    endless = FixtureTransport([{"method": "GET", "path": "^/api/v1/systems$",
                                 "body": {"items": [{"node_id": "n1", "name": "X"}], "next_page_token": "again"}}])
    conn = dc.DeclarativeConnector(d, {}, endless)
    with pytest.raises(ConnectorError, match="pages in one sync"):
        records(conn, "systems")


def test_a_record_without_its_identifier_is_refused_with_why():
    d = dc.parse(TRELLIX_AS_DEFINITION, source="t.yaml")
    conn = dc.DeclarativeConnector(d, {}, FixtureTransport([]))
    with pytest.raises(ValueError, match="identifier"):
        conn.normalize("systems", {"name": "NO-ID"})


def test_a_bad_definition_is_left_out_and_reported_while_others_load(definitions):
    write(definitions, TRELLIX_AS_DEFINITION)
    write(definitions, {**TRELLIX_AS_DEFINITION, "connector": "broken_one", "category": "toaster"})
    write(definitions, {**TRELLIX_AS_DEFINITION, "connector": "trend_micro"}, name="clash")
    found = discover()
    assert "trellix_declared" in found and "broken_one" not in found
    assert found["trend_micro"].origin == "code"                 # a definition never replaces a code connector
    problems = " ".join(dc.problems())
    assert "toaster" in problems and "already exists" in problems


def test_connector_validate_reports_a_definition_and_its_streams(tmp_path):
    ok = subprocess.run([sys.executable, "-m", "soc_platform", "connector", "validate",
                         str(EXAMPLES / "examplevendor_edr.yaml")], check=False, capture_output=True, text=True,
                        timeout=120)
    assert ok.returncode == 0, ok.stderr[-500:]
    assert "endpoints: 3 record(s)" in ok.stdout and "alerts: 1 record(s)" in ok.stdout
    p = write(tmp_path, bad(category="toaster"), name="refused")
    no = subprocess.run([sys.executable, "-m", "soc_platform", "connector", "validate", str(p)], check=False,
                        capture_output=True, text=True, timeout=120)
    assert no.returncode != 0 and "definition refused" in no.stderr
