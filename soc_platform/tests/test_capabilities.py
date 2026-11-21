"""Plug-and-play by capability: every connector declares what it provides, each declaration holds on the connector's
own data, workflows read whichever tool provides a capability (a second product of the same kind needs no workflow
code), and the capability matrix tells a deployment what is missing before it goes live."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from soc_platform.connectors import capabilities as caps
from soc_platform.connectors.base import SyncRunner
from soc_platform.connectors.registry import ConnectorRegistry, discover
from soc_platform.core import controls
from soc_platform.core.context_store import ContextStore
from soc_platform.intelligence.control_coverage import coverage

# streams whose sample data is empty on purpose (pushed-only, catalogue look-ups, a CSV the operator uploads)
EMPTY_IN_FAKE_MODE = {("servicenow", "tickets"), ("cmdb_csv", "cmdb")}


def registry(*names: str) -> ConnectorRegistry:
    return ConnectorRegistry({"connectors": {n: {"enabled": True, "stage": "fake"} for n in names}})


def records(conn, stream: str, pages: int = 5) -> list:
    out, cursor = [], None
    for _ in range(pages):
        page = conn.fetch_page(stream, cursor)
        for raw in page.records:
            out += conn.normalize(stream, raw)
        if not page.has_more:
            break
        cursor = page.next_cursor
    return out


def declarations():
    return [(name, cap, p) for name, m in sorted(discover().items()) for cap, p in sorted(m.provides.items())]


# ------------------------------------------------------------------ the declarations


def test_every_connector_declares_what_it_provides_from_the_catalogue():
    found = discover()
    assert found and all(m.provides for m in found.values()), [n for n, m in found.items() if not m.provides]
    for name, cap, p in declarations():
        contract = caps.CAPABILITIES[cap]
        assert set(p.fields) <= set(contract.fields), (name, cap, "maps a field the contract does not have")
        if contract.kinds:
            assert p.streams or cap == "siem.alerts", (name, cap, "a record capability needs a stream (or is pushed)")


def test_an_unknown_capability_is_refused_when_the_manifest_is_built():
    m = discover()["trend_micro"]
    with pytest.raises(KeyError, match="unknown capability"):
        type(m)(**{**{f: getattr(m, f) for f in m.__dataclass_fields__}, "provides": {"edr.inventry": "endpoints"}})


@pytest.mark.parametrize(("name", "cap", "p"), declarations(), ids=lambda x: x if isinstance(x, str) else "")
def test_each_declared_capability_holds_on_the_connectors_own_data(name, cap, p):
    """The capability's conformance test: the stream exists, delivers only the contract's record kinds, and carries
    the contract's fields under the names the declaration maps."""
    contract = caps.CAPABILITIES[cap]
    conn = ConnectorRegistry.all_fake().get(name)
    for st in p.streams:
        assert st in conn.streams, f"{name} declares {cap} on {st}, which it does not have"
        recs = records(conn, st)
        if (name, st) in EMPTY_IN_FAKE_MODE or not contract.kinds:
            continue
        assert recs, f"{name}.{st} gave no records in fake mode"
        assert {r.kind for r in recs} <= set(contract.kinds), (name, st, {r.kind for r in recs})
        for f in contract.fields:
            own = caps.field_name(name, cap, f)
            if own is None:
                continue                                  # the declaration says the tool does not report it
            if f in p.fields or f in ("last_seen", "disk_encrypted", "privileged"):
                assert any(own in r.attributes for r in recs), f"{name}.{st} never carries {own} (contract {f})"


def test_providers_are_only_switched_on_tools_in_a_fixed_order():
    reg = registry("trend_micro", "directory_export")
    got = [(c.name, st) for c, st in reg.providers("directory.devices", "edr.inventory")]
    assert got == [("directory_export", "devices"), ("trend_micro", "endpoints")]
    assert reg.provider_names("dlp.incidents") == []
    assert caps.tools_for("edr.inventory") == tuple(sorted(caps.tools_for("edr.inventory")))


# ------------------------------------------------------------------ a second product needs no workflow code


def _sync(session, reg, *capabilities):
    runner = SyncRunner(session, ContextStore(session))
    for rep in runner.sync_many(reg.providers(*capabilities)):
        assert not rep.errors, rep.errors


@pytest.mark.parametrize("edr", sorted(caps.tools_for("edr.inventory")))
def test_the_edr_control_is_measured_from_whichever_edr_product_is_connected(session, edr):
    """The same coverage code with a different EDR product: the EDR control is measured from it, devices it lists
    are not 'missing', and those it does not list are missing *from it* - no product named anywhere."""
    reg = registry("directory_export", edr)
    _sync(session, reg, "directory.devices", "edr.inventory")
    snap = controls.snapshot(session)
    edr_control = next(c for c in controls.CONTROLS if c.id == "edr")
    assert snap.measured(edr_control) == [edr]
    cov = coverage(session)
    assert cov["available"] and cov["baseline"]["tools"] == ["directory_export"]
    row = next(c for c in cov["controls"] if c["control"] == "edr")
    assert row["tools"] == [edr] and row["applicable"] == cov["baseline"]["devices"]
    listed = {a.id for a in snap.assets if snap.view(a, edr) is not None}
    for a in snap.assets:
        if snap.baseline_view(a) is None:
            continue
        state, detail, tool = controls.best_state(edr_control, a, snap)
        assert tool == edr
        assert (state == "missing") == (a.id not in listed), (a.display_name, state, detail)
    assert row["covered"] + row["silent"] + row["unknown"] == len(listed & {a.id for a in snap.assets
                                                                             if snap.baseline_view(a) is not None})


def test_two_edr_products_at_once_count_a_device_once_with_the_better_state(session):
    reg = registry("directory_export", "trend_micro", "crowdstrike")
    _sync(session, reg, "directory.devices", "edr.inventory")
    snap = controls.snapshot(session)
    c = next(x for x in controls.CONTROLS if x.id == "edr")
    assert snap.measured(c) == ["crowdstrike", "trend_micro"]
    for a in snap.assets:
        if snap.baseline_view(a) is None:
            continue
        each = [controls.state_from(c, t, a, snap)[0] for t in ("crowdstrike", "trend_micro")]
        assert controls.control_state(c, a, snap)[0] == min(each, key=controls.RANK.get)
    row = next(x for x in coverage(session)["controls"] if x["control"] == "edr")
    alone = None
    for t in ("crowdstrike", "trend_micro"):
        n = sum(1 for a in snap.assets if snap.baseline_view(a) is not None
                and controls.state_from(c, t, a, snap)[0] not in controls.SHORT)
        alone = n if alone is None else max(alone, n)
    assert row["covered"] + row["unknown"] >= alone                     # never fewer devices than the better tool


def test_a_tools_own_field_name_is_read_through_its_declaration():
    assert caps.field_name("trend_micro", "edr.inventory", "last_seen") == "last_connected"
    assert caps.field_name("crowdstrike", "edr.inventory", "last_seen") == "last_seen"
    assert caps.field_name("forcepoint_dlp", "dlp.agents", "last_seen") == "last_checkin"
    assert caps.field_name("entra", "directory.users", "privileged") is None
    assert caps.read_field({"last_connected": "x"}, "trend_micro", "edr.inventory", "last_seen") == "x"
    assert caps.read_field({"privileged": True}, "entra", "directory.users", "privileged") is None


def test_the_dlp_workflow_reads_by_capability_not_by_product(session):
    from soc_platform.domains.dlp.service import CONTEXT_CAPABILITIES, INCIDENT_CAPABILITIES, DlpService

    reg = registry("directory_export", "crowdstrike", "forcepoint_dlp")
    svc = DlpService(session, reg, org_domains=["acme-demo.com"])
    out = svc.ingest()
    assert set(out["synced"]) == {f"{c.name}.{st}" for c, st in reg.providers(*CONTEXT_CAPABILITIES,
                                                                              *INCIDENT_CAPABILITIES)}
    assert "crowdstrike.hosts" in out["synced"] and "forcepoint_dlp.dlp_incidents" in out["synced"]


def test_no_workflow_names_a_product_in_its_tool_lists():
    """The constants that used to name products are gone; the code reads capabilities."""
    from soc_platform.domains.dlp import service as dlp
    from soc_platform.domains.incident import service as inc
    from soc_platform.domains.vulnerability import service as vuln
    from soc_platform.intelligence import ciso, crosstool, posture, risk

    for mod, gone in ((controls, "BASELINE_TOOL"), (dlp, "INVENTORY_STREAMS"), (inc, "INVENTORY_STREAMS"),
                      (vuln, "FINDING_STREAMS"), (ciso, "HEALTH_TOOLS"), (crosstool, "TOOL_LABEL"),
                      (posture, "DATA_PROTECTION_TOOLS"), (risk, "EDR_TOOLS")):
        assert not hasattr(mod, gone), (mod.__name__, gone)
    assert risk.edr_tools() == frozenset(caps.tools_for("edr.inventory", "edr.alerts"))
    assert ciso.health_tools(["trend_micro", "jira"]) == ["trend_micro"]


# ------------------------------------------------------------------ the capability matrix and readiness


def test_the_matrix_names_what_each_module_lacks():
    m = caps.matrix(registry("directory_export", "trend_micro"))
    by_mod = {x["module"]: x for x in m["modules"]}
    assert by_mod["dlp"]["ready"] is False and by_mod["dlp"]["missing_required"] == [["dlp.incidents"]]
    assert by_mod["posture"]["ready"] is True and "dlp.agents" in by_mod["posture"]["reduced_without"]
    assert m["ready"] is False
    edr = next(c for c in m["capabilities"] if c["capability"] == "edr.inventory")
    assert [p["tool"] for p in edr["provided_by"]] == ["trend_micro"] and "crowdstrike" in edr["available_from"]
    full = caps.matrix(ConnectorRegistry.all_fake())
    assert full["ready"] is True, [x for x in full["modules"] if not x["ready"]]


def test_the_capabilities_command_checks_readiness(tmp_path):
    cfg = tmp_path / "connectors.yaml"
    cfg.write_text("connectors:\n  directory_export: {enabled: true, stage: fake}\n", encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "soc_platform", "capabilities", "--check", "--json", "--config",
                          str(cfg)], check=False, capture_output=True, text=True, timeout=120)
    assert run.returncode == 1, run.stderr[-500:]
    doc = json.loads(run.stdout)
    assert any(not x["ready"] and x["module"] == "dlp" for x in doc["modules"])
    cfg.write_text("connectors:\n" + "".join(f"  {n}: {{enabled: true, stage: fake}}\n" for n in sorted(discover())),
                   encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "soc_platform", "capabilities", "--check", "--config", str(cfg)],
                         check=False, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, run.stdout[-800:] + run.stderr[-500:]
    assert "ready" in run.stdout.lower()
