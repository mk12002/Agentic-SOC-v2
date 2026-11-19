"""Paging and resume for the data-protection stack's connectors (directory export, Forcepoint DLP, Silverfort, Trend
Micro, Trellix ePO), and what each stream means. The shared suite in test_connector_conformance.py also runs
throttling, token renewal, missing-permission and missing-field checks on them automatically."""

import pytest
from sqlalchemy import select

from soc_platform.connectors.registry import ConnectorRegistry
from soc_platform.core.models import Entity
from soc_platform.tests.test_connector_conformance import (
    asked_from,
    at_least,
    calls_to,
    demo_routes,
    fresh,
    reroute,
    stamp,
    sync,
)

NAMES = ("directory_export", "forcepoint_dlp", "silverfort", "trend_micro", "trellix_epo")
STREAMS = [(n, s) for n in NAMES for s in ConnectorRegistry.all_fake().get(n).streams]
# read by the shared coverage test: every stream of every connector needs a paging test
PAGING_TESTED = set(STREAMS)


def _route(name: str, stream: str) -> dict:
    path = ConnectorRegistry.all_fake().get(name).path_of(stream)
    return next(r for r in demo_routes(name) if r["path"] == f"^{path}$")


@pytest.mark.parametrize("name,stream", STREAMS, ids=[f"{a}.{b}" for a, b in STREAMS])
def test_streams_page_with_tokens_and_never_keep_one_between_syncs(session, name, stream):
    src = _route(name, stream)
    path = src["path"].strip("^$")
    changed = ConnectorRegistry.all_fake().get(name).STREAMS[stream][1]
    items = at_least(src["body"]["items"])
    for i, it in enumerate(items):                       # clones need their own identifier, whatever it is called
        for k in ("agent_guid", "node_id"):
            if k in it:
                it[k] = f"{it[k]}-{i}"
    newest = stamp(items, changed) if changed else None
    routes = [{**src, "times": 1, "body": {"items": items[:2], "next_page_token": "p2"}},
              {**src, "body": {"items": items[2:]}}]
    conn = fresh(name, routes)
    rep, cp = sync(session, conn, stream)
    assert not rep.errors and rep.ingested == len(items), rep.errors
    assert calls_to(conn.http, path, "GET")[1]["params"]["page_token"] == "p2"
    t = reroute(conn, routes)
    sync(session, conn, stream)
    first = calls_to(t, path, "GET")[0]["params"]
    assert "page_token" not in first                              # a token is never the next sync's start
    if changed:                                                   # events resume from the newest change time seen
        assert cp.cursor == f"since:{newest}" and first["updated_since"] == asked_from(newest)
    else:                                                         # inventories and health are read in full
        assert cp.cursor is None and "updated_since" not in first


def test_every_endpoint_path_is_a_declared_setting_marked_to_be_confirmed():
    reg = ConnectorRegistry.all_fake()
    for name in NAMES:
        m, conn = reg.manifests[name], reg.get(name)
        declared = {f.name: f for f in m.config}
        for stream in conn.streams:
            assert f"{stream}_path" in declared and not declared[f"{stream}_path"].required
            assert "confirmed" in declared[f"{stream}_path"].description
        assert m.confidence == "Unknown" and m.to_confirm


ACTIONS = {"silverfort": {"identity.revoke_sessions", "identity.require_mfa", "identity.release_mfa"},
           "trend_micro": {"endpoint.isolate", "endpoint.release"}}


def test_the_stack_adds_no_lookup_or_alert_kind_the_other_workflows_read_and_only_the_planned_actions(session):
    """These tools feed the data-protection and cross-tool workflows: no enrichment look-up and no record of a kind the
    incident, phishing or risk pipelines read (endpoint alerts are ``edr_alert``, not ``alert``), so adding them changes
    none of those workflows' results. Their actions are exactly the planned ones, recommended (L2) by default and
    isolation four-eyes."""
    from soc_platform.core.policy import DEFAULT_POLICY

    reg = ConnectorRegistry.all_fake()
    for name in NAMES:
        conn = reg.get(name)
        assert not conn.lookups
        assert {a.action_type for a in reg.manifests[name].actions(conn)} == ACTIONS.get(name, set())
        for stream in conn.streams:
            sync(session, conn, stream)
    kinds = {k for (k,) in session.execute(select(Entity.kind).distinct()).all()}
    assert kinds <= {"asset", "identity", "dlp_incident", "auth_risk", "tool_health", "edr_alert"}, kinds
    for t in set().union(*ACTIONS.values()):
        assert DEFAULT_POLICY["actions"][t]["level"] == 2
    assert DEFAULT_POLICY["actions"]["endpoint.isolate"]["four_eyes"] is True


def test_one_device_seen_by_four_tools_is_one_record(session):
    reg = ConnectorRegistry.all_fake()
    for name, stream in (("directory_export", "devices"), ("trend_micro", "endpoints"), ("forcepoint_dlp", "endpoints"),
                         ("trellix_epo", "systems")):
        rep, _ = sync(session, reg.get(name), stream)
        assert not rep.errors, rep.errors
    assets = session.execute(select(Entity).where(Entity.kind == "asset")).scalars().all()
    baseline = [a for a in assets if "directory_export" in (a.attributes or {}).get("by_tool", {})]
    listed = len(_route("directory_export", "devices")["body"]["items"])
    assert len(baseline) == listed                                # no device split in two, none merged
    seen_by = [set((a.attributes or {}).get("by_tool", {})) for a in baseline]
    assert any(len(s) == 4 for s in seen_by)
    # a device a tool reports that the directory does not list stays its own record
    assert len(assets) == listed + 1
