"""The product scope: CyberDome for NAM offers NAM's tools and modules plus the platform essentials, and nothing of the
inherited modules (phishing, vulnerability management, cloud posture, shadow IT, supplier risk, ATT&CK coverage) -
not as a connector, a job, a route, a screen or a report section. The full scope keeps everything."""

from __future__ import annotations

import pytest

from soc_platform import jobs
from soc_platform.connectors.config_schema import check_entry
from soc_platform.connectors.registry import ConnectorRegistry, discover
from soc_platform.core import scope
from soc_platform.reporting import builder
from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture

INHERITED_TOOLS = {"crowdstrike", "defender_endpoint", "defender_office365", "avanan", "entra", "defender_identity",
                   "umbrella", "canary", "delinea", "rapid7", "wiz", "threat_intel", "nvd", "epss", "cisa_kev", "sentinel"}


@pytest.fixture()
def nam(monkeypatch):
    monkeypatch.setenv("SOC_PRODUCT_SCOPE", "nam")


def test_the_nam_scope_offers_only_nams_tools(nam):
    reg = ConnectorRegistry.all_fake()
    assert set(reg.enabled_names()) == set(scope.NAM_CONNECTORS) & set(discover())
    assert not set(reg.manifests) & INHERITED_TOOLS
    assert not set(ConnectorRegistry.from_file().configured_names()) & INHERITED_TOOLS
    with pytest.raises(KeyError):
        reg.get("crowdstrike")
    assert check_entry("crowdstrike", {"enabled": True}, reg.manifests) == []        # an entry left in the file is ignored
    assert check_entry("crowdstrikee", {"enabled": True}, reg.manifests)             # a typo still is an error


def test_the_full_scope_offers_every_installed_tool(monkeypatch):
    monkeypatch.setenv("SOC_PRODUCT_SCOPE", "full")
    assert set(ConnectorRegistry.all_fake().manifests) == set(discover())
    monkeypatch.setenv("SOC_PRODUCT_SCOPE", "something else")                         # unknown: the build's default
    assert scope.current() == scope.DEFAULT == "nam"


def test_the_inherited_jobs_are_not_scheduled_in_the_nam_scope(nam):
    assert set(jobs.active()) == set(jobs.JOBS) - scope.FULL_ONLY_JOBS
    assert jobs.active()[0] == "inventory"                                           # the baseline still reads first
    assert not set(jobs.due(10**12, {})) & scope.FULL_ONLY_JOBS


def test_the_phishing_engine_never_loads_outside_the_full_scope(nam, monkeypatch):
    from soc_platform.domains.phishing.agents.analyzer import engine_enabled

    monkeypatch.setenv("SOC_PHISHING_ENGINE", "1")
    assert engine_enabled() is False


def test_reports_offer_only_sections_the_scope_has(nam, session):
    offered = builder.sources()
    assert not set(offered) & scope.FULL_ONLY_SOURCES and {"posture", "data_protection", "governance"} <= set(offered)
    ids = {t["id"] for t in builder.list_templates(session)}
    assert {"cyberdome_board_monthly", "cyberdome_ciso_weekly"} <= ids and "board_monthly" not in ids
    assert builder.get_template(session, "vm_weekly") is None
    with pytest.raises(ValueError):
        builder.validate_spec({"sections": [{"source": "phishing"}]})
    plan = builder.plan_report("a one-page board brief on our posture and data leaks", None)
    assert plan["sections"][0]["source"] == "posture" and all(s["source"] in offered for s in plan["sections"])
    assert builder.plan_report("phishing and vulnerabilities", None)["sections"]          # never an empty plan


def test_the_api_has_no_route_screen_or_job_of_an_inherited_module(client, monkeypatch):  # noqa: F811
    from soc_platform.api import app as appmod

    monkeypatch.setenv("SOC_PRODUCT_SCOPE", "nam")
    appmod.registry.cache_clear()
    try:
        lead, ops = tok(client, "lena", "lead"), tok(client, "otto", "automation_admin")
        for path in ("/api/v1/vm/findings", "/api/v1/phishing/metrics", "/api/v1/dashboard/shadow-it",
                     "/api/v1/dashboard/attack-coverage"):
            r = client.get(path, headers=lead)
            assert r.status_code == 404 and r.headers.get("X-Content-Type-Options") == "nosniff", path
        assert client.post("/api/v1/phishing/ingest", headers=lead).status_code == 404
        me = client.get("/api/v1/me", headers=lead).json()["product"]
        assert me["scope"] == "nam" and {"phishing", "vulnerabilities", "overview"} <= set(me["hidden_screens"])
        assert {c["name"] for c in client.get("/api/v1/connectors", headers=lead).json()} <= scope.NAM_CONNECTORS
        assert not set(client.get("/api/v1/jobs", headers=lead).json()["jobs"]) & scope.FULL_ONLY_JOBS
        assert client.post("/api/v1/jobs/vulnerability/run", headers=ops).status_code == 404
        assert client.get("/api/v1/dashboard/ciso", headers=lead).status_code == 200
        assert client.get("/api/v1/audit", headers=lead).status_code in (200, 403)    # the essentials stay
    finally:
        monkeypatch.setenv("SOC_PRODUCT_SCOPE", "full")
        appmod.registry.cache_clear()
    assert client.get("/api/v1/me", headers=lead).json()["product"] == {"scope": "full", "hidden_screens": []}
