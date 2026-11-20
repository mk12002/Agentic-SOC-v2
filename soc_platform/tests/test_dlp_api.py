"""The data-protection, decision, coverage and CISO routes: who may read and do what, what each answers, and that
the one screen for the CISO shows the same figures as the screens behind it."""

from __future__ import annotations

from soc_platform.tests.test_watchlists import client, tok  # noqa: F401 - the module-scoped API client fixture


def J(r):
    assert r.status_code == 200, (str(r.request.url), r.status_code, r.text[:300])
    return r.json()


def test_the_dlp_queue_runs_reads_and_takes_a_ruling_within_scope(client):  # noqa: F811 - the imported fixture
    analyst, auditor = tok(client, "dana", "analyst", "dlp"), tok(client, "audrey", "auditor")
    phishing_only = tok(client, "pia", "analyst", "phishing")
    for path in ("/api/v1/dlp/summary", "/api/v1/dlp/alerts", "/api/v1/decisions"):
        assert client.get(path, headers=phishing_only).status_code == 403            # another domain's data
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/dlp/run", headers=auditor).status_code == 403        # reading is not investigating
    assert client.post("/api/v1/dlp/run", headers=phishing_only).status_code == 403
    before = J(client.get("/api/v1/dlp/summary", headers=auditor))["alerts"]   # another test may have run it already
    run = J(client.post("/api/v1/dlp/run", headers=analyst))
    assert not run["errors"] and run["ai_decided"] == 0
    assert before or (run["new_alerts"] > 0 and run["escalated"] > 0)            # a first run judges the sample
    again = J(client.post("/api/v1/dlp/run", headers=analyst))
    assert (again["new_alerts"], again["escalated"]) == (0, 0)                       # a second run changes nothing
    sm = J(client.get("/api/v1/dlp/summary", headers=auditor))
    assert sm["alerts"] == before + run["new_alerts"] == sum(sm["by_status"].values()) == sum(sm["by_computed"].values()) > 0
    assert sm["model"] == "off" and {t["stage"] for t in sm["decision_types"]} == {"shadow"}
    listed = J(client.get("/api/v1/dlp/alerts?limit=500", headers=analyst))
    assert listed["total"] == sm["alerts"] == len(listed["items"])
    for st, n in sm["by_status"].items():
        assert J(client.get(f"/api/v1/dlp/alerts?status={st}", headers=analyst))["total"] == n
    assert client.get("/api/v1/dlp/alerts?status=deleted", headers=analyst).status_code == 422
    waiting = next(a for a in listed["items"] if a["computed"]["outcome"] == "review" and not a["analyst"])
    one = J(client.get(f"/api/v1/dlp/alerts/{waiting['id']}", headers=analyst))
    assert one["id"] == waiting["id"] and one["evidence"] and one["untrusted"]["file_names"] and one["ai"] is None
    url = f"/api/v1/dlp/alerts/{waiting['id']}/decision"
    assert client.post(url, headers=auditor, json={"outcome": "escalate"}).status_code == 403
    assert client.post(url, headers=analyst, json={"outcome": "delete"}).status_code == 422
    assert client.post(url, headers=analyst, json={"outcome": "escalate", "reason": "x" * 2001}).status_code == 422
    ruled = J(client.post(url, headers=analyst, json={"outcome": "escalate", "reason": "not expected"}))
    assert ruled["status"] == "escalated" and ruled["analyst"]["outcome"] == "escalate" and ruled["case_id"]
    # the case it opened is a data-protection case: visible within that scope only
    assert J(client.get(f"/api/v1/cases/{ruled['case_id']}", headers=analyst))["case"]["domain"] == "dlp"
    assert client.get(f"/api/v1/cases/{ruled['case_id']}", headers=phishing_only).status_code == 404
    assert ruled["case_id"] in {c["id"] for c in J(client.get("/api/v1/cases?domain=dlp", headers=analyst))}
    assert ruled["case_id"] not in {c["id"] for c in J(client.get("/api/v1/cases", headers=phishing_only))}
    for bogus in ("does-not-exist", "0" * 32):
        assert client.get(f"/api/v1/dlp/alerts/{bogus}", headers=analyst).status_code == 404
        assert client.post(f"/api/v1/dlp/alerts/{bogus}/decision", headers=analyst, json={"outcome": "escalate"}).status_code == 404


def test_only_leads_change_how_far_the_ai_is_trusted_and_the_api_refuses_what_the_store_refuses(client):  # noqa: F811
    lead1, lead2 = tok(client, "lead.one", "lead"), tok(client, "lead.two", "lead")
    analyst, vm_lead = tok(client, "dana", "analyst"), tok(client, "vic", "lead", "vulnerability")
    target = "/api/v1/decisions/dlp.email/target"
    for who in (analyst, vm_lead):
        assert client.put(target, headers=who, json={"agreement_percent": 90, "min_sample": 50}).status_code == 403
        assert client.post("/api/v1/decisions/dlp.email/stage", headers=who, json={"stage": "recommend"}).status_code == 403
    assert client.put(target, headers=lead1, json={"agreement_percent": 10, "min_sample": 50}).status_code == 400
    assert client.put("/api/v1/decisions/dlp.nothing/target", headers=lead1,
                      json={"agreement_percent": 90, "min_sample": 50}).status_code == 404
    assert J(client.put(target, headers=lead1, json={"agreement_percent": 90, "min_sample": 50})) == {
        "agreement_percent": 90, "min_sample": 50}
    view = J(client.get("/api/v1/decisions", headers=analyst))
    email = next(t for t in view["types"] if t["decision_type"] == "dlp.email")
    assert email["target"] == {"agreement_percent": 90, "min_sample": 50} and not email["eligible"]
    assert view["available_stages"] == ["shadow", "recommend"] and view["stages"][-1] == "decide"
    r = client.post("/api/v1/decisions/dlp.email/stage", headers=lead1, json={"stage": "recommend"})
    assert r.status_code == 400 and "not ready" in r.json()["detail"]                # nothing measured yet
    r = client.post("/api/v1/decisions/dlp.email/stage", headers=lead1, json={"stage": "decide"})
    assert r.status_code == 400 and "not available" in r.json()["detail"]
    assert client.post("/api/v1/decisions/proposals/999999/approve", headers=lead2, json={}).status_code == 404
    assert client.post("/api/v1/decisions/proposals/1/frobnicate", headers=lead2, json={}).status_code == 404
    assert client.post("/api/v1/decisions/proposals/99999999999999999999/approve", headers=lead2, json={}).status_code == 404


def test_the_ciso_view_shows_the_figures_of_the_screens_behind_it(client):  # noqa: F811 - the imported fixture
    lead, ops = tok(client, "lena", "lead"), tok(client, "ops", "automation_admin")
    scoped = tok(client, "dana", "analyst", "dlp")
    J(client.post("/api/v1/dlp/run", headers=lead))
    assert J(client.post("/api/v1/jobs/posture/run", headers=ops))["status"] == "ok"
    assert client.get("/api/v1/dashboard/ciso", headers=scoped).status_code == 403   # spans every domain
    assert client.get("/api/v1/dashboard/posture", headers=scoped).status_code == 403
    ciso = J(client.get("/api/v1/dashboard/ciso", headers=lead))
    cov = J(client.get("/api/v1/dashboard/control-coverage", headers=lead))
    health = J(client.get("/api/v1/dashboard/tool-health", headers=lead))
    pos = J(client.get("/api/v1/dashboard/posture", headers=lead))
    sm = J(client.get("/api/v1/dlp/summary", headers=lead))
    assert {k: v for k, v in ciso["posture"].items() if k != "movement"} == pos and pos["score"] is not None and pos["trend"]["points"][-1]["score"] == pos["score"]
    assert ciso["coverage"]["coverage_percent"] == cov["coverage_percent"] == pos["coverage_percent"]
    assert ciso["coverage"]["devices_short_count"] == cov["devices_short_count"] == len(cov["devices_short"])
    assert ciso["coverage"]["devices_short"] == cov["devices_short"][:5]
    assert ciso["tool_health"] == health and health["counts"]["critical"] >= 1
    shared = set(ciso["dlp"]) - {"week", "people"}                                  # the CISO view adds the week and the people
    assert {k: ciso["dlp"][k] for k in shared} == {k: sm[k] for k in shared}
    cases = J(client.get("/api/v1/cases", headers=lead))
    open_critical = sum(c["severity"] == "critical" and c["status"] != "closed" for c in cases)
    assert ciso["cases"]["critical"] == open_critical >= 1
    assert all(c["severity"] in ("critical", "high") for c in ciso["cases"]["items"])
    assert [c["severity"] for c in ciso["cases"]["items"]] == sorted((c["severity"] for c in ciso["cases"]["items"]), key=["critical", "high"].index)
    # coverage and tool health are open to every signed-in role; the DLP count on a device only within DLP scope
    other = J(client.get("/api/v1/dashboard/control-coverage", headers=tok(client, "pia", "analyst", "phishing")))
    assert other["coverage_percent"] == cov["coverage_percent"]
    assert {d["personal_data_alerts"] for d in other["devices_short"]} == {None}
    assert any(d["personal_data_alerts"] for d in cov["devices_short"])
    assert J(client.get("/api/v1/dashboard/tool-health", headers=scoped)) == health


def test_the_new_jobs_run_are_idempotent_and_their_settings_are_known(client):  # noqa: F811 - the imported fixture
    from soc_platform import jobs
    from soc_platform.llm.usage_policy import KNOWN_WORKFLOWS
    from soc_platform.settings_check import JOB_SECONDS, SPEC

    ops = tok(client, "ops", "automation_admin")
    assert jobs.JOBS["dlp"] == ("SOC_JOB_DLP_SECONDS", 300) and jobs.JOBS["posture"] == ("SOC_JOB_POSTURE_SECONDS", 3600)
    names = list(jobs.JOBS)
    # the baseline before anything names a host, exposure before alerts are judged, the score last
    assert names[0] == "inventory" and names.index("vulnerability") < names.index("dlp") < names.index("posture")
    assert {"SOC_JOB_DLP_SECONDS", "SOC_JOB_POSTURE_SECONDS", "SOC_JOB_INVENTORY_SECONDS"} <= JOB_SECONDS
    assert J(client.post("/api/v1/jobs/inventory/run", headers=ops))["status"] == "ok"
    assert {"SOC_AGENT_SILENT_HOURS", "SOC_CERT_WARN_DAYS", "SOC_CERT_CRITICAL_DAYS", "SOC_DLP_AI_MAX_PER_RUN"} <= set(SPEC)
    assert KNOWN_WORKFLOWS["dlp.disposition"][:2] == ("small", "scheduled")
    first = J(client.post("/api/v1/jobs/dlp/run", headers=ops))
    assert first["status"] == "ok", first
    before = J(client.get("/api/v1/dlp/summary", headers=ops))
    second = J(client.post("/api/v1/jobs/dlp/run", headers=ops))
    assert second["status"] == "ok" and second["summary"]["new_alerts"] == 0 and second["summary"]["demoted"] == []
    assert J(client.get("/api/v1/dlp/summary", headers=ops)) == before
