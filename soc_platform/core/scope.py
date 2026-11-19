"""What this deployment offers: CyberDome for NAM, or the full inherited platform.

``SOC_PRODUCT_SCOPE``:

* ``nam`` (the default of this build) - only what NAM asked for: its tools (DLP, identity protection, EDR, disk
  encryption, the directory / CMDB baseline, ticketing, the SIEM / SOAR webhook), DLP triage with earned autonomy and
  the AI investigator, cross-tool cases, control coverage, tool health, configuration snapshots, the Dome Score and the
  CISO view - plus the platform essentials every module relies on: cases, approvals and actions, the autonomy policy,
  the AI gateway and its usage policy, watch lists, ownership, notifications, reports, access, the audit trail.
* ``full`` - every inherited module as well (phishing and its ML engine, vulnerability management, cloud posture,
  shadow IT, supplier risk, ATT&CK coverage, the tools of the earlier estate). The inherited test suite runs here.

Out of scope means: the connector is not offered (not listed, not built, not synced), the job is not scheduled, its API
routes answer 404 and its screens are not in the console. The code stays, so switching scope changes no data.
"""

from __future__ import annotations

import os

SCOPES = ("nam", "full")
DEFAULT = "nam"

# NAM's tools that have a connector (CLAUDE.md §0.1); Arcon, Cloudflare and the SOAR product join when they are built
NAM_CONNECTORS = frozenset({
    "forcepoint_dlp", "silverfort", "trend_micro", "trellix_epo", "directory_export",   # phase 1
    "servicenow", "jira", "cmdb_csv",                                                     # tickets, ownership
    "generic_siem",                     # alerts pushed by the SIEM / SOAR (product unknown; Sentinel joins if it is the one)
})
# jobs of the inherited modules (phishing, vulnerability management and the reports built from them)
FULL_ONLY_JOBS = frozenset({"vulnerability", "phishing", "follow_up", "daily_report"})
# API routes of those modules (path prefixes)
FULL_ONLY_ROUTES = ("/api/v1/phishing", "/api/v1/vm", "/api/v1/dashboard/attack-coverage", "/api/v1/dashboard/shadow-it")
# console screens of those modules (the ids of app.js NAV)
# (the inherited Overview counts phishing and vulnerabilities; the Dome Score is the NAM home screen)
FULL_ONLY_SCREENS = frozenset({"overview", "phishing", "vulnerabilities", "cloud", "coverage", "shadow-it", "suppliers"})
# report data sources that read only those modules
FULL_ONLY_SOURCES = frozenset({"vulnerability_posture", "top_vulnerabilities", "cloud_misconfigurations", "phishing",
                               "supplier_risk", "detection_coverage", "shadow_it"})


def current() -> str:
    v = (os.environ.get("SOC_PRODUCT_SCOPE") or DEFAULT).strip().lower()
    return v if v in SCOPES else DEFAULT


def is_full() -> bool:
    return current() == "full"


def connector_in_scope(name: str) -> bool:
    return is_full() or name in NAM_CONNECTORS


def job_in_scope(name: str) -> bool:
    return is_full() or name not in FULL_ONLY_JOBS


def route_in_scope(path: str) -> bool:
    return is_full() or not any(path == p or path.startswith(p + "/") for p in FULL_ONLY_ROUTES)


def source_in_scope(source: str) -> bool:
    return is_full() or source not in FULL_ONLY_SOURCES


def describe() -> dict[str, object]:
    """What the console needs: the scope and the screens it leaves out."""
    return {"scope": current(), "hidden_screens": [] if is_full() else sorted(FULL_ONLY_SCREENS)}
