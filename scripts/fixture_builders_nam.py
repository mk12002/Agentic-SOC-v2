"""Fixture builders for the data-protection stack (directory export, Forcepoint DLP, Silverfort, Trend Micro, Trellix
ePO) - same organisation, people, devices and day as build_fixtures.py, so the estate builders rename them with the
rest.

The storyline (alert-title level only): the person whose account was phished at 09:02 signs in from an unmanaged
device; minutes later an e-mail with investor records to a personal address is quarantined; the sending laptop has
disk encryption off. Around it: one noisy rule a partner's invoices trip, a few alerts that need a person, four devices
missing a control, a certificate close to expiry and a directory import that left two people out of every policy.

Placeholder shapes: the vendors' real response formats replace these once each tool's API is confirmed.
"""

from __future__ import annotations

import sys

from build_fixtures import HOSTS, ORG, USERS, D, route


def write(name: str, routes: list[dict]) -> None:
    """Write through the build_fixtures module as it is loaded *now*: the estate builders load a fresh copy for every
    estate and point its output folder elsewhere, while this module stays imported - a ``write`` bound at import
    would keep writing into the first estate's folder."""
    sys.modules["build_fixtures"].write(name, routes)

LAPTOPS = {
    "jane": {"hostname": HOSTS["jane"]["hostname"], "ip": HOSTS["jane"]["ip"], "serial": HOSTS["jane"]["serial"]},
    "bob": {"hostname": HOSTS["bob"]["hostname"], "ip": HOSTS["bob"]["ip"], "serial": HOSTS["bob"]["serial"]},
    "priya": {"hostname": "PRIYA-LT07", "ip": "10.20.1.31", "serial": "5CG3107QRT"},
    "arun": {"hostname": "ARUN-LT05", "ip": "10.20.1.41", "serial": "5CG4105QRT"},
    "meera": {"hostname": "MEERA-LT06", "ip": "10.20.1.44", "serial": "5CG4406QRT"},
    "tom": {"hostname": "TOM-LT07", "ip": "10.20.1.47", "serial": "5CG4707QRT"},
    "li": {"hostname": "LI-DEV08", "ip": "10.20.1.52", "serial": "5CG5208QRT"},
}
SERVERS = ("web01", "db01", "fs01")
UNLISTED = {"hostname": "KIOSK-RC01", "ip": "10.20.1.90", "serial": "5CG9001QRT"}   # seen by the EDR, not in the directory
NO_EDR = {"arun"}
NO_DLP_AGENT = {"tom"}
SILENT_DLP_AGENT = {"priya"}
ENCRYPTION_OFF = {"jane"}
PERSONAL_MAIL = "protonmail.example"       # a personal mailbox provider, under a domain reserved for examples


def _fqdn(name: str) -> str:
    return f"{name.lower()}.{ORG}"


def _page(items: list[dict]) -> dict:
    return {"items": items, "next_page_token": None}


def directory_export() -> None:
    devices = [{"id": f"ad-dev-{k}", "name": lt["hostname"], "dns_name": _fqdn(lt["hostname"]), "ip": lt["ip"],
                "os": "Windows 11 Enterprise", "ou": "Workstations", "enabled": True, "serial_number": lt["serial"],
                "last_logon": f"{D}08:{10 + i}:00Z", "managed_by": USERS[k]["upn"]}
               for i, (k, lt) in enumerate(LAPTOPS.items())]
    devices += [{"id": f"ad-dev-{k}", "name": HOSTS[k]["hostname"], "dns_name": HOSTS[k]["fqdn"], "ip": HOSTS[k]["ip"],
                 "os": HOSTS[k]["os"], "ou": "Servers", "enabled": True, "serial_number": HOSTS[k]["serial"],
                 "last_logon": f"{D}06:0{i}:00Z", "managed_by": None} for i, k in enumerate(SERVERS)]
    groups = {"jane": ["Finance Team", "DLP-Policy-Finance"], "bob": ["IT Team", "Domain Admins", "DLP-Policy-IT"],
              "raj": ["Executive Team", "DLP-Policy-Executive"], "priya": ["Finance Team", "DLP-Policy-Finance"],
              "arun": ["Sales Team", "DLP-Policy-Sales"], "meera": ["HR Team"], "tom": ["Legal Team"],
              "li": ["Engineering Team", "DLP-Policy-Engineering"]}
    users = [{"id": f"ad-user-{k}", "upn": u["upn"], "sam": u["upn"].split("@")[0], "display_name": u["name"],
              "department": u["dept"], "title": u["title"], "enabled": True, "groups": groups[k]}
             for k, u in USERS.items()]
    write("directory_export", [route("GET", r"^/api/v1/devices$", _page(devices)),
                               route("GET", r"^/api/v1/users$", _page(users))])


def trend_micro() -> None:
    def agent(i: int, name: str, ip: str, serial: str, os_name: str) -> dict:
        return {"agent_guid": f"tm-agent-{i:04d}", "endpoint_name": name, "fqdn": _fqdn(name), "ip": ip,
                "os_name": os_name, "serial_number": serial, "agent_version": "14.0.12980",
                "agent_status": "online", "last_connected": f"{D}09:{20 + i}:00Z"}

    items = [agent(i, lt["hostname"], lt["ip"], lt["serial"], "Windows 11 Enterprise")
             for i, (k, lt) in enumerate(LAPTOPS.items()) if k not in NO_EDR]
    items += [agent(20 + i, HOSTS[k]["hostname"], HOSTS[k]["ip"], HOSTS[k]["serial"], HOSTS[k]["os"])
              for i, k in enumerate(SERVERS)]
    items.append(agent(40, UNLISTED["hostname"], UNLISTED["ip"], UNLISTED["serial"], "Windows 10 IoT Enterprise"))
    guid = {k: f"tm-agent-{i:04d}" for i, k in enumerate(LAPTOPS) if k not in NO_EDR}

    def alert(n: int, who: str, at: str, sev: str, title: str, category: str, action: str) -> dict:
        return {"id": f"tm-alert-{n:04d}", "created_at": f"{D}{at}Z", "updated_at": f"{D}{at}Z", "severity": sev,
                "title": title, "category": category, "action": action, "status": "new", "user": USERS[who]["upn"],
                "endpoint": {"agent_guid": guid[who], "name": LAPTOPS[who]["hostname"], "ip": LAPTOPS[who]["ip"]}}

    # alert-title level only: the phished person's laptop packs many documents just after the risky sign-in
    alerts = [alert(1, "jane", "09:08:40", "medium", "Archive utility compressed many documents", "data staging", "logged"),
              alert(2, "li", "13:30:05", "low", "Potentially unwanted application", "pua", "quarantined")]
    write("trend_micro", [route("GET", r"^/api/v1/endpoints$", _page(items)),
                          route("GET", r"^/api/v1/alerts$", _page(alerts)),
                          route("POST", r"^/api/v1/endpoints/[^/]+/(isolate|restore)$", {"status": "accepted"})])


def trellix_epo() -> None:
    systems = [{"node_id": f"epo-node-{i:04d}", "name": lt["hostname"], "fqdn": _fqdn(lt["hostname"]), "ip": lt["ip"],
                "os": "Windows 11 Enterprise", "serial_number": lt["serial"], "last_communication": f"{D}09:{10 + i}:00Z",
                "encryption": {"state": "Not encrypted" if k in ENCRYPTION_OFF else "Encrypted", "product_version": "7.4.1"}}
               for i, (k, lt) in enumerate(LAPTOPS.items())]
    health = [{"id": "epo-cert-agent-handler", "type": "certificate", "name": "Agent handler certificate",
               "status": "valid", "expires_at": "2027-06-01T00:00:00Z", "reported_at": f"{D}09:30:00Z"},
              {"id": "epo-task-encryption-status", "type": "sync_job", "name": "Encryption status collection",
               "status": "ok", "last_run": f"{D}08:00:00Z", "interval_minutes": 240, "reported_at": f"{D}09:30:00Z"}]
    policies = [{"id": "epo-pol-de-workstations", "name": "Drive encryption - workstations", "product": "Drive Encryption",
                 "assigned_to": "Workstations", "settings": {"encrypt": "all disks", "algorithm": "AES-256",
                                                             "pre_boot_authentication": True}},
                {"id": "epo-pol-de-servers", "name": "Drive encryption - servers", "product": "Drive Encryption",
                 "assigned_to": "Servers", "settings": {"encrypt": "none"}}]
    write("trellix_epo", [route("GET", r"^/api/v1/systems$", _page(systems)),
                          route("GET", r"^/api/v1/server/health$", _page(health)),
                          route("GET", r"^/api/v1/policies$", _page(policies))])


def silverfort() -> None:
    def ev(n: int, who: str, at: str, level: str, factors: list[str], *, host: str | None, ip: str,
           managed: bool, mfa: str = "passed") -> dict:
        return {"id": f"sf-risk-{n:04d}", "event_time": f"{D}{at}Z", "user": USERS[who]["upn"], "source_host": host,
                "source_ip": ip, "destination": "portal", "protocol": "kerberos" if managed else "oidc",
                "result": "allowed", "mfa": mfa, "risk_level": level, "risk_factors": factors, "device_managed": managed}

    items = [ev(1, "priya", "07:55:10", "low", [], host=LAPTOPS["priya"]["hostname"], ip=LAPTOPS["priya"]["ip"], managed=True),
             ev(2, "bob", "08:15:42", "low", [], host=LAPTOPS["bob"]["hostname"], ip=LAPTOPS["bob"]["ip"], managed=True),
             ev(3, "jane", "09:02:31", "high", ["unmanaged device", "new source address"], host=None,
                ip="203.0.113.77", managed=False, mfa="not required"),
             ev(4, "arun", "10:01:05", "medium", ["unusual time for this person"], host=LAPTOPS["arun"]["hostname"],
                ip=LAPTOPS["arun"]["ip"], managed=True)]
    policies = [{"id": "sf-pol-admins-mfa", "name": "MFA for privileged accounts", "enabled": True, "action": "mfa",
                 "applies_to": "Domain Admins", "risk_threshold": "low"},
                {"id": "sf-pol-risky-mfa", "name": "MFA on high-risk sign-in", "enabled": True, "action": "mfa",
                 "applies_to": "All users", "risk_threshold": "high"}]
    write("silverfort", [route("GET", r"^/api/v1/risk/events$", _page(items)),
                         route("GET", r"^/api/v1/policies$", _page(policies)),
                         route("POST", r"^/api/v1/users/[^/]+/(sessions/revoke|mfa)$", {"status": "ok"})])


def forcepoint_dlp() -> None:
    endpoints = [{"id": f"fp-ep-{i:04d}", "hostname": lt["hostname"], "fqdn": _fqdn(lt["hostname"]), "ip": lt["ip"],
                  "agent_version": "23.11.5661", "profile": "Corporate laptops",
                  "status": "disconnected" if k in SILENT_DLP_AGENT else "connected",
                  "last_checkin": "2026-09-17T16:40:00Z" if k in SILENT_DLP_AGENT else f"{D}09:{12 + i}:00Z"}
                 for i, (k, lt) in enumerate(LAPTOPS.items()) if k not in NO_DLP_AGENT]
    at = f"{D}09:30:00Z"
    health = [{"id": "fp-cert-manager-ssl", "type": "certificate", "name": "Security Manager SSL certificate",
               "status": "valid", "expires_at": "2026-09-29T09:30:00Z", "reported_at": at},
              {"id": "fp-sync-directory", "type": "directory_sync", "name": "User directory import",
               "status": "completed_with_errors", "last_run": f"{D}06:00:00Z", "interval_minutes": 1440,
               "unmapped_users": [USERS["meera"]["upn"], USERS["tom"]["upn"]], "reported_at": at,
               "detail": "2 accounts could not be mapped to a policy group"},
              {"id": "fp-sync-incident-db", "type": "sync_job", "name": "Incident database replication", "status": "ok",
               "last_run": f"{D}06:30:00Z", "interval_minutes": 240, "reported_at": at},
              {"id": "fp-sync-policy-deploy", "type": "sync_job", "name": "Policy deployment to endpoints", "status": "ok",
               "last_run": f"{D}07:00:00Z", "interval_minutes": 1440, "reported_at": at}]

    # each classifier's type as the configuration reports it (placeholder vocabulary: see forcepoint_dlp.py)
    ctype = {"India PAN": "regex", "Investor account number": "exact_data_match", "Credit card number (wide)": "regex",
             "Customer contact list": "file_fingerprint", "Salary figures": "regex", "Legal privilege marking": "keyword",
             "Source code": "machine_learning", "Confidential marking": "keyword", "Employee directory": "file_fingerprint",
             "Aadhaar number": "regex", "Passport number": "regex"}

    def inc(n: int, who: str, at: str, severity: str, channel: str, action: str, policy: str, rule: str,
            classifiers: list[tuple[str, int]], dest_kind: str, dest: str, *, subject: str | None = None,
            files: list[str] | None = None, resolution: str | None = None, size: int = 48_000, ocr: bool = False) -> dict:
        return {"id": 881000 + n, "event_time": f"{D}{at}Z", "updated_at": f"{D}{at}Z", "severity": severity,
                "channel": channel, "action": action, "status": "CLOSED" if resolution else "NEW", "policy": policy,
                "rule": rule, "classifiers": [{"name": c, "matches": m, "type": ctype[c], **({"ocr": True} if ocr else {})}
                                              for c, m in classifiers],
                "source": {"user": USERS[who]["upn"], "hostname": LAPTOPS[who]["hostname"] if who in LAPTOPS else None,
                           "ip": LAPTOPS[who]["ip"] if who in LAPTOPS else None},
                "destination": {"kind": dest_kind, "value": dest}, "subject": subject, "file_names": files or [],
                "size_bytes": size, "resolution": resolution, "resolved_by": "dlp.analyst" if resolution else None}

    card = ("Payment card data", "Card-like numbers in outbound mail", [("Credit card number (wide)", 2)])
    partner = "accounts@krishna-logistics.com"
    incidents = [
        inc(1, "jane", "09:11:04", "HIGH", "EMAIL", "QUARANTINED", "Investor personal data",
            "PAN numbers to external recipients", [("India PAN", 3980), ("Investor account number", 3980)],
            "email", f"jane.doe.home@{PERSONAL_MAIL}", subject="Approved transfer per manager - reconciliation extract",
            files=["investor_master_q3.xlsx"], size=2_400_000),
        *[inc(10 + i, "priya", f"08:{5 + 7 * i:02d}:10", "LOW", "EMAIL", "PERMITTED", card[0], card[1], card[2], "email",
              partner, subject=f"Remittance advice for invoice {4471 + i}", files=[f"remittance_{4471 + i}.pdf"],
              resolution="False Positive" if i < 4 else None, ocr=True) for i in range(6)],   # scanned PDFs
        inc(20, "arun", "10:05:40", "MEDIUM", "WEB", "PERMITTED", "Customer lists", "Customer contact list to cloud storage",
            [("Customer contact list", 240)], "url", "https://www.dropbox.com/upload", files=["client_contacts.csv"]),
        inc(21, "meera", "11:20:15", "LOW", "EMAIL", "PERMITTED", "HR records", "Salary data in mail",
            [("Salary figures", 6)], "email", USERS["tom"]["upn"], subject="Offer letter review", files=["offer_draft.docx"]),
        inc(22, "tom", "12:10:00", "MEDIUM", "USB", "BLOCKED", "Legal documents", "Privileged documents to removable media",
            [("Legal privilege marking", 12)], "device", "USB mass storage", files=["contracts_2026.zip"]),
        inc(23, "li", "13:02:30", "LOW", "WEB", "PERMITTED", "Source code", "Source code to code hosting",
            [("Source code", 40)], "url", "https://github.com/", files=["build_scripts.tar"]),
        inc(24, "raj", "14:15:00", "LOW", "EMAIL", "PERMITTED", "Confidential markings", "Confidential document in mail",
            [("Confidential marking", 1)], "email", f"raj.mehta.home@{PERSONAL_MAIL}", subject="Board pack for the weekend",
            files=["board_pack_sept.pdf"]),
        inc(25, "bob", "15:40:20", "MEDIUM", "WEB", "PERMITTED", "Employee data", "Employee directory to file transfer",
            [("Employee directory", 300)], "url", "https://transfer.example.net/upload", files=["staff_export.csv"]),
        inc(26, "priya", "16:05:00", "LOW", "EMAIL", "PERMITTED", "Investor personal data", "Aadhaar number in mail",
            [("Aadhaar number", 2)], "email", USERS["meera"]["upn"], subject="Vendor onboarding form",
            files=["onboarding.pdf"]),
    ]
    # the rules as configured (the configuration export); every rule the incidents name, plus one quiet rule
    seen: dict[str, dict] = {}
    for i in incidents:
        seen.setdefault(i["rule"], {"policy": i["policy"], "severity": i["severity"].lower(), "channel": i["channel"].lower(),
                                    "classifiers": sorted({c["name"] for c in i["classifiers"]})})
    seen["Passport scans to cloud storage"] = {"policy": "Investor personal data", "severity": "medium", "channel": "web",
                                               "classifiers": ["Passport number"]}
    rules = [{"id": f"fp-rule-{n + 1:03d}", "name": name, "policy": r["policy"], "enabled": True, "channel": r["channel"],
              "classifiers": r["classifiers"], "classifier_types": {c: ctype[c] for c in r["classifiers"]},
              "ocr_enabled": True, "threshold": 1, "action": "audit" if r["severity"] == "low" else "block",
              "severity": r["severity"], "excluded_destinations": [], "modified_at": "2026-08-01T10:00:00Z"}
             for n, (name, r) in enumerate(sorted(seen.items()))]
    write("forcepoint_dlp", [route("GET", r"^/api/v1/incidents$", _page(incidents)),
                             route("GET", r"^/api/v1/endpoints$", _page(endpoints)),
                             route("GET", r"^/api/v1/system/health$", _page(health)),
                             route("GET", r"^/api/v1/policies/rules$", _page(rules))])


BUILDERS = [directory_export, forcepoint_dlp, silverfort, trend_micro, trellix_epo]
