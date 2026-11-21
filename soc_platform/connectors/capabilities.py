"""Capabilities: what a tool provides, named once, so a workflow never names a product.

A capability is a contract: the record kinds a stream delivers into the canonical schema and the attribute names a
workflow may read from them. A connector's manifest declares which of its streams provide which capability
(``ConnectorManifest.provides``), mapping its own attribute names onto the contract's where they differ; a module asks
for providers of a capability (``providers``, ``tools_for``, ``ConnectorRegistry.providers``) and reads the contract's
attribute names through ``field_name``. A second product of the same kind is then used by every workflow without a
code change: it declares the same capability.

A capability with ``stream=None`` in a declaration is served through the connector's own look-up or catalogue methods
(threat-intelligence feeds, a configuration export) rather than a sync stream.

What a module needs is declared in ``MODULE_NEEDS`` (required capabilities as any-of groups, optional ones); the
capability matrix (``matrix``) shows, for one deployment, which capability each switched-on tool provides and what is
missing - the readiness check of a client onboarding (``python -m soc_platform capabilities --check``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any


@dataclass(frozen=True)
class Capability:
    name: str
    category: str                          # the kind of tool (devkit.CATEGORIES) that usually provides it
    kinds: tuple[str, ...]                 # record kinds the stream delivers (empty: look-up / catalogue only)
    fields: tuple[str, ...] = ()           # attribute names a workflow may read (a provider maps its own onto them)
    description: str = ""


@dataclass(frozen=True)
class Provides:
    """One declaration in a manifest: the stream that provides a capability, and the connector's own name for each of
    the contract's fields where it differs (``None``: the tool does not report that field)."""

    stream: str | tuple[str, ...] | None
    fields: dict[str, str | None] = field(default_factory=dict)

    @property
    def streams(self) -> tuple[str, ...]:
        if self.stream is None:
            return ()
        return (self.stream,) if isinstance(self.stream, str) else tuple(self.stream)


_C = Capability
CAPABILITIES: dict[str, Capability] = {c.name: c for c in (
    # the device and people baseline
    _C("directory.users", "directory", ("identity",), ("department", "privileged"),
       "People and accounts from a directory"),
    _C("directory.devices", "directory", ("asset",), ("device_type", "primary_user", "directory_enabled"),
       "The device baseline: every device the organisation manages"),
    # endpoint
    _C("edr.inventory", "edr", ("asset",), ("last_seen", "device_type"),
       "Devices carrying the EDR agent, with when each agent last reported"),
    _C("edr.alerts", "edr", ("alert", "edr_alert"), (), "Endpoint detections"),
    # data protection
    _C("dlp.incidents", "dlp", ("dlp_incident",), (), "DLP incidents: what data went where, by whom"),
    _C("dlp.agents", "dlp", ("asset",), ("last_seen",), "Devices carrying the DLP agent, with its last check-in"),
    _C("encryption.inventory", "encryption", ("asset",), ("disk_encrypted", "encryption_state", "device_type"),
       "Devices and their disk-encryption state"),
    # identity
    _C("identity.risk_events", "identity", ("auth_risk",), (), "Risky authentications scored by the identity tool"),
    _C("identity.signins", "identity", ("signin",), (), "Sign-in and logon events"),
    _C("identity.alerts", "identity", ("alert",), (), "Identity detections (risky users, risk detections)"),
    _C("identity.directory_audits", "identity", ("signin",), (), "Directory changes (consents, role grants)"),
    # e-mail, DNS, deception, privileged access
    _C("email.reported", "email", ("email",), (), "Messages users reported as suspicious"),
    _C("email.alerts", "email", ("alert",), (), "E-mail security alerts"),
    _C("email.events", "email", ("mail_event",), (), "E-mail security verdicts on delivered messages"),
    _C("dns.events", "dns", ("dns",), (), "DNS resolutions with the resolver's verdict"),
    _C("deception.alerts", "deception", ("deception",), (), "Hits on decoys"),
    _C("deception.devices", "deception", ("asset",), (), "The decoys themselves"),
    _C("pam.checkouts", "pam", ("secret_access",), (), "Privileged credential check-outs and use"),
    _C("pam.elevations", "pam", ("elevation",), (), "Privilege elevations on endpoints"),
    # vulnerability, cloud, CMDB, tickets, SIEM
    _C("vuln.assets", "vuln", ("asset",), (), "Assets a vulnerability source scans or reports on"),
    _C("vuln.findings", "vuln", ("finding",), (), "Vulnerability findings per asset"),
    _C("vuln.exceptions", "vuln", ("risk_exception",), (), "Accepted-risk records kept by the scanner"),
    _C("cloud.issues", "cloud", ("cloud_issue",), (), "Cloud misconfigurations"),
    _C("cmdb.assets", "cmdb", ("asset",), (), "Configuration items: owner, environment, criticality"),
    _C("itsm.tickets", "itsm", ("ticket",), (), "Tickets"),
    _C("siem.alerts", "siem", ("alert",), (), "Alerts read from, or pushed by, a SIEM or SOAR"),
    # reference data read through look-ups or catalogues, not sync records
    _C("intel.kev", "intel", (), (), "Known-exploited vulnerabilities catalogue"),
    _C("intel.epss", "intel", (), (), "Exploit prediction scores per CVE"),
    _C("intel.cve", "intel", (), (), "CVE details"),
    _C("intel.indicators", "intel", (), (), "Reputation of IPs, domains, URLs and hashes"),
    # the tools' own upkeep
    _C("tool.health", "other", ("tool_health",), (), "What the tool reports about itself: certificates, sync jobs"),
    _C("tool.config_export", "other", (), (), "The tool's configuration (policies, rules), exported in full"),
)}

# What each module needs. ``required``: any-of groups - every group must have a provider, or the module cannot work.
# ``optional``: used when present; a missing one is shown as a reduced feature, never an error. Keys are job names.
MODULE_NEEDS: dict[str, dict[str, Any]] = {
    "inventory": {"label": "Device and people baseline", "required": [("directory.devices", "edr.inventory")],
                  "optional": ["directory.users", "dlp.agents", "encryption.inventory"]},
    "dlp": {"label": "Data protection (DLP triage)", "required": [("dlp.incidents",)],
            "optional": ["directory.users", "directory.devices", "edr.inventory", "dlp.agents", "encryption.inventory",
                         "identity.risk_events", "edr.alerts"]},
    "crosstool": {"label": "Cross-tool cases", "required": [("dlp.incidents",)],
                  "optional": ["identity.risk_events", "edr.alerts", "directory.users", "edr.inventory"]},
    "posture": {"label": "Coverage, tool health and posture score", "required": [("directory.devices",)],
                "optional": ["edr.inventory", "dlp.agents", "encryption.inventory", "identity.risk_events",
                             "tool.health"]},
    "config_snapshots": {"label": "Configuration baseline", "required": [("tool.config_export",)], "optional": []},
    "incident": {"label": "Incident triage", "required": [("edr.alerts", "identity.alerts", "email.alerts",
                                                           "siem.alerts", "deception.alerts")],
                 "optional": ["directory.users", "edr.inventory", "identity.directory_audits", "identity.signins",
                              "dns.events", "pam.checkouts", "intel.indicators", "intel.kev"]},
    "phishing": {"label": "Phishing triage", "required": [("email.reported",)],
                 "optional": ["email.alerts", "email.events", "dns.events", "edr.inventory", "directory.users",
                              "identity.signins", "intel.indicators"]},
    "vulnerability": {"label": "Vulnerability management", "required": [("vuln.findings",)],
                      "optional": ["vuln.assets", "vuln.exceptions", "cmdb.assets", "cloud.issues", "intel.kev",
                                   "intel.epss", "intel.cve", "itsm.tickets"]},
}


def check(name: str) -> Capability:
    if name not in CAPABILITIES:
        raise KeyError(f"unknown capability {name!r}")
    return CAPABILITIES[name]


def as_provides(value: Any) -> Provides:
    """A declaration written as a stream name, ``None`` (look-up only) or a ``Provides``."""
    if isinstance(value, Provides):
        return value
    if value is None or isinstance(value, str):
        return Provides(value)
    if isinstance(value, (tuple, list)) and value and all(isinstance(v, str) for v in value):
        return Provides(tuple(value))
    raise TypeError(f"a capability declaration is a stream name, None or Provides, not {type(value).__name__}")


@lru_cache(maxsize=1)
def _catalog() -> tuple[tuple[str, str, Provides], ...]:
    """(capability, connector, declaration) for every connector the platform can load, sorted - so the order of
    providers is the same on every run and every replica."""
    from soc_platform.connectors.registry import discover

    return tuple(sorted(((cap, name, p) for name, m in discover().items() for cap, p in m.provides.items()),
                        key=lambda x: (x[0], x[1])))


def reset() -> None:
    """Forget the catalogue (a test that installs a connector package, or a reload after one)."""
    _catalog.cache_clear()


def providers(capability: str) -> list[tuple[str, Provides]]:
    """Every loadable connector that declares the capability, whether switched on or not, by name."""
    check(capability)
    return [(name, p) for cap, name, p in _catalog() if cap == capability]


def tools_for(*capabilities: str) -> tuple[str, ...]:
    """Connector names that provide any of the capabilities (records in the context store carry these names)."""
    return tuple(sorted({name for c in capabilities for name, _ in providers(c)}))


def declaration(tool: str, capability: str) -> Provides | None:
    return next((p for name, p in providers(capability) if name == tool), None)


def field_name(tool: str, capability: str, name: str) -> str | None:
    """The tool's own attribute name for a field of the contract (the contract's name when it maps none);
    ``None`` when the tool does not report it."""
    p = declaration(tool, capability)
    if p is None or name not in p.fields:
        return name
    return p.fields[name]


def read_field(view: dict[str, Any] | None, tool: str, capability: str, name: str) -> Any:
    """A contract field from one tool's view of an entity (``attributes["by_tool"][tool]``)."""
    if not view:
        return None
    own = field_name(tool, capability, name)
    return view.get(own) if own else None


def stream_of(tool: str, capability: str) -> str | None:
    """The (first) stream through which the tool provides the capability."""
    p = declaration(tool, capability)
    return p.streams[0] if p and p.streams else None


def label(tool: str) -> str:
    """The product's name as a person reads it, from its manifest (the connector id when it has none)."""
    from soc_platform.connectors.registry import discover

    m = discover().get(tool)
    return m.tool if m is not None else tool


# ------------------------------------------------------------------ one deployment's view

def module_on(module: str) -> bool:
    from soc_platform.core import scope

    return scope.job_in_scope(module)


def matrix(registry: Any) -> dict[str, Any]:
    """For this deployment: every capability with the switched-on tools that provide it (and those that could), and
    for every module in scope whether its required capabilities are met. Everything is read from manifests and the
    connector configuration in force; nothing is assumed about a product."""
    enabled = set(registry.enabled_names())
    configured = set(registry.configured_names())
    caps = []
    for name, cap in CAPABILITIES.items():
        decl = providers(name)
        on = [{"tool": t, "label": label(t), "streams": list(p.streams), "stage": registry.stage_of(t)}
              for t, p in decl if t in enabled]
        caps.append({"capability": name, "category": cap.category, "description": cap.description,
                     "kinds": list(cap.kinds), "fields": list(cap.fields), "provided_by": on,
                     "configured_but_unusable": sorted(t for t, _ in decl if t in configured and t not in enabled),
                     "available_from": sorted(t for t, _ in decl if t not in enabled)})
    provided = {c["capability"] for c in caps if c["provided_by"]}
    modules = []
    for mod, need in MODULE_NEEDS.items():
        if not module_on(mod):
            continue
        missing = [list(group) for group in need["required"] if not provided & set(group)]
        reduced = [c for c in need["optional"] if c not in provided]
        modules.append({"module": mod, "label": need["label"], "ready": not missing,
                        "missing_required": missing, "reduced_without": reduced,
                        "uses": sorted({c for g in need["required"] for c in g} | set(need["optional"]) & provided)})
    return {"capabilities": caps, "modules": modules, "ready": all(m["ready"] for m in modules),
            "connectors": [{"tool": t, "label": label(t), "stage": registry.stage_of(t),
                            "provides": sorted(c for c, n, _ in _catalog() if n == t)} for t in sorted(enabled)]}
