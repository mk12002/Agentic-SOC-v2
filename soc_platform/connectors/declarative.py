"""Declarative connectors: a tool with a plain REST / JSON API connected by a definition file - no code.

A definition (YAML or JSON, one per file) names the tool, how to sign in, and for each capability it provides
(``connectors/capabilities.py``) the endpoint, where the list sits in the answer, how pages follow each other, the
record's identifier and time, and a field mapping. The connector it describes is an ordinary connector: the same
transport (rate budget, retries, ``Retry-After``, token renewal, refusal of next links to any other host), the same
sync semantics (watermarks for event streams, full reads for inventories, never a page token as the resume point),
fake mode on a fixture file, preflight, stages, and the four-eyes console configuration. Every workflow that reads the
capability then uses the tool.

What a definition cannot do, by design:

* **write to a tool** - a definition reads only; an action is code with preconditions, reversal and policy;
* **run code** - values are read by dotted path and passed through a fixed set of converters (``CONVERTERS``); there
  are no expressions, templates or scripts;
* **hold a secret** - credentials are settings, set like any connector's (``${VAR}`` references, the vault), never
  values in the definition;
* **call another host** - every path is relative to the configured ``base_url``; a next link to any other origin is
  refused by the transport.

Definitions are read from ``config/connectors.d/*.yaml|*.yml|*.json`` and from the folders in
``SOC_CONNECTOR_DEFINITIONS`` (separated by the OS path separator). A definition with a problem is left out and the
problem is reported (``problems()``; ``python -m soc_platform connector validate FILE``); every other tool still loads.

Example::

    connector: examplevendor_edr
    tool: Example EDR
    vendor: Example Vendor
    category: edr
    description: EDR agent inventory and detections
    sign_in: {type: bearer}                       # settings: base_url, api_key
    fixtures: examplevendor_edr.json              # fake mode, next to the definition
    provides:
      edr.inventory:
        stream: endpoints
        path: /api/v2/endpoints
        items: data
        paging: {style: next_link, field: links.next}
        id: endpoint_id
        observed_at: last_checkin
        keys: {examplevendor_agent_id: endpoint_id, serial_number: serial}
        map:
          hostname: [hostname, {from: fqdn, as: label}]
          fqdn: {from: fqdn, as: fqdn}
          os: os_name
          device_type: {from: os_name, as: device_type}
          last_seen: last_checkin
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from soc_platform.connectors.base import ConnectorError, Page
from soc_platform.connectors.capabilities import CAPABILITIES, Provides
from soc_platform.connectors.http import (
    ApiKeyHeader,
    ApiKeyQuery,
    BasicAuth,
    FixtureTransport,
    HttpTransport,
    NoAuth,
    OAuth2ClientCredentials,
)
from soc_platform.connectors.tools._common import ToolConnector, Watermark, need, parse_ts, sev_name
from soc_platform.connectors.tools._paged import device_type, flag
from soc_platform.core.identity import user_ref
from soc_platform.core.schema import EntityRef, NormalizedRecord

log = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = ROOT / "config" / "connectors.d"
NAME = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%{}-]*$")
DOTTED = re.compile(r"^[A-Za-z0-9_$@-]+(\.[A-Za-z0-9_$@-]+)*$")
ENTITY_KINDS = {"asset", "identity"}
MAX_PAGES = 1000                 # per stream per sync; a vendor that never stops paging is an error, not a loop

TOP_KEYS = {"connector", "tool", "vendor", "category", "dimension", "description", "sign_in", "rate_per_sec",
            "page_size", "fixtures", "provides", "to_confirm", "confidence"}
STREAM_KEYS = {"stream", "path", "items", "paging", "watermark", "kind", "source_type", "dimension", "id",
               "observed_at", "title", "severity", "keys", "user", "device", "device_keys", "map", "params"}
PAGING_STYLES = {"none", "next_link", "page_token", "offset", "page"}
SIGN_IN = {"none": (), "bearer": ("api_key",), "api_key_header": ("api_key",), "api_key_query": ("api_key",),
           "basic": ("username", "password"), "oauth_client_credentials": ("client_id", "client_secret")}


# ------------------------------------------------------------------ converters (the only transformations allowed)

def _label(v: Any) -> str | None:
    s = str(v or "").strip()
    return s.split(".")[0] or None if s else None


def _fqdn(v: Any) -> str | None:
    s = str(v or "").strip()
    return s if "." in s else None


def _lower(v: Any) -> str | None:
    s = str(v).strip().lower() if v is not None else ""
    return s or None


def _list(v: Any) -> list[str]:
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    return [str(x).strip() for x in v if isinstance(x, (str, int)) and str(x).strip()] if isinstance(v, list) else []


def _num(cast):
    def conv(v: Any):
        try:
            return cast(v) if v not in (None, "") and not isinstance(v, bool) else None
        except (TypeError, ValueError):
            return None
    return conv


CONVERTERS = {
    "str": lambda v: None if v is None else str(v),
    "lower": _lower,
    "bool": flag,
    "int": _num(int),
    "float": _num(float),
    "device_type": lambda v: device_type(v),
    "label": _label,
    "fqdn": _fqdn,
    "list": _list,
    "severity": lambda v: sev_name(v) if v not in (None, "") else None,
}


def dig(obj: Any, path: str) -> Any:
    """A value by dotted path (``a.b.c``); None when any step is missing."""
    v = obj
    for part in path.split("."):
        v = v.get(part) if isinstance(v, dict) else None
    return v


@dataclass(frozen=True)
class Source:
    """One mapped value: the first non-empty of several paths, through one converter."""

    paths: tuple[str, ...]
    convert: str | None = None

    def read(self, raw: dict[str, Any]) -> Any:
        for p in self.paths:
            v = dig(raw, p)
            if v is not None and v != "":
                return CONVERTERS[self.convert](v) if self.convert else v
        return None


class DefinitionError(ValueError):
    pass


def _source(spec: Any, where: str) -> Source:
    """``path`` | ``{from: path | [paths], as: converter}`` | ``[ either of those ... ]`` (first non-empty wins)."""
    if isinstance(spec, str):
        if not DOTTED.match(spec):
            raise DefinitionError(f"{where}: '{spec}' is not a field path (letters, digits, _ and dots)")
        return Source((spec,))
    if isinstance(spec, dict):
        extra = set(spec) - {"from", "as"}
        if extra or "from" not in spec:
            raise DefinitionError(f"{where}: a mapping is {{from: path, as: converter}}"
                                  + (f" (unknown: {', '.join(sorted(extra))})" if extra else ""))
        conv = spec.get("as")
        if conv is not None and conv not in CONVERTERS:
            raise DefinitionError(f"{where}: unknown converter '{conv}' (one of {', '.join(sorted(CONVERTERS))})")
        inner = _source(spec["from"], where) if not isinstance(spec["from"], list) else \
            Source(tuple(p for s in spec["from"] for p in _source(s, where).paths))
        return Source(inner.paths, conv)
    if isinstance(spec, list) and spec:
        parts = [_source(s, where) for s in spec]
        convs = {p.convert for p in parts}
        if len(parts) > 1 and len(convs) > 1:
            # each alternative keeps its own converter: read in order, first non-empty result wins
            return _Alternatives(tuple(parts))  # type: ignore[return-value]
        return Source(tuple(p for s in parts for p in s.paths), parts[0].convert)
    raise DefinitionError(f"{where}: expected a field path, {{from, as}} or a list of them")


@dataclass(frozen=True)
class _Alternatives:
    parts: tuple[Source, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(p for s in self.parts for p in s.paths)

    def read(self, raw: dict[str, Any]) -> Any:
        for s in self.parts:
            v = s.read(raw)
            if v is not None and v != "":
                return v
        return None


@dataclass
class StreamDef:
    capability: str
    stream: str
    path: str
    kind: str
    source_type: str
    dimension: str
    id: Source
    items: str = ""
    paging: dict[str, Any] = field(default_factory=lambda: {"style": "none"})
    watermark: dict[str, str] | None = None
    observed_at: Source | None = None
    title: Source | None = None
    severity: Source | None = None
    keys: dict[str, Source] = field(default_factory=dict)
    user: Source | None = None
    device: dict[str, Source] = field(default_factory=dict)
    device_keys: dict[str, Source] = field(default_factory=dict)
    attributes: dict[str, Source] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class Definition:
    connector: str
    tool: str
    vendor: str
    category: str
    dimension: str
    description: str
    sign_in: dict[str, Any]
    streams: dict[str, StreamDef]
    source: str
    fixtures: Path | None = None
    rate_per_sec: float = 2.0
    page_size: int = 200
    to_confirm: str = ""
    confidence: str = ""


def _need(doc: dict[str, Any], key: str, where: str) -> Any:
    v = doc.get(key)
    if v in (None, "", {}):
        raise DefinitionError(f"{where}: '{key}' is required")
    return v


def parse(doc: Any, *, source: str = "<definition>", folder: Path | None = None) -> Definition:
    """Check a definition completely and return it; every problem is a DefinitionError naming where it is."""
    from soc_platform.connectors.devkit import CATEGORIES, DIMENSIONS

    if not isinstance(doc, dict):
        raise DefinitionError(f"{source}: a definition is a mapping (connector:, tool:, provides: ...)")
    extra = set(doc) - TOP_KEYS
    if extra:
        raise DefinitionError(f"{source}: unknown key(s) {', '.join(sorted(extra))} (allowed: {', '.join(sorted(TOP_KEYS))})")
    name = str(_need(doc, "connector", source))
    if not NAME.match(name):
        raise DefinitionError(f"{source}: connector '{name}' must be lower-case letters, digits and _ (2-40)")
    category = str(_need(doc, "category", source))
    if category not in CATEGORIES:
        raise DefinitionError(f"{source}: category '{category}' is not one of {', '.join(CATEGORIES)}")
    dimension = str(doc.get("dimension") or DIMENSIONS.get(category, "other"))
    sign_in = doc.get("sign_in") or {"type": "bearer"}
    if not isinstance(sign_in, dict) or sign_in.get("type") not in SIGN_IN:
        raise DefinitionError(f"{source}: sign_in.type must be one of {', '.join(SIGN_IN)}")
    for k, v in sign_in.items():
        if k not in {"type", "header", "prefix", "param", "token_path", "scope"}:
            raise DefinitionError(f"{source}: sign_in.{k} is not a sign-in option (credentials are settings, never "
                                  "written in a definition)")
        if k == "token_path" and (not PATH.match(str(v)) or str(v).startswith("//") or "/../" in str(v) + "/"):
            raise DefinitionError(f"{source}: sign_in.token_path must be a path on the tool's own host (/...)")
    provides = _need(doc, "provides", source)
    if not isinstance(provides, dict):
        raise DefinitionError(f"{source}: provides maps a capability to its stream")
    streams: dict[str, StreamDef] = {}
    for cap, spec in provides.items():
        where = f"{source}: provides.{cap}"
        if cap not in CAPABILITIES:
            raise DefinitionError(f"{where}: unknown capability (one of {', '.join(sorted(CAPABILITIES))})")
        if not CAPABILITIES[cap].kinds:
            raise DefinitionError(f"{where}: this capability is a look-up or export, which needs code")
        sd = _stream(cap, spec, where, dimension)
        if sd.stream in streams:
            raise DefinitionError(f"{where}: stream '{sd.stream}' is declared twice")
        streams[sd.stream] = sd
    fixtures = None
    if doc.get("fixtures"):
        fx = Path(str(doc["fixtures"]))
        fixtures = fx if fx.is_absolute() else (folder or Path.cwd()) / fx
    try:
        rate = float(doc.get("rate_per_sec", 2.0))
        size = int(doc.get("page_size", 200))
    except (TypeError, ValueError) as exc:
        raise DefinitionError(f"{source}: rate_per_sec and page_size are numbers") from exc
    if not 0 < rate <= 50 or not 1 <= size <= 5000:
        raise DefinitionError(f"{source}: rate_per_sec must be in (0, 50] and page_size in [1, 5000]")
    return Definition(connector=name, tool=str(doc.get("tool") or name), vendor=str(doc.get("vendor") or ""),
                      category=category, dimension=dimension, description=str(doc.get("description") or ""),
                      sign_in=dict(sign_in), streams=streams, source=source, fixtures=fixtures, rate_per_sec=rate,
                      page_size=size, to_confirm=str(doc.get("to_confirm") or ""),
                      confidence=str(doc.get("confidence") or "Declared"))


def _stream(cap: str, spec: Any, where: str, dimension: str) -> StreamDef:
    if not isinstance(spec, dict):
        raise DefinitionError(f"{where}: expected a mapping (path:, id:, map: ...)")
    extra = set(spec) - STREAM_KEYS
    if extra:
        raise DefinitionError(f"{where}: unknown key(s) {', '.join(sorted(extra))}")
    contract = CAPABILITIES[cap]
    path = str(_need(spec, "path", where))
    if not PATH.match(path) or path.startswith("//") or "/../" in path + "/":
        raise DefinitionError(f"{where}: path must start with / and stay on the tool's host (no scheme, no host, "
                              "no //, no ..)")
    kind = str(spec.get("kind") or contract.kinds[0])
    if kind not in contract.kinds:
        raise DefinitionError(f"{where}: kind '{kind}' is not one {cap} delivers ({', '.join(contract.kinds)})")
    stream = str(spec.get("stream") or cap.replace(".", "_"))
    if not NAME.match(stream):
        raise DefinitionError(f"{where}: stream '{stream}' must be lower-case letters, digits and _")
    paging = spec.get("paging") or {"style": "none"}
    if not isinstance(paging, dict) or paging.get("style") not in PAGING_STYLES:
        raise DefinitionError(f"{where}: paging.style must be one of {', '.join(sorted(PAGING_STYLES))}")
    if paging["style"] in ("next_link", "page_token") and not paging.get("field"):
        raise DefinitionError(f"{where}: paging style {paging['style']} needs 'field' (where the answer names the "
                              "next page)")
    if paging["style"] in ("offset", "page") and not paging.get("limit_param"):
        raise DefinitionError(f"{where}: paging style {paging['style']} needs 'limit_param' (the page-size "
                              "parameter), so a short page can be told from the last one")
    for k in ("field", "param", "limit_param"):
        if paging.get(k) is not None and not DOTTED.match(str(paging[k])):
            raise DefinitionError(f"{where}: paging.{k} must be a field name")
    wm = spec.get("watermark")
    if wm is not None and (not isinstance(wm, dict) or set(wm) - {"param", "field"} or not wm.get("field")):
        raise DefinitionError(f"{where}: watermark is {{param: <query parameter>, field: <change-time field>}}")
    params = spec.get("params") or {}
    if not isinstance(params, dict) or not all(isinstance(v, (str, int)) for v in params.values()):
        raise DefinitionError(f"{where}: params are fixed query parameters (name: value)")
    if kind in ENTITY_KINDS and not spec.get("keys"):
        raise DefinitionError(f"{where}: an inventory record needs keys (the tool's own id at least) so it resolves")

    def srcs(name: str) -> dict[str, Source]:
        m = spec.get(name) or {}
        if not isinstance(m, dict):
            raise DefinitionError(f"{where}: {name} maps a name to a field")
        return {str(k): _source(v, f"{where}.{name}.{k}") for k, v in m.items()}

    attributes = srcs("map")
    missing = [f for f in contract.fields if f not in attributes and f in ("last_seen", "disk_encrypted")]
    if missing:
        raise DefinitionError(f"{where}: {cap} needs the field(s) {', '.join(missing)} in map")
    opt = {k: _source(spec[k], f"{where}.{k}") for k in ("observed_at", "title", "severity", "user") if spec.get(k)}
    return StreamDef(capability=cap, stream=stream, path=path, kind=kind,
                     source_type=str(spec.get("source_type") or stream.rstrip("s") or stream),
                     dimension=str(spec.get("dimension") or dimension), id=_source(_need(spec, "id", where), where),
                     items=str(spec.get("items") or ""), paging=dict(paging), watermark=dict(wm) if wm else None,
                     keys=srcs("keys"), device=srcs("device"), device_keys=srcs("device_keys"),
                     attributes=attributes, params={str(k): str(v) for k, v in params.items()}, **opt)


# ------------------------------------------------------------------ the connector

class DeclarativeConnector(ToolConnector):
    """Reads what its definition says, nothing else; no actions, no look-ups."""

    def __init__(self, definition: Definition, settings: dict[str, Any], transport: Any) -> None:
        super().__init__(settings, transport, rate_per_sec=definition.rate_per_sec,
                         burst=max(1, int(definition.rate_per_sec * 2)))
        self.definition = definition
        self.name = self.tool = definition.connector
        self.dimension = definition.dimension
        self.streams = tuple(definition.streams)
        self.read_scopes = tuple(f"read {s.path}" for s in definition.streams.values())
        self.page_size = definition.page_size

    def _items(self, sd: StreamDef, body: Any) -> list[dict[str, Any]]:
        got = dig(body, sd.items) if sd.items else body
        if not isinstance(got, list):
            raise ConnectorError(f"{self.tool}.{sd.stream}: the answer has no list at '{sd.items or '(top level)'}'")
        return [x for x in got if isinstance(x, dict)]

    def fetch_page(self, stream: str, cursor: str | None) -> Page:
        sd = self.definition.streams[stream]
        style = sd.paging.get("style", "none")
        # Between syncs the cursor is "since:<newest change time>" (event streams) or nothing (inventories); within
        # one sync it is "<position>|<since>" - a page token, a next link, an offset or a page number.
        position, _, since = (cursor or "").rpartition("|") if "|" in (cursor or "") else (cursor or "", "", "")
        wm = Watermark.of(self, stream)
        if not cursor or cursor.startswith("since:"):
            since, position = (wm.start(cursor) or "") if sd.watermark else "", ""
        params: dict[str, Any] = dict(sd.params)
        limit_param = sd.paging.get("limit_param")
        if limit_param:
            params[limit_param] = self.page_size
        if since and sd.watermark and sd.watermark.get("param"):
            params[sd.watermark["param"]] = since
        path = sd.path
        if style == "next_link" and position:
            path, params = position, {}                     # the link carries its own query; same host only
        elif style == "page_token" and position:
            params[sd.paging.get("param") or "page_token"] = position
        elif style == "offset":
            params[sd.paging.get("param") or "offset"] = int(position or 0)
        elif style == "page":
            params[sd.paging.get("param") or "page"] = int(position or sd.paging.get("first", 1))
        body = self.get(path, params=params)
        recs = self._items(sd, body)
        if sd.watermark:
            wm.see(recs, sd.watermark["field"])
        nxt: str | None = None
        if recs:
            if style in ("next_link", "page_token"):
                v = dig(body, sd.paging["field"])
                nxt = str(v) if v else None
            elif style == "offset":
                nxt = str(int(position or 0) + len(recs)) if len(recs) >= self.page_size else None
            elif style == "page":
                nxt = str(int(position or sd.paging.get("first", 1)) + 1) if len(recs) >= self.page_size else None
        if nxt:
            pages = self.__dict__.setdefault("_pages", {})
            pages[stream] = pages.get(stream, 0) + 1
            if pages[stream] > MAX_PAGES:
                raise ConnectorError(f"{self.tool}.{stream}: more than {MAX_PAGES} pages in one sync - check paging")
            return Page(recs, f"{nxt}|{since}", has_more=True)
        self.__dict__.setdefault("_pages", {})[stream] = 0
        return Page(recs, wm.finish() if sd.watermark else None, has_more=False, reset=True)

    def normalize(self, stream: str, raw: dict[str, Any]) -> list[NormalizedRecord]:
        sd = self.definition.streams[stream]
        rid = sd.id.read(raw)
        need({"id": rid}, "id")                              # a record without its identifier is refused, with why
        attrs = {k: s.read(raw) for k, s in sd.attributes.items()}
        rec: dict[str, Any] = {
            "kind": sd.kind, "tool": self.tool, "source_type": sd.source_type, "source_id": str(rid),
            "observed_at": parse_ts(sd.observed_at.read(raw)) if sd.observed_at else None,
            "dimension": sd.dimension, "attributes": attrs}
        if sd.kind in ENTITY_KINDS:
            rec["keys"] = {k: s.read(raw) for k, s in sd.keys.items()}
        else:
            refs: list[EntityRef] = []
            if sd.device:
                dev = {k: s.read(raw) for k, s in sd.device.items()}
                keys = {k: s.read(raw) for k, s in sd.device_keys.items()}
                if any(v is not None for v in (*dev.values(), *keys.values())):
                    refs.append(EntityRef(kind="asset", role="host", keys=keys, attributes=dev))
            if sd.user:
                u = user_ref(sd.user.read(raw), default_domain=self.settings.get("user_domain"))
                if u is not None:
                    refs.append(u)
            sev = sev_name(sd.severity.read(raw)) if sd.severity else None
            rec |= {"refs": refs, "title": str(sd.title.read(raw) or "")[:200] if sd.title else "",
                    "severity": sev}
            if sev:
                attrs.setdefault("severity", sev)
        return [NormalizedRecord(**rec)]


# ------------------------------------------------------------------ manifests

def _auth(d: Definition, s: dict[str, Any]):
    t, si = d.sign_in["type"], d.sign_in
    if t == "none":
        return NoAuth()
    if t == "bearer":
        return ApiKeyHeader("Authorization", s["api_key"], "Bearer ")
    if t == "api_key_header":
        return ApiKeyHeader(str(si.get("header") or "X-API-Key"), s["api_key"], str(si.get("prefix") or ""))
    if t == "api_key_query":
        return ApiKeyQuery(str(si.get("param") or "api_key"), s["api_key"])
    if t == "basic":
        return BasicAuth(s["username"], s["password"])
    token_url = s["base_url"].rstrip("/") + str(si.get("token_path") or "/oauth/token")
    return OAuth2ClientCredentials(token_url, s["client_id"], s["client_secret"], scope=si.get("scope"))


def manifest(d: Definition):
    from soc_platform.connectors.registry import ConfigField, ConnectorManifest

    secrets = SIGN_IN[d.sign_in["type"]]
    config = [ConfigField("base_url", f"API URL of {d.tool}", kind="url"),
              *[ConfigField(k, f"{k.replace('_', ' ')} for {d.tool}", secret=k in ("api_key", "password",
                                                                                   "client_secret"))
                for k in secrets],
              ConfigField("user_domain", "UPN suffix for bare user names", required=False)]
    provides = {sd.capability: Provides(sd.stream) for sd in d.streams.values()}
    fixtures = d.fixtures

    class _Manifest(ConnectorManifest):
        def fixture_transport(self) -> FixtureTransport:          # fake mode reads the definition's own fixture file
            return FixtureTransport.from_file(fixtures, tool=d.connector) if fixtures else FixtureTransport([], d.connector)

    return _Manifest(
        name=d.connector, tool=d.tool, vendor=d.vendor, category=d.category, dimension=d.dimension,
        description=d.description or f"Declared connector ({d.source})",
        factory=lambda s, t: DeclarativeConnector(d, s, t),
        live_transport=lambda s: HttpTransport(s["base_url"], _auth(d, s)),
        config=config, confidence=d.confidence, to_confirm=d.to_confirm,
        fake_settings={"base_url": f"https://{d.connector.replace('_', '-')}.example.invalid"},
        provides=provides, origin="definition")


# ------------------------------------------------------------------ loading

_PROBLEMS: list[str] = []


def problems() -> list[str]:
    """Definitions left out at the last load, each with why."""
    return list(_PROBLEMS)


def folders() -> list[Path]:
    out = [DEFAULT_DIR]
    for p in (os.environ.get("SOC_CONNECTOR_DEFINITIONS") or "").split(os.pathsep):
        if p.strip():
            out.append(Path(p.strip()))
    return out


def read_file(path: Path) -> Definition:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        doc = json.loads(text)
    else:
        import yaml

        doc = yaml.safe_load(text)                       # safe_load: no Python objects from a definition
    return parse(doc, source=path.name, folder=path.parent)


def load_all() -> list[Any]:
    """Every valid definition in the definition folders as a manifest; problems are kept for ``problems()``."""
    _PROBLEMS.clear()
    out, seen = [], set()
    for folder in folders():
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            if path.suffix.lower() not in (".yaml", ".yml", ".json") or not path.is_file():
                continue
            try:
                d = read_file(path)
                if d.connector in seen:
                    raise DefinitionError(f"{path.name}: connector '{d.connector}' is defined twice")
                seen.add(d.connector)
                out.append(manifest(d))
            except Exception as exc:
                _PROBLEMS.append(f"{path}: {exc}")
                log.error("connector definition %s left out: %s", path, exc)
    return out
