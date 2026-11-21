"""Cross-tool cases (M8): one person, several tools agreeing - one case, its severity computed from how many agree.

The deck's story: a risky sign-in (Silverfort), a data leak (Forcepoint DLP), a laptop with disk encryption off
(Trellix) and an endpoint alert (Trend Micro) are four "medium" alerts in four consoles - and one data-theft case here.

Every signal is a structured fact the tools reported - never the text of a message:

* ``dlp``          an escalated DLP alert, or one carrying personal data (Forcepoint DLP)
* ``identity``     a high or critical risky sign-in within 24 h of it (Silverfort; read from the alert's facts)
* ``control_off``  the sending device lacks a control: encryption off, EDR or DLP agent missing or silent
* ``endpoint``     an endpoint alert on the sending device or by the person within 24 h of it (Trend Micro)
* ``privileged``   the person is in a privileged group in the directory (Arcon joins when it is connected)

Rules (each needs the DLP signal and one more):

* X1  a risky sign-in, then data sent out                         identity + dlp
* X2  data sent out from a device with a control off             control_off + dlp
* X3  an endpoint alert on the device that sent the data         endpoint + dlp
* X4  a privileged person sent personal data out                 privileged + dlp with personal data

Severity = by the number of distinct tools that agree: 2 high, 3 or more critical. One open cross-tool case per
person; new signals are added to it (re-runs add nothing). Recommended actions go through ``ActionService`` and the
autonomy policy: revoke sessions and require MFA (reversible), and - only when three or more tools agree - isolate the
device (two approvers, always).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, func, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from soc_platform.core.db import Base, UTCDateTime
from soc_platform.core.models import Case, Entity, utcnow

AGENT = "agent:crosstool"
WINDOW = timedelta(days=30)            # DLP alerts up to 30 days before the newest are joined
NEAR = timedelta(hours=24)             # an endpoint alert this close to the leak counts
RULES = {
    "X1": "A risky sign-in, then data sent out",
    "X2": "Data sent out from a device with a control off",
    "X3": "An endpoint alert on the device that sent the data",
    "X4": "A privileged person sent personal data out",
}
def tool_label(tool: str) -> str:
    """The product's name from its manifest (no product is named in this module)."""
    from soc_platform.connectors.capabilities import label

    return label(tool)


class CrossToolCase(Base):
    """Which case holds a person's cross-tool signals, and what it last saw (so a re-run adds nothing)."""
    __tablename__ = "crosstool_cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    person_entity_id: Mapped[str] = mapped_column(String(32), index=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("cases.id"), index=True)
    tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    rules: Mapped[list[str]] = mapped_column(JSON, default=list)
    signal_keys: Mapped[list[str]] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(16), default="high")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)


def severity_for(tools: int) -> str:
    return "critical" if tools >= 3 else "high"


def _aware(v: datetime | None) -> datetime | None:
    from datetime import UTC

    return None if v is None else (v if v.tzinfo else v.replace(tzinfo=UTC))


class CrossToolService:
    def __init__(self, session: Session, registry: Any) -> None:
        from soc_platform.core.cases import CaseService
        from soc_platform.core.context_store import ContextStore

        self.s, self.registry = session, registry
        self.cases = CaseService(session)
        self.store = ContextStore(session)

    # ------------------------------------------------------------------ signals

    def _edr_alerts(self, entity_ids: set[str], around: datetime) -> list[Entity]:
        """Endpoint alerts linked to the device or the person, within 24 h of the leak."""
        from soc_platform.connectors.capabilities import CAPABILITIES, tools_for

        edr = set(tools_for("edr.alerts"))
        out = []
        for eid in sorted(entity_ids):
            for ent in self.store.events_for(eid, kinds=set(CAPABILITIES["edr.alerts"].kinds)):
                seen = _aware(ent.first_seen)
                if (ent.attributes or {}).get("tool") in edr and seen is not None and abs(seen - around) <= NEAR \
                        and ent not in out:
                    out.append(ent)
        return sorted(out, key=lambda e: (e.first_seen, e.id))

    def signals_for(self, person: str, alerts: list[Any]) -> list[dict[str, Any]]:
        """Every signal about one person, each with the tool that reported it and a stable key."""
        sig: list[dict[str, Any]] = []
        for a in alerts:
            f = a.facts or {}
            at = _aware(a.event_time)
            classes = f.get("data_classes") or []
            sig.append({"key": f"dlp:{a.id}", "kind": "dlp", "tool": a.tool, "at": at, "alert": a,
                        "personal": bool(a.personal_data),
                        "text": f"DLP alert: {a.rule} to {f.get('destination_class') or 'unknown'} destination"
                                + (f" ({', '.join(classes)})" if classes else "") + f", computed {a.computed_outcome}"})
            risk = f.get("identity_risk") or {}
            if risk.get("level") in ("high", "critical"):
                sig.append({"key": f"identity:{a.id}", "kind": "identity", "tool": risk.get("tool") or "identity",
                            "at": at, "text": f"Risky sign-in ({risk.get('level')}) within 24 h of the DLP alert"
                                              + (f": {', '.join(risk.get('factors') or [])}" if risk.get("factors") else "")})
            for g in (f.get("device") or {}).get("short") or []:
                sig.append({"key": f"control:{a.host_entity_id}:{g.get('control')}", "kind": "control_off",
                            "tool": g.get("tool"), "at": at,
                            "text": f"The sending device {(f.get('device') or {}).get('name') or ''}: "
                                    f"{g.get('label') or g.get('control')} {g.get('state')}".replace("  ", " ")})
            if (f.get("user") or {}).get("privileged"):
                sig.append({"key": f"privileged:{person}", "kind": "privileged",
                            "tool": (f.get("user") or {}).get("directory") or "directory", "at": at,
                            "personal": bool(a.personal_data),
                            "text": "The person is in a privileged group in the directory"})
            for e in self._edr_alerts({x for x in (a.host_entity_id, person) if x}, at):
                sig.append({"key": f"endpoint:{e.id}", "kind": "endpoint", "tool": (e.attributes or {}).get("tool"),
                            "at": _aware(e.first_seen),
                            "entity_id": e.id, "text": f"Endpoint alert: {e.display_name} "
                                                       f"({(e.attributes or {}).get('severity') or 'unrated'})"})
        seen, out = set(), []
        for x in sig:                                       # one row per key (the same gap on several alerts)
            if x["key"] not in seen and x.get("tool"):
                seen.add(x["key"])
                out.append(x)
        return out

    @staticmethod
    def rules_for(sig: list[dict[str, Any]]) -> list[str]:
        kinds = {x["kind"] for x in sig}
        if "dlp" not in kinds:
            return []
        out = []
        if "identity" in kinds:
            out.append("X1")
        if "control_off" in kinds:
            out.append("X2")
        if "endpoint" in kinds:
            out.append("X3")
        if "privileged" in kinds and any(x["kind"] == "dlp" and x.get("personal") for x in sig):
            out.append("X4")
        return out

    # ------------------------------------------------------------------ run

    def candidates(self) -> dict[str, list[Any]]:
        """People with an escalated or personal-data DLP alert in the 30 days up to the newest alert."""
        from soc_platform.domains.dlp.models import DlpAlert

        newest = self.s.execute(select(func.max(DlpAlert.event_time))).scalar()
        if newest is None:
            return {}
        rows = self.s.execute(select(DlpAlert).where(
            DlpAlert.user_entity_id.is_not(None), DlpAlert.event_time > newest - WINDOW,
            (DlpAlert.computed_outcome == "escalate") | DlpAlert.personal_data.is_(True))
            .order_by(DlpAlert.event_time, DlpAlert.id)).scalars()
        out: dict[str, list[Any]] = {}
        for a in rows:
            out.setdefault(a.user_entity_id, []).append(a)
        return dict(sorted(out.items()))

    def run(self) -> dict[str, Any]:
        opened, updated, unchanged = [], [], 0
        for person, alerts in self.candidates().items():
            sig = self.signals_for(person, alerts)
            rules = self.rules_for(sig)
            if not rules or len({x["tool"] for x in sig}) < 2:    # one tool alone is that tool's own alert
                continue
            res = self._upsert(person, sig, rules)
            if res == "opened":
                opened.append(person)
            elif res == "updated":
                updated.append(person)
            else:
                unchanged += 1
        return {"opened": len(opened), "updated": len(updated), "unchanged": unchanged}

    def _open_row(self, person: str) -> CrossToolCase | None:
        return self.s.execute(select(CrossToolCase).join(Case, Case.id == CrossToolCase.case_id).where(
            CrossToolCase.person_entity_id == person, Case.status != "closed")
            .order_by(CrossToolCase.id.desc())).scalars().first()

    def _upsert(self, person: str, sig: list[dict[str, Any]], rules: list[str]) -> str:
        tools = sorted({x["tool"] for x in sig})
        keys = sorted(x["key"] for x in sig)
        row = self._open_row(person)
        if row is not None and set(keys) <= set(row.signal_keys) and set(rules) <= set(row.rules):
            return "unchanged"
        who = self.s.get(Entity, person)
        name = who.display_name if who is not None else person
        severity = severity_for(len(tools))
        if row is None:
            case = self.cases.create("incident", f"Possible data theft: {len(tools)} tools agree ({name})",
                                     severity=severity, actor=AGENT,
                                     attributes={"crosstool": True, "person": person, "detection_source": "cross-tool rules"})
            row = CrossToolCase(person_entity_id=person, case_id=case.id)
            self.s.add(row)
            outcome = "opened"
        else:
            case = self.s.get(Case, row.case_id)
            tools = sorted(set(tools) | set(row.tools))
            rules = sorted(set(rules) | set(row.rules))
            keys = sorted(set(keys) | set(row.signal_keys))
            severity = severity_for(len(tools))
            case.title = f"Possible data theft: {len(tools)} tools agree ({name})"
            outcome = "updated"
        self.cases.link(case.id, person, "user")
        for x in sorted(sig, key=lambda x: (x["at"] or utcnow(), x["key"])):
            ent = x.get("entity_id") or (x["alert"].event_id if x.get("alert") is not None else None)
            self.cases.add_evidence(case.id, summary=x["text"], source=x["tool"],
                                         dimension={"dlp": "data_protection", "identity": "identity", "endpoint": "endpoint",
                                                    "control_off": "endpoint", "privileged": "identity"}[x["kind"]],
                                         data={"signal": x["kind"], "key": x["key"]}, entity_id=ent, observed_at=x["at"])
            if x.get("alert") is not None:
                if x["alert"].host_entity_id:
                    self.cases.link(case.id, x["alert"].host_entity_id, "host")
                if x["alert"].case_id:
                    self.cases.link(case.id, x["alert"].event_id, "dlp_incident")
        # numbered as the case screen numbers them (E1, E2 ...), so a claim's citation opens the row it cites
        from soc_platform.core.enrichment import evidence_for_llm
        from soc_platform.core.models import Evidence

        ev = evidence_for_llm(list(self.s.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars()))
        summary = (f"{len(tools)} tools agree about {name}: " + "; ".join(RULES[r] for r in rules) + ". Tools: "
                   + ", ".join(tool_label(t) for t in tools) + ".")
        self.cases.set_assessment(
            case, verdict="suspicious", severity=severity,
            confidence=min(0.95, 0.5 + 0.15 * (len(tools) - 1)), summary=summary,
            assessment={"claims": [{"text": e["claim"], "kind": "fact", "evidence_ids": [e["id"]]} for e in ev],
                        "evidence_index": {e["id"]: e["evidence_row"] for e in ev},
                        "source": "deterministic", "tools_agreeing": tools, "rules": rules,
                        "rule_text": {r: RULES[r] for r in rules}, "crosstool": True,
                        # the model's written account follows, from the same rows (the decision above is the rules')
                        "narration_pending": self.cases.narration_request(
                            "crosstool.summary", f"Explain to an analyst why these tools together point to possible "
                            f"data theft by {name}, and what to check first. Use only the evidence.", ev)},
            completeness={"queried": tools, "unavailable": []}, actor=AGENT)
        row.tools, row.rules, row.signal_keys, row.severity, row.updated_at = tools, rules, keys, severity, utcnow()
        self.s.flush()
        self._recommend(case, person, sig, len(tools))
        return outcome

    # ------------------------------------------------------------------ actions (through ActionService only)

    def _recommend(self, case: Case, person: str, sig: list[dict[str, Any]], n_tools: int) -> None:
        from soc_platform.core.cases import Recommendation
        from soc_platform.core.policy import PolicyEngine

        keys = self.store.keys_of(person)
        upn = keys.get("upn")
        recs = []
        if upn:
            who = [{"type": "identity", "id": person, "upn": upn}]
            recs.append(Recommendation("identity.revoke_sessions", who, "Sign the person out everywhere while the "
                                       "leak is investigated (reversible: they sign in again)", priority=10,
                                       expected_impact="active sessions end; the person signs in again",
                                       blast_radius="one person", reversible=True))
            recs.append(Recommendation("identity.require_mfa", who, "Require MFA at every sign-in until the case is "
                                       "closed (reversible)", priority=20,
                                       expected_impact="MFA prompt at each sign-in", blast_radius="one person",
                                       reversible=True))
        hosts = sorted({x["alert"].host_entity_id for x in sig if x.get("alert") is not None and x["alert"].host_entity_id})
        if n_tools >= 3:
            for h in hosts:
                guid = self.store.keys_of(h).get("trend_agent_guid")
                if guid:
                    host = self.s.get(Entity, h)
                    recs.append(Recommendation("endpoint.isolate", [{"type": "asset", "id": h, "trend_agent_guid": guid,
                                                                     "hostname": host.display_name if host else h}],
                                               "Isolate the device that sent the data: three or more tools agree "
                                               "(two approvers, always)", priority=30, reversible=True,
                                               expected_impact="the device keeps only its link to the EDR console",
                                               blast_radius="one device"))
        if recs:
            self.cases.recommend(case, recs, self.registry.action_registry(), PolicyEngine.for_session(self.s), agent=AGENT)

    # ------------------------------------------------------------------ read

    def narrate(self, llm: Any) -> int:
        """The model's written account of the cross-tool cases still waiting for one (after the commit)."""
        ids = [r.case_id for r in self.s.execute(select(CrossToolCase)).scalars()]
        return self.cases.narrate_pending(ids, llm, actor=AGENT) if ids else 0

    def overview(self) -> dict[str, Any]:
        rows = self.s.execute(select(CrossToolCase, Case).join(Case, Case.id == CrossToolCase.case_id)
                              .order_by(CrossToolCase.updated_at.desc(), CrossToolCase.id.desc())).all()
        items = []
        for r, c in rows:
            who = self.s.get(Entity, r.person_entity_id)
            items.append({"case_id": c.id, "title": c.title, "status": c.status, "severity": c.severity,
                          "person": who.display_name if who else r.person_entity_id, "person_entity_id": r.person_entity_id,
                          "tools": r.tools, "rules": [{"id": x, "text": RULES[x]} for x in r.rules],
                          "updated_at": _aware(r.updated_at).isoformat()})
        return {"cases": items, "open": sum(i["status"] != "closed" for i in items), "rules": RULES}
