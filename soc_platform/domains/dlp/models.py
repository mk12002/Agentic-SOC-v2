"""Data-loss-prevention workflow state: one row per DLP incident a tool reported.

The incident itself (who, what, where to) lives in the shared context store as an event linked to its person and
device. This table holds what the platform worked out about it - the facts it was judged on, the computed
disposition and its reasons, what never lets it be closed automatically - and what a person ruled.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import new_id, utcnow


class DlpAlert(Base):
    __tablename__ = "dlp_alerts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    source_ref: Mapped[str] = mapped_column(String(256), unique=True)        # tool:incident id - one row per incident
    event_id: Mapped[str] = mapped_column(String(32), index=True)            # the incident in the context store
    tool: Mapped[str] = mapped_column(String(64))
    decision_type: Mapped[str] = mapped_column(String(64), index=True)
    rule: Mapped[str] = mapped_column(BoundedText(256), default="")
    event_time: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    user_entity_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    host_entity_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    tool_severity: Mapped[str] = mapped_column(String(16), default="low")
    severity: Mapped[str] = mapped_column(String(16), default="low")         # computed (see service.dispose)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)   # open | escalated | closed
    facts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)    # the F-numbered facts as cited
    computed_outcome: Mapped[str] = mapped_column(String(24))                # close_benign | escalate | review
    computed_reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    never_auto: Mapped[list[str]] = mapped_column(JSON, default=list)        # why it is never closed without a person
    personal_data: Mapped[bool | None] = mapped_column(Boolean, nullable=True, index=True)   # a personal-data class matched
    destination_domain: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    # the AI investigator's record: plan (model or rules), look-ups run, I-numbered findings (domains/dlp/investigator.py)
    investigation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    evidence_hash: Mapped[str] = mapped_column(String(64), default="")
    # the AI's newest decision, copied here so the queue's counts are plain aggregates (the full record: ai_decisions)
    ai_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ai_effective: Mapped[str | None] = mapped_column(String(24), nullable=True)
    ai_evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)   # evidence the AI last decided on
    analyst_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    analyst: Mapped[str | None] = mapped_column(String(256), nullable=True)
    analyst_source: Mapped[str | None] = mapped_column(String(16), nullable=True)     # platform | tool
    analyst_reason: Mapped[str] = mapped_column(BoundedText(2000), default="")
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, onupdate=utcnow)
