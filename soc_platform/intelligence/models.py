"""Cross-domain intelligence findings ("insights")."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from soc_platform.core.db import Base, BoundedText, UTCDateTime
from soc_platform.core.models import new_id, utcnow


class Insight(Base):
    __tablename__ = "insights"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    rule: Mapped[str] = mapped_column(String(64), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(256), unique=True)
    title: Mapped[str] = mapped_column(BoundedText(512))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    entity_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    domains: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    next_steps: Mapped[list[str]] = mapped_column(JSON, default=list)
    narrative: Mapped[str] = mapped_column(Text, default="")
    narrative_source: Mapped[str] = mapped_column(String(32), default="deterministic")
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)  # new|acknowledged|dismissed|resolved
    requirement_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)


class PostureSnapshot(Base):
    """The posture score as it stood on one day (one row per day; the trend is read from these)."""

    __tablename__ = "posture_snapshots"

    day: Mapped[str] = mapped_column(String(10), primary_key=True)             # YYYY-MM-DD (UTC)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)        # domains, factors, formula version
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
