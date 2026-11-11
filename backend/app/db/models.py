"""Database models. Columns ending in `_enc` hold AES-GCM ciphertext (see app/core/crypto.py).

Privacy rule: anything a user typed, pasted or uploaded, and anything derived from it (URLs, matched phrases,
IBANs), is stored only in `_enc` columns. Plain columns hold codes, enums, counters and timestamps so that
statistics and administration never need decrypted content.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, list[Any]: JSONB}


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


ROLES = ("user", "support", "admin", "security")
PLANS = ("free", "plus", "family", "business", "enterprise")
KINDS = ("url", "message", "advert", "payment", "qr", "image")
STATUSES = ("queued", "processing", "completed", "failed")
VERDICTS = (
    "known_malicious",
    "strong_suspicious",
    "moderate_warning",
    "insufficient_information",
    "no_known_warning_signals",
)
SEVERITIES = ("known_malicious", "strong", "moderate", "info")
CONFIDENCE = ("low", "medium", "high")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    locale: Mapped[str] = mapped_column(String(8), nullable=False, default="fr")
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    failed_logins: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    onboarding_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    preferences: Mapped[UserPreferences] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False, lazy="joined"
    )
    subscription: Mapped[Subscription] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False, lazy="joined"
    )

    __table_args__ = (
        Index("uq_users_email_lower", func.lower(email), unique=True),
        CheckConstraint(f"role IN {ROLES}", name="ck_users_role"),
        CheckConstraint("locale IN ('fr','en')", name="ck_users_locale"),
    )


class UserPreferences(Base):
    __tablename__ = "user_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # Days to keep analyses. 0 = delete submitted content right after analysis (result summary kept 1 day).
    retention_days: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=90)
    explanation_level: Mapped[str] = mapped_column(String(12), nullable=False, default="standard")
    notify_analysis_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notify_family_warnings: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    product_analytics_opt_in: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_ai_processing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="preferences")

    __table_args__ = (
        CheckConstraint("retention_days IN (0, 30, 90, 365)", name="ck_prefs_retention"),
        CheckConstraint("explanation_level IN ('simple','standard','detailed')", name="ck_prefs_level"),
    )


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    plan: Mapped[str] = mapped_column(String(16), nullable=False, default="free")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    provider_ref: Mapped[str | None] = mapped_column(String(128))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="subscription")

    __table_args__ = (
        CheckConstraint(f"plan IN {PLANS}", name="ck_sub_plan"),
        CheckConstraint("status IN ('active','past_due','canceled')", name="ck_sub_status"),
        CheckConstraint("source IN ('manual','stripe')", name="ck_sub_source"),
    )


class AuthSession(Base):
    """One row per refresh token. Rotation creates a new row; reuse of a rotated token revokes the chain."""

    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    chain_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    client: Mapped[str] = mapped_column(String(16), nullable=False, default="web")
    user_agent: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    storage_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    content_type: Mapped[str] = mapped_column(String(40), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    width: Mapped[int] = mapped_column(Integer, nullable=False)
    height: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    verdict: Mapped[str | None] = mapped_column(String(32))
    confidence: Mapped[str | None] = mapped_column(String(8))
    language: Mapped[str] = mapped_column(String(8), nullable=False, default="fr")
    upload_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("uploads.id", ondelete="SET NULL")
    )
    input_enc: Mapped[bytes | None] = mapped_column(LargeBinary)  # submitted text / URL
    label_enc: Mapped[bytes | None] = mapped_column(LargeBinary)  # short label for history (e.g. domain)
    result_enc: Mapped[bytes | None] = mapped_column(LargeBinary)  # extracted entities, org, missing info
    note_enc: Mapped[bytes | None] = mapped_column(LargeBinary)  # user's own note
    modules_run: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    sources_checked: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    ai_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _now()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    findings: Mapped[list[Finding]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
        order_by="Finding.position",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_analyses_user_created", "user_id", "created_at"),
        Index("ix_analyses_expires", "expires_at"),
        CheckConstraint(f"kind IN {KINDS}", name="ck_analyses_kind"),
        CheckConstraint(f"status IN {STATUSES}", name="ck_analyses_status"),
        CheckConstraint(f"verdict IS NULL OR verdict IN {VERDICTS}", name="ck_analyses_verdict"),
        CheckConstraint(f"confidence IS NULL OR confidence IN {CONFIDENCE}", name="ck_analyses_conf"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    position: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    module: Mapped[str] = mapped_column(String(24), nullable=False)
    code: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(8), nullable=False)
    source: Mapped[str] = mapped_column(String(48), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ai_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    details_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # params + evidence

    analysis: Mapped[Analysis] = relationship(back_populates="findings")

    __table_args__ = (
        CheckConstraint(f"severity IN {SEVERITIES}", name="ck_findings_severity"),
        CheckConstraint(f"confidence IN {CONFIDENCE}", name="ck_findings_conf"),
    )


class UsageCounter(Base):
    __tablename__ = "usage_counters"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    period: Mapped[str] = mapped_column(String(7), primary_key=True)  # YYYY-MM
    checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class FamilyGroup(Base):
    __tablename__ = "family_groups"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = _now()

    members: Mapped[list[FamilyMember]] = relationship(
        back_populates="group", cascade="all, delete-orphan", lazy="selectin"
    )


class FamilyMember(Base):
    __tablename__ = "family_members"

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("family_groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(12), nullable=False, default="member")
    age_band: Mapped[str] = mapped_column(String(8), nullable=False, default="adult")
    receive_warnings: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    can_share_warnings: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    joined_at: Mapped[datetime] = _now()

    group: Mapped[FamilyGroup] = relationship(back_populates="members")

    __table_args__ = (
        UniqueConstraint("user_id", name="uq_family_member_one_group"),
        CheckConstraint("role IN ('owner','guardian','member')", name="ck_fm_role"),
        CheckConstraint("age_band IN ('child','teen','adult','senior')", name="ck_fm_age"),
    )


class FamilyInvite(Base):
    __tablename__ = "family_invites"

    id: Mapped[uuid.UUID] = _uuid_pk()
    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("family_groups.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(String(12), nullable=False, default="member")
    age_band: Mapped[str] = mapped_column(String(8), nullable=False, default="adult")
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SharedWarning(Base):
    """A user-approved summary shared with family. Never contains the raw submitted content."""

    __tablename__ = "shared_warnings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("family_groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    shared_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    finding_codes: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    message_enc: Mapped[bytes | None] = mapped_column(LargeBinary)  # optional note written by the sharer
    created_at: Mapped[datetime] = _now()


class SupportAccessGrant(Base):
    """Customer consent letting support staff view one analysis for a limited time. Every view is audited."""

    __tablename__ = "support_access_grants"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False
    )
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("support_tickets.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SupportTicket(Base):
    __tablename__ = "support_tickets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    priority: Mapped[str] = mapped_column(String(8), nullable=False, default="normal")
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="open")
    subject_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    body_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "category IN ('general','technical','account','fraud','security')", name="ck_ticket_cat"
        ),
        CheckConstraint("priority IN ('low','normal','high','urgent')", name="ck_ticket_prio"),
        CheckConstraint("status IN ('open','pending','resolved','closed')", name="ck_ticket_status"),
    )


class AuditLog(Base):
    """Append-only (UPDATE blocked by trigger; DELETE only via the retention purge). No content, ever."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = _now()
    category: Mapped[str] = mapped_column(String(16), nullable=False)  # auth, data, admin, security
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_role: Mapped[str | None] = mapped_column(String(16))
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(12), nullable=False, default="success")
    ip_hash: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_audit_occurred", "occurred_at"),
        Index("ix_audit_category_action", "category", "action"),
    )


class FeatureFlag(Base):
    __tablename__ = "feature_flags"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class SystemConfig(Base):
    __tablename__ = "system_config"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class ThreatSourceHealth(Base):
    __tablename__ = "threat_source_health"

    source: Mapped[str] = mapped_column(String(48), primary_key=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(120))
    success_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_latency_ms: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class AIUsage(Base):
    __tablename__ = "ai_usage"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = _now()
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_micro_eur: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    error_code: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (Index("ix_ai_usage_occurred", "occurred_at"),)


class ErrorEvent(Base):
    __tablename__ = "error_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = _now()
    route: Mapped[str] = mapped_column(String(120), nullable=False)
    error_type: Mapped[str] = mapped_column(String(120), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (Index("ix_error_events_occurred", "occurred_at"),)


__all__ = [n for n in dir() if n[0].isupper()]
