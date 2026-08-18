"""SQLAlchemy ORM models."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    source_type: Mapped[str] = mapped_column(String(50), default="path")  # path | upload | inline
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="Scan.id"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="completed")  # running|completed|failed
    source_ref: Mapped[str] = mapped_column(String(500), default="")

    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    grade: Mapped[str] = mapped_column(String(2), default="A")

    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # full scoring.score() output
    error: Mapped[str] = mapped_column(Text, default="")

    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    project: Mapped["Project"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    rule_id: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(200))
    algorithm: Mapped[str] = mapped_column(String(80), index=True)
    family: Mapped[str] = mapped_column(String(80), index=True)
    quantum_threat: Mapped[str] = mapped_column(String(20), index=True)  # shor|grover|classical
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[str] = mapped_column(String(20), default="High")
    language: Mapped[str] = mapped_column(String(30), index=True)

    file: Mapped[str] = mapped_column(String(500))
    line: Mapped[int] = mapped_column(Integer, default=0)
    column: Mapped[int] = mapped_column(Integer, default=0)
    snippet: Mapped[str] = mapped_column(Text, default="")

    cwe: Mapped[str] = mapped_column(String(20), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")

    pqc_primary: Mapped[str] = mapped_column(String(80), default="")
    pqc_standard: Mapped[str] = mapped_column(String(40), default="")
    migration_difficulty: Mapped[str] = mapped_column(String(20), default="")
    pqc_guidance: Mapped[str] = mapped_column(Text, default="")
    analysis: Mapped[str] = mapped_column(String(10), default="regex", index=True)
    dataflow: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship(back_populates="findings")


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    label: Mapped[str] = mapped_column(String(300), default="")

    subject: Mapped[str] = mapped_column(String(400), default="")
    issuer: Mapped[str] = mapped_column(String(400), default="")
    serial: Mapped[str] = mapped_column(String(80), default="")

    public_key_algorithm: Mapped[str] = mapped_column(String(30), index=True, default="")
    key_size: Mapped[int] = mapped_column(Integer, default=0)
    curve: Mapped[str] = mapped_column(String(40), default="")
    hash_algorithm: Mapped[str] = mapped_column(String(30), default="")
    signature_algorithm: Mapped[str] = mapped_column(String(80), default="")

    not_before: Mapped[str] = mapped_column(String(40), default="")
    not_after: Mapped[str] = mapped_column(String(40), default="")
    days_to_expiry: Mapped[int] = mapped_column(Integer, default=0)
    is_expired: Mapped[bool] = mapped_column(default=False, index=True)
    expiring_soon: Mapped[bool] = mapped_column(default=False)
    is_self_signed: Mapped[bool] = mapped_column(default=False)
    is_ca: Mapped[bool] = mapped_column(default=False)

    quantum_vulnerable: Mapped[bool] = mapped_column(default=False, index=True)
    pqc_ready: Mapped[bool] = mapped_column(default=False)
    pqc_recommendation: Mapped[str] = mapped_column(String(80), default="")

    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    grade: Mapped[str] = mapped_column(String(2), default="A")
    fingerprint_sha256: Mapped[str] = mapped_column(String(80), default="")

    report: Mapped[dict] = mapped_column(JSON, default=dict)  # full analyzer output
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class DependencyReport(Base):
    __tablename__ = "dependency_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    label: Mapped[str] = mapped_column(String(300), default="")
    manifests: Mapped[list] = mapped_column(JSON, default=list)

    total_packages: Mapped[int] = mapped_column(Integer, default=0)
    flagged: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    grade: Mapped[str] = mapped_column(String(2), default="A")

    report: Mapped[dict] = mapped_column(JSON, default=dict)  # full analyzer output incl. SBOM
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
