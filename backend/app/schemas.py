"""Pydantic request/response schemas (API contract)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------- Projects
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    source_type: str = "path"


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    source_type: str
    created_at: datetime
    updated_at: datetime


# ----------------------------------------------------------------------- Scans
class InlineScanRequest(BaseModel):
    """Scan pasted source code."""
    project_id: Optional[int] = None
    project_name: Optional[str] = None
    filename: str = Field("snippet.py", max_length=200)
    content: str = Field(..., min_length=1)


class PathScanRequest(BaseModel):
    """Scan a directory / file already on the server host."""
    project_id: Optional[int] = None
    project_name: Optional[str] = None
    path: str = Field(..., min_length=1)


class RepoScanRequest(BaseModel):
    """Clone and scan a public Git repository."""
    url: str = Field(..., min_length=4)
    branch: Optional[str] = None
    project_name: Optional[str] = None


class FileBlob(BaseModel):
    path: str
    content: str


class MultiFileScanRequest(BaseModel):
    project_id: Optional[int] = None
    project_name: Optional[str] = None
    files: list[FileBlob]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    name: str
    algorithm: str
    family: str
    quantum_threat: str
    severity: str
    confidence: str
    language: str
    file: str
    line: int
    column: int
    snippet: str
    cwe: str
    description: str
    remediation: str
    pqc_primary: str
    pqc_standard: str
    migration_difficulty: str
    pqc_guidance: str
    analysis: str = "regex"
    dataflow: str = ""


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    source_ref: str
    files_scanned: int
    lines_scanned: int
    total_findings: int
    risk_score: int
    grade: str
    summary: dict[str, Any]
    error: str
    started_at: datetime
    completed_at: datetime


class ScanSummaryOut(BaseModel):
    """Lightweight scan card (no full summary payload)."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    source_ref: str
    files_scanned: int
    total_findings: int
    risk_score: int
    grade: str
    completed_at: datetime


class PagedFindings(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[FindingOut]


class DashboardOut(BaseModel):
    projects: int
    scans: int
    posture: dict[str, Any]
    recent_scans: list[ScanSummaryOut]
    top_findings: list[FindingOut]
    certificates: dict[str, Any] = {}


# ----------------------------------------------------------------- Certificates
class CertAnalyzeRequest(BaseModel):
    pem: str = Field(..., min_length=1)
    label: Optional[str] = None
    project_id: Optional[int] = None


class CertificateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    label: str
    subject: str
    issuer: str
    serial: str
    public_key_algorithm: str
    key_size: int
    curve: str
    hash_algorithm: str
    signature_algorithm: str
    not_before: str
    not_after: str
    days_to_expiry: int
    is_expired: bool
    expiring_soon: bool
    is_self_signed: bool
    is_ca: bool
    quantum_vulnerable: bool
    pqc_ready: bool
    pqc_recommendation: str
    risk_score: int
    grade: str
    fingerprint_sha256: str
    report: dict[str, Any]
    created_at: datetime


# ----------------------------------------------------------------- Dependencies
class DependencyAnalyzeRequest(BaseModel):
    files: list[FileBlob]
    label: Optional[str] = None
    project_id: Optional[int] = None


class DependencyReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    label: str
    manifests: list[str]
    total_packages: int
    flagged: int
    risk_score: int
    grade: str
    report: dict[str, Any]
    created_at: datetime
