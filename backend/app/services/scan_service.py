"""
Scan orchestration: run the detection engine, score the result, and persist a
Scan plus its Findings. Also resolves/creates the owning Project.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..config import settings
from ..core.detection.engine import ScanResult, scan_path, scan_sources
from ..core.risk import scoring
from ..models import Finding, Project, Scan


class ScanError(Exception):
    """Raised for invalid scan requests (bad path, missing project, etc.)."""


# ------------------------------------------------------------------ project mgmt
def resolve_project(
    db: Session,
    project_id: Optional[int],
    project_name: Optional[str],
    source_type: str = "path",
) -> Project:
    if project_id is not None:
        project = db.get(Project, project_id)
        if project is None:
            raise ScanError(f"Project {project_id} not found")
        return project

    name = (project_name or "Untitled Project").strip()
    project = Project(name=name, description="", source_type=source_type)
    db.add(project)
    db.flush()  # assign id without committing yet
    return project


# ------------------------------------------------------------------ path safety
def _validate_path(path: str) -> str:
    real = os.path.realpath(path)
    if not os.path.exists(real):
        raise ScanError(f"Path does not exist: {path}")
    allowed = [os.path.realpath(root) for root in settings.scan_allowed_roots]
    if not any(real == root or real.startswith(root + os.sep) for root in allowed):
        raise ScanError(
            "Path is outside the permitted scan roots. "
            "Set QS_SCAN_ALLOWED_ROOTS to broaden the sandbox."
        )
    return real


# ------------------------------------------------------------------ persistence
def _persist(db: Session, project: Project, source_ref: str, result: ScanResult) -> Scan:
    summary = scoring.score(result.findings) if result.findings else scoring.empty_summary()
    now = datetime.now(timezone.utc)

    scan = Scan(
        project_id=project.id,
        status="completed",
        source_ref=source_ref,
        files_scanned=result.files_scanned,
        lines_scanned=result.lines_scanned,
        total_findings=len(result.findings),
        risk_score=summary["risk_score"],
        grade=summary["grade"],
        summary=summary,
        error="; ".join(result.errors[:5]),
        started_at=now,
        completed_at=now,
    )
    db.add(scan)
    db.flush()

    for f in result.findings:
        db.add(Finding(scan_id=scan.id, **f.to_dict()))

    db.commit()
    db.refresh(scan)
    return scan


# ---------------------------------------------------------------------- runners
def run_path_scan(
    db: Session, path: str, project_id: Optional[int], project_name: Optional[str]
) -> Scan:
    real = _validate_path(path)
    project = resolve_project(db, project_id, project_name or os.path.basename(real.rstrip(os.sep)), "path")
    result = scan_path(real)
    return _persist(db, project, real, result)


def run_inline_scan(
    db: Session,
    filename: str,
    content: str,
    project_id: Optional[int],
    project_name: Optional[str],
) -> Scan:
    project = resolve_project(db, project_id, project_name or "Inline Snippet", "inline")
    result = scan_sources({filename: content})
    return _persist(db, project, f"inline:{filename}", result)


def run_multifile_scan(
    db: Session,
    files: dict[str, str],
    project_id: Optional[int],
    project_name: Optional[str],
) -> Scan:
    if not files:
        raise ScanError("No files provided")
    project = resolve_project(db, project_id, project_name or "Uploaded Files", "upload")
    result = scan_sources(files)
    return _persist(db, project, f"upload:{len(files)} files", result)


# ------------------------------------------------------------ repository scanning
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _addr_is_internal(ip: ipaddress._BaseAddress) -> bool:
    """True if an address (unwrapping NAT64 / IPv4-mapped) targets an internal host."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def _validate_repo_url(url: str) -> str:
    """Validate a repo URL and guard against SSRF to internal hosts."""
    url = url.strip()
    if not _URL_RE.match(url):
        raise ScanError("Only http(s) Git URLs are supported.")
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ScanError("Invalid repository URL.")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ScanError(f"Cannot resolve host '{host}'.")
    for info in infos:
        if _addr_is_internal(ipaddress.ip_address(info[4][0])):
            raise ScanError("Refusing to scan an internal/private host (SSRF guard).")
    return url


def _rm_readonly(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _repo_name(url: str) -> str:
    tail = urlparse(url).path.rstrip("/").split("/")[-1]
    return re.sub(r"\.git$", "", tail) or "repository"


def run_repository_scan(
    db: Session,
    url: str,
    branch: Optional[str],
    project_id: Optional[int],
    project_name: Optional[str],
) -> Scan:
    safe_url = _validate_repo_url(url)
    dest = tempfile.mkdtemp(prefix="qs-repo-")
    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [safe_url, dest]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
        )
        if proc.returncode != 0:
            err = (proc.stderr or "git clone failed").strip().splitlines()[-1:]
            raise ScanError(f"Clone failed: {' '.join(err)[:200]}")

        project = resolve_project(db, project_id, project_name or _repo_name(safe_url), "repo")
        result = scan_path(dest)
        return _persist(db, project, safe_url, result)
    except subprocess.TimeoutExpired:
        raise ScanError("Clone timed out (repository too large or unreachable).")
    finally:
        shutil.rmtree(dest, onerror=_rm_readonly)
