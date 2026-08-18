"""Application configuration (env-overridable via QS_* variables)."""
from __future__ import annotations

import os

from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class Settings(BaseSettings):
    app_name: str = "QuantumShield"
    app_version: str = "0.1.0"
    tagline: str = "Enterprise Platform for Quantum-Safe Cryptography Assessment and Migration"

    # Persistence
    database_url: str = "sqlite:///./quantumshield.db"

    # CORS - the Vite dev server + common local ports
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:4173",
    ]

    # Default sample tree used by the seed script / demo scans
    samples_path: str = os.path.join(_REPO_ROOT, "samples", "vulnerable-app")
    dep_samples_path: str = os.path.join(_REPO_ROOT, "samples", "sample-manifests")

    # Guardrail: only allow on-disk path scans under these roots (defense in depth)
    scan_allowed_roots: list[str] = [_REPO_ROOT]

    model_config = SettingsConfigDict(env_prefix="QS_", env_file=".env", extra="ignore")


settings = Settings()
