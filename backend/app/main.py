"""
QuantumShield API entrypoint.

Enterprise Platform for Quantum-Safe Cryptography Assessment and Migration.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import (
    advisor,
    certificates,
    compliance,
    dashboard,
    dependencies,
    meta,
    migration,
    projects,
    reports,
    scans,
    simulation,
)
from .config import settings
from .database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=settings.tagline,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API = "/api"
app.include_router(meta.router, prefix=API)
app.include_router(projects.router, prefix=API)
app.include_router(scans.router, prefix=API)
app.include_router(certificates.router, prefix=API)
app.include_router(dependencies.router, prefix=API)
app.include_router(advisor.router, prefix=API)
app.include_router(reports.router, prefix=API)
app.include_router(migration.router, prefix=API)
app.include_router(compliance.router, prefix=API)
app.include_router(simulation.router, prefix=API)
app.include_router(dashboard.router, prefix=API)


@app.get("/")
def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "tagline": settings.tagline,
        "docs": "/docs",
        "api": API,
    }
