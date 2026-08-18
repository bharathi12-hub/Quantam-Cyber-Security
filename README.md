# 🛡️ QuantumShield

### Enterprise Platform for Quantum-Safe Cryptography Assessment and Migration

QuantumShield scans source code for cryptography that will be broken by quantum
computers, classifies each finding by **how** quantum computing defeats it, scores
your overall risk posture, and maps every issue to a **NIST-standardized
post-quantum replacement** (ML-KEM / ML-DSA / SLH-DSA — FIPS 203/204/205).

> **"Harvest now, decrypt later"** — adversaries are recording encrypted traffic
> today to decrypt once quantum computers mature. QuantumShield tells you exactly
> where you are exposed and what to migrate to.

---

## ✨ What it does

A **working, runnable** quantum-safe security console — every panel is wired to a
real backend API with real data (no placeholders, no fake charts):

| Capability | Status |
|---|---|
| **Repository scanner** — clone any public GitHub/GitLab repo by URL and scan it (shallow, with SSRF guard) | ✅ Implemented |
| **AST analysis for Python** — real syntax-tree parsing with import/alias resolution + **data-flow taint tracking** (hardcoded secret → crypto sink); regex fallback on parse errors | ✅ Implemented |
| **PQC Migration Engine** — phased roadmap (quick wins → key exchange → signatures → hardening) with effort, timeline, risk-reduction, compatibility, and **rollback strategy** | ✅ Implemented |
| **Migration Impact Simulation** — key/sig/storage growth, per-handshake + daily bandwidth, latency, compatibility risk, downtime — grounded in real FIPS 203/204/205 sizes | ✅ Implemented |
| **Compliance mapping** — findings → NIST PQC, NIST 800-53, OWASP ASVS + Top 10, PCI DSS 4.0, ISO 27001, SOC 2, CIS v8 (per-framework posture + control matrix) | ✅ Implemented |
| **Analytics** — cryptographic risk matrix (severity × quantum-threat) + cryptographic dependency graph (detected → quantum-safe) | ✅ Implemented |
| **Crypto static analysis** — 13 languages + IaC/CI/config (Terraform, Dockerfile, YAML, SSH, nginx, …) | ✅ Implemented |
| Detects RSA, ECC/ECDSA, EdDSA, DSA, DH/ECDH, MD5, SHA-1/224, DES/3DES, RC2/RC4, Blowfish, ECB, weak RNG, hardcoded keys/secrets/IVs, short keys, weak JWT (`alg:none`), weak SSH, weak password hashing, obsolete TLS | ✅ Implemented |
| **Quantum-threat classification** (Shor-broken / Grover-weakened / classically-weak) | ✅ Implemented |
| **NIST PQC recommendation engine** (per-finding target, difficulty, size/perf impact) | ✅ Implemented |
| **Certificate intelligence** — real X.509 (PEM/DER) parsing, expiry, weak key/sig, self-signed, **PQC readiness** | ✅ Implemented |
| **Dependency & SBOM** — parses requirements/package.json/go.mod/Cargo.toml/pom/…, flags crypto-risky packages, emits **CycloneDX 1.5** | ✅ Implemented |
| **Enterprise risk engine** — risk, quantum-readiness, compliance, migration-effort, threat-level, confidence | ✅ Implemented |
| **AI Security Advisor** — offline, knowledge-based: explains findings/algorithms/NIST, generates secure replacement code, summarizes scans | ✅ Implemented |
| **Reporting** — export **PDF / SARIF 2.1.0 / CSV / JSON / Markdown** | ✅ Implemented |
| **SOC console UI** — dark glassmorphism, command palette (Ctrl K), global search, notifications, keyboard shortcuts, collapsible sidebar | ✅ Implemented |
| REST API (FastAPI + OpenAPI), SQLAlchemy persistence, seed data | ✅ 37 endpoints / 11 modules |
| Automated tests (pytest) | ✅ 32 passing |

See [**Roadmap**](#-roadmap) for the remaining infra stream (Postgres/Redis,
RBAC/MFA, Docker/K8s, WebSockets, observability).

---

## 🚀 Quickstart

**Prerequisites:** Python 3.11+ and Node 18+ (developed on Python 3.14 / Node 24).

You need **two terminals** — one for the API, one for the dashboard.

### Windows (one-click scripts)

```bat
REM Terminal 1 — API  (creates venv, installs, seeds, serves on :8000)
scripts\run-backend.cmd

REM Terminal 2 — Dashboard  (installs, serves on :5173)
scripts\run-frontend.cmd
```

### Manual (any OS)

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv
.venv/Scripts/activate            # Windows
# source .venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
python -m app.seed                # loads the demo scan
python -m uvicorn app.main:app --port 8000

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```

Then open **http://localhost:5173**.

- API docs (Swagger UI): **http://localhost:8000/docs**
- The dashboard's Vite dev server proxies `/api/*` to the backend automatically.

> First run: the dashboard shows an empty state with a **“Run demo scan”** button,
> or run `python -m app.seed` (done for you by `run-backend.cmd`) to pre-load a scan
> of the bundled intentionally-vulnerable sample app.

---

## 🧠 How it works

```
                    ┌────────────────────────────────────────────┐
   Source code ───► │  Detection Engine (rule-based static scan)  │
   (repo / paste)   │  • language detection                       │
                    │  • ~25 crypto rules, per-language regex      │
                    │  • comment-aware (skips comments; keeps      │
                    │    meaningful signals like #include md5.h)   │
                    └───────────────────┬────────────────────────┘
                                        │ findings (file:line, severity)
                    ┌───────────────────▼────────────────────────┐
                    │  Quantum classification + PQC mapping        │
                    │  Shor / Grover / classical  →  FIPS 203/204/205
                    └───────────────────┬────────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────────┐
                    │  Risk scoring   →  0–100 score, A–F grade    │
                    └───────────────────┬────────────────────────┘
                                        │ persisted (SQLAlchemy)
              REST API (FastAPI)  ◄─────┘  ─────►  React dashboard
```

**Quantum-threat model**

- **Shor-broken** — RSA, ECC/ECDSA, EdDSA, DSA, DH/ECDH. Public-key crypto whose
  hard problem (factoring / discrete log) Shor's algorithm solves outright. *Must
  migrate to PQC.*
- **Grover-weakened** — 128-bit symmetric keys / short hashes. Grover halves the
  effective strength; *double the size* (e.g. AES-256).
- **Classically-weak** — MD5, SHA-1, DES, RC4, ECB, hardcoded keys, weak RNG.
  Already broken regardless of quantum computing.

---

## 🔌 API reference (v1)

| Method | Endpoint | Description |
|---|---|---|
| `GET`  | `/api/health` | Liveness + app metadata |
| `GET`  | `/api/dashboard` | Aggregated posture across latest scans |
| `POST` | `/api/scans/demo` | Scan the bundled vulnerable sample app |
| `POST` | `/api/scans/inline` | Scan pasted source (`{filename, content}`) |
| `POST` | `/api/scans/repository` | Clone a public Git repo by URL and scan it |
| `GET`  | `/api/migration/plan` | Phased PQC migration roadmap for a scan |
| `POST` | `/api/scans/path` | Scan a directory on the host (sandboxed) |
| `POST` | `/api/scans/upload` | Scan uploaded files (multipart) |
| `GET`  | `/api/scans` | List scans |
| `GET`  | `/api/scans/{id}` | Scan detail + full posture summary |
| `GET`  | `/api/scans/{id}/findings` | Findings (filter/sort/paginate) |
| `GET`  | `/api/certificates` · `/analyze` · `/summary` · `/demo` | X.509 analysis & inventory |
| `GET`  | `/api/dependencies` · `/{id}/sbom` · `/demo` | Dependency analysis & CycloneDX SBOM |
| `POST` | `/api/advisor/ask` · `/summarize` · `GET /explain/{rule}` | AI Security Advisor |
| `GET`  | `/api/reports/scan/{id}?format=pdf\|sarif\|csv\|json\|md` | Report export |
| `GET`  | `/api/projects` · `/api/meta/algorithms` · `/api/meta/rules` | Projects, PQC catalog, ruleset |

Findings query params: `severity`, `quantum_threat`, `language`, `family`,
`search`, `sort_by`, `sort_dir`, `page`, `page_size`.

**Keyboard:** `Ctrl K` command palette · `/` search · `g` then `d/f/c/p/a/r/s` to navigate.

Example:

```bash
curl -X POST http://localhost:8000/api/scans/demo
curl "http://localhost:8000/api/scans/1/findings?severity=Critical&quantum_threat=shor"
```

---

## 🧪 Testing

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest
```

Covers detection accuracy (algorithm→PQC mapping, comment handling, language
scoping, multi-finding lines) and scoring invariants.

---

## 🗂️ Project structure

```
Quantam Cyber Security/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── detection/     # languages, rules (the ruleset), engine
│   │   │   ├── pqc/           # NIST PQC recommendation catalog
│   │   │   └── risk/          # scoring & aggregation
│   │   ├── api/               # meta, projects, scans, dashboard routers
│   │   ├── services/          # scan orchestration
│   │   ├── models.py          # SQLAlchemy ORM
│   │   ├── schemas.py         # Pydantic contracts
│   │   ├── config.py / database.py / main.py / seed.py
│   │   └── ...
│   └── tests/                 # pytest suite
├── frontend/
│   └── src/
│       ├── pages/             # Dashboard, Findings, NewScan, Algorithms
│       ├── components/        # Layout, charts, RiskGauge, primitives
│       ├── lib/               # typed API client, UI helpers
│       └── hooks/             # theme
├── samples/vulnerable-app/    # intentionally-vulnerable multi-language code
└── scripts/                   # run-backend.cmd / run-frontend.cmd
```

---

## 🧰 Tech stack

**Backend:** Python · FastAPI · SQLAlchemy 2 · Pydantic v2 · Uvicorn · SQLite · `cryptography` (X.509) · `reportlab` (PDF)
**Frontend:** React 18 · TypeScript · Vite · Tailwind CSS (glassmorphism) · Recharts · React Router · lucide-react
**Standards:** NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · CycloneDX 1.5 · SARIF 2.1.0 · CWE

---

## 🛣️ Roadmap

Delivered so far: crypto scanner (13 languages + IaC), **repository scanning by
URL**, **AST analysis + taint tracking (Python)**, certificate intelligence,
dependency/SBOM, enterprise risk engine, AI advisor, **PQC migration engine +
impact simulation**, **compliance mapping (8 frameworks)**, **analytics graphs**,
multi-format reporting, and the SOC console UI. The remaining stream is
production infrastructure:

- **Data layer** — PostgreSQL + Redis, Alembic migrations, repository pattern.
- **Auth** — JWT + refresh, RBAC, MFA, API keys, audit logs (OAuth2/SSO/LDAP).
- **Real-time** — WebSocket live scan progress, background workers / task queue.
- **Deeper static analysis** — CFG/call-graph + AST for JS/TS/Java/Go.
- **PQC benchmark engine** — measure ML-KEM/ML-DSA keygen/sign/verify vs. classical.
- **DevSecOps & observability** — Docker Compose / K8s / Helm, Prometheus + Grafana + OpenTelemetry.

---

## ⚠️ Note on the sample code

Everything under `samples/vulnerable-app/` is **intentionally insecure** for
demonstration only. The PEM block there is a non-functional placeholder, not a
real key. Never use any of it in production.
