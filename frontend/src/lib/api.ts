// Typed API client for the QuantumShield backend.

export type QuantumThreat = "shor" | "grover" | "classical";
export type Severity = "Critical" | "High" | "Medium" | "Low";

export interface Posture {
  risk_score: number;
  grade: string;
  total_findings: number;
  quantum_vulnerable: number;
  quantum_weakened: number;
  classically_weak: number;
  quantum_vulnerable_pct: number;
  quantum_readiness: number;
  migration_effort: number;
  compliance_score: number;
  confidence: number;
  threat_level: string;
  by_severity: Record<Severity, number>;
  by_quantum_threat: Record<QuantumThreat, number>;
  by_family: Record<string, number>;
  by_algorithm: Record<string, number>;
  by_language: Record<string, number>;
  recommended_targets: Record<string, number>;
}

export interface Finding {
  id: number;
  rule_id: string;
  name: string;
  algorithm: string;
  family: string;
  quantum_threat: QuantumThreat;
  severity: Severity;
  confidence: string;
  language: string;
  file: string;
  line: number;
  column: number;
  snippet: string;
  cwe: string;
  description: string;
  remediation: string;
  pqc_primary: string;
  pqc_standard: string;
  migration_difficulty: string;
  pqc_guidance: string;
  analysis?: string;
  dataflow?: string;
}

export interface ScanSummary {
  id: number;
  project_id: number;
  status: string;
  source_ref: string;
  files_scanned: number;
  total_findings: number;
  risk_score: number;
  grade: string;
  completed_at: string;
}

export interface Scan extends ScanSummary {
  lines_scanned: number;
  summary: Posture;
  error: string;
  started_at: string;
}

export interface Project {
  id: number;
  name: string;
  description: string;
  source_type: string;
  created_at: string;
  updated_at: string;
}

export interface CertSummary {
  total: number;
  expired: number;
  quantum_vulnerable: number;
  expiring_soon: number;
  pqc_ready: number;
}

export interface Dashboard {
  projects: number;
  scans: number;
  posture: Posture;
  recent_scans: ScanSummary[];
  top_findings: Finding[];
  certificates: CertSummary;
}

export interface CertFlag {
  severity: Severity;
  title: string;
  detail: string;
}

export interface Certificate {
  id: number;
  label: string;
  subject: string;
  issuer: string;
  serial: string;
  public_key_algorithm: string;
  key_size: number;
  curve: string;
  hash_algorithm: string;
  signature_algorithm: string;
  not_before: string;
  not_after: string;
  days_to_expiry: number;
  is_expired: boolean;
  expiring_soon: boolean;
  is_self_signed: boolean;
  is_ca: boolean;
  quantum_vulnerable: boolean;
  pqc_ready: boolean;
  pqc_recommendation: string;
  risk_score: number;
  grade: string;
  fingerprint_sha256: string;
  report: { flags: CertFlag[]; san: string[]; [k: string]: any };
  created_at: string;
}

export interface DepPackage {
  name: string;
  version: string;
  ecosystem: string;
  scope: string;
  purl: string;
  is_crypto: boolean;
  advisory: { severity: Severity; category: string; note: string; recommendation: string } | null;
}

export interface DependencyReport {
  id: number;
  label: string;
  manifests: string[];
  total_packages: number;
  flagged: number;
  risk_score: number;
  grade: string;
  report: {
    packages: DepPackage[];
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    by_ecosystem: Record<string, number>;
    sbom: any;
  };
  created_at: string;
}

export interface AdvisorReply {
  kind: string;
  answer: string;
  references?: string[];
  concept?: string;
  secure_code?: string | null;
}

export interface MigrationPhase {
  id: number;
  name: string;
  goal: string;
  complexity: string;
  compatibility_score: number;
  rollback: string;
  findings: number;
  affected_files: number;
  effort_days: number;
  duration_weeks: number;
  start_week: number;
  end_week: number;
  risk_reduction: number;
  targets: { target: string; count: number }[];
}

export interface MigrationPlan {
  scan_id: number;
  phases: MigrationPhase[];
  total_findings: number;
  total_effort_days: number;
  estimated_weeks: number;
  team_size: number;
  total_risk_reduction: number;
  priority_note: string;
}

export interface ComplianceControl {
  id: string;
  title: string;
  findings: number;
  severity: Severity;
}
export interface ComplianceFramework {
  name: string;
  status: "Pass" | "Partial" | "Fail";
  score: number;
  findings: number;
  controls_impacted: number;
  controls: ComplianceControl[];
}
export interface CompliancePlan {
  scan_id: number;
  total_findings: number;
  frameworks: ComplianceFramework[];
  overall: { passed: number; partial: number; failed: number };
}

export interface SimMetric {
  name: string;
  before: number;
  after: number;
  unit: string;
  delta_pct: number;
  note: string;
}
export interface SimulationPlan {
  scan_id: number;
  assumptions: { handshakes_per_day: number };
  metrics: SimMetric[];
  bandwidth: {
    per_handshake_before_b: number;
    per_handshake_after_b: number;
    per_handshake_delta_b: number;
    delta_pct: number;
    projected_daily_increase_mb: number;
    note: string;
  };
  latency: { rating: string; notes: string[] };
  compatibility_risk: number;
  downtime: { estimate: string; detail: string };
  api_sites_to_update: number;
  affected: { key_establishment: number; signatures: number; quantum_vulnerable: number };
  summary: string;
}

export interface PagedFindings {
  total: number;
  page: number;
  page_size: number;
  items: Finding[];
}

export interface PQCAlgorithm {
  name: string;
  standard: string;
  kind: string;
  nist_security_category: number;
  summary: string;
  public_key_bytes: number | null;
  private_key_bytes: number | null;
  ciphertext_or_sig_bytes: number | null;
  notes: string;
}

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export interface FindingQuery {
  severity?: string;
  quantum_threat?: string;
  language?: string;
  family?: string;
  search?: string;
  sort_by?: string;
  sort_dir?: string;
  page?: number;
  page_size?: number;
}

export const api = {
  health: () => req<{ status: string; app: string; version: string; tagline: string }>("/health"),
  dashboard: () => req<Dashboard>("/dashboard"),
  projects: () => req<Project[]>("/projects"),
  scans: (projectId?: number) =>
    req<ScanSummary[]>(`/scans${projectId ? `?project_id=${projectId}` : ""}`),
  scan: (id: number) => req<Scan>(`/scans/${id}`),
  algorithms: () => req<{ algorithms: PQCAlgorithm[] }>("/meta/algorithms"),

  runDemo: () => req<Scan>("/scans/demo", { method: "POST" }),
  runInline: (payload: { filename: string; content: string; project_name?: string }) =>
    req<Scan>("/scans/inline", { method: "POST", body: JSON.stringify(payload) }),
  runRepo: (payload: { url: string; branch?: string; project_name?: string }) =>
    req<Scan>("/scans/repository", { method: "POST", body: JSON.stringify(payload) }),

  findings: (scanId: number, q: FindingQuery = {}) => {
    const params = new URLSearchParams();
    Object.entries(q).forEach(([k, v]) => {
      if (v !== undefined && v !== "" && v !== null) params.set(k, String(v));
    });
    const qs = params.toString();
    return req<PagedFindings>(`/scans/${scanId}/findings${qs ? `?${qs}` : ""}`);
  },

  // Certificates
  certificates: () => req<Certificate[]>("/certificates"),
  certificate: (id: number) => req<Certificate>(`/certificates/${id}`),
  certSummary: () => req<CertSummary>("/certificates/summary"),
  analyzeCert: (pem: string, label?: string) =>
    req<Certificate>("/certificates/analyze", { method: "POST", body: JSON.stringify({ pem, label }) }),
  seedCerts: () => req<Certificate[]>("/certificates/demo", { method: "POST" }),

  // Dependencies
  dependencyReports: () => req<DependencyReport[]>("/dependencies"),
  dependencyReport: (id: number) => req<DependencyReport>(`/dependencies/${id}`),
  seedDependencies: () => req<DependencyReport>("/dependencies/demo", { method: "POST" }),
  sbomUrl: (id: number) => `/api/dependencies/${id}/sbom`,

  // Advisor
  advisorAsk: (question: string, scanId?: number) =>
    req<AdvisorReply>("/advisor/ask", {
      method: "POST",
      body: JSON.stringify({ question, scan_id: scanId }),
    }),
  advisorSummarize: (scanId?: number) =>
    req<AdvisorReply>("/advisor/summarize", { method: "POST", body: JSON.stringify({ scan_id: scanId }) }),
  advisorExplainFinding: (findingId: number) => req<any>(`/advisor/finding/${findingId}`),

  // Reports
  reportUrl: (scanId: number, format: string) => `/api/reports/scan/${scanId}?format=${format}`,

  // Migration
  migrationPlan: (scanId?: number) =>
    req<MigrationPlan>(`/migration/plan${scanId ? `?scan_id=${scanId}` : ""}`),

  // Compliance & simulation
  compliancePlan: (scanId?: number) =>
    req<CompliancePlan>(`/compliance/plan${scanId ? `?scan_id=${scanId}` : ""}`),
  simulationPlan: (scanId?: number) =>
    req<SimulationPlan>(`/simulation/plan${scanId ? `?scan_id=${scanId}` : ""}`),
};
