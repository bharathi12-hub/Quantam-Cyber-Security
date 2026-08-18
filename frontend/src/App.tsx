import { Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/Layout";
import { useGlobalHotkeys } from "./hooks/useHotkeys";
import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import NewScan from "./pages/NewScan";
import Algorithms from "./pages/Algorithms";
import Certificates from "./pages/Certificates";
import Dependencies from "./pages/Dependencies";
import Advisor from "./pages/Advisor";
import Reports from "./pages/Reports";
import Migration from "./pages/Migration";
import Compliance from "./pages/Compliance";
import Analytics from "./pages/Analytics";
import NotFound from "./pages/NotFound";

const META: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Executive Dashboard", subtitle: "Quantum-safe cryptography posture across your estate" },
  "/findings": {
    title: "Cryptographic Findings",
    subtitle: "Quantum-vulnerable and weak cryptography with PQC migration guidance",
  },
  "/certificates": {
    title: "Certificate Intelligence",
    subtitle: "X.509 inventory, expiry, and post-quantum readiness",
  },
  "/dependencies": {
    title: "Dependencies & SBOM",
    subtitle: "Crypto-relevant package risk and CycloneDX software bill of materials",
  },
  "/advisor": { title: "AI Security Advisor", subtitle: "Explain findings, generate secure code, plan migration" },
  "/migration": { title: "Migration Roadmap", subtitle: "Phased PQC plan with impact simulation, effort, timeline, and rollback" },
  "/compliance": { title: "Compliance", subtitle: "Findings mapped to NIST, PCI DSS, ISO 27001, SOC 2, OWASP, CIS" },
  "/analytics": { title: "Analytics", subtitle: "Cryptographic risk matrix and dependency graph" },
  "/algorithms": { title: "PQC Catalog", subtitle: "Standardized post-quantum migration targets" },
  "/scan": { title: "New Scan", subtitle: "Analyze source code for cryptographic risk" },
  "/reports": { title: "Reports", subtitle: "Export assessments as PDF, SARIF, CSV, JSON, or Markdown" },
};

const NOT_FOUND_META = { title: "Page Not Found", subtitle: "The requested route does not exist" };

// React Router matches paths case-insensitively and ignores a trailing slash, so
// the header lookup has to normalise the same way or a URL like /Reports/ would
// render the Reports page under a "Page Not Found" heading.
function metaFor(pathname: string) {
  const normalised = pathname.toLowerCase().replace(/\/+$/, "") || "/";
  return META[normalised] ?? NOT_FOUND_META;
}

export default function App() {
  const { pathname } = useLocation();
  useGlobalHotkeys();
  const meta = metaFor(pathname);

  return (
    <Layout title={meta.title} subtitle={meta.subtitle}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/certificates" element={<Certificates />} />
        <Route path="/dependencies" element={<Dependencies />} />
        <Route path="/advisor" element={<Advisor />} />
        <Route path="/migration" element={<Migration />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/algorithms" element={<Algorithms />} />
        <Route path="/scan" element={<NewScan />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  );
}
