
import { useEffect, useState } from "react";
import { Search, Shield, AlertTriangle } from "lucide-react";
import { threatApi, ThreatIndicator } from "../lib/api";
import { formatDate, severityColor } from "../lib/utils";
import VerdictBadge from "../components/VerdictBadge";
import Spinner from "../components/Spinner";
import EmptyState from "../components/EmptyState";
import ErrorBanner from "../components/ErrorBanner";

export default function ThreatIntelligence() {
  const [data, setData] = useState<{ items: ThreatIndicator[]; total: number; pages: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [verdict, setVerdict] = useState("");

  const fetch = (p: number) => {
    setLoading(true);
    threatApi.list({ page: p, per_page: 20, search: search || undefined, severity: severity || undefined, verdict: verdict || undefined })
      .then(res => setData(res.data))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetch(page); }, [page, search, severity, verdict]);

  const SEV_COLORS: Record<string, string> = { critical: "#f87171", high: "#f87171", medium: "#fbbf24", low: "#4ade80", info: "#64748b" };

  return (
    <div className="animate-fade-in">
      <div className="cs-card" style={{ marginBottom: "1rem" }}>
        <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
          <input className="cs-input" style={{ flex: 1, minWidth: 200 }} placeholder="Search indicators..."
            value={search} onChange={e => { setSearch(e.target.value); setPage(1); }}/>
          <select className="cs-input" style={{ width: 140 }} value={verdict} onChange={e => { setVerdict(e.target.value); setPage(1); }}>
            <option value="">All verdicts</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
          </select>
          <select className="cs-input" style={{ width: 140 }} value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {error && <ErrorBanner message={error} onClose={() => setError(null)}/>}

      <div className="cs-card" style={{ padding: 0 }}>
        <div style={{ padding: "0.75rem 1rem", borderBottom: "1px solid rgba(34,211,238,0.06)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em" }}>Threat Indicators</span>
          <span style={{ fontSize: "0.75rem", color: "#475569" }}>{data?.total ?? 0} active indicators</span>
        </div>
        {loading ? (
          <div style={{ display: "flex", justifyContent: "center", padding: "3rem", gap: 12, color: "#22d3ee" }}><Spinner/> Loading...</div>
        ) : !data?.items?.length ? (
          <EmptyState title="No threat indicators" subtitle="Run URL scans to populate the threat intelligence database" icon={<Shield size={40}/>}/>
        ) : (
          <table className="cs-table">
            <thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Severity</th><th>Source</th><th>Confidence</th><th>Last Seen</th></tr></thead>
            <tbody>
              {data.items.map(t => (
                <tr key={t.id}>
                  <td>
                    <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "0.82rem", color: "#e2e8f0" }}>{t.indicator}</div>
                    {t.category && <span style={{ fontSize: "0.7rem", color: "#475569" }}>{t.category}</span>}
                  </td>
                  <td><span style={{ fontSize: "0.75rem", color: "#64748b", background: "rgba(100,116,139,0.1)", padding: "1px 8px", borderRadius: 999 }}>{t.indicator_type}</span></td>
                  <td><VerdictBadge verdict={t.verdict} size="sm"/></td>
                  <td><span style={{ color: SEV_COLORS[t.severity] ?? "#64748b", fontWeight: 600, fontSize: "0.78rem" }}>{t.severity?.toUpperCase()}</span></td>
                  <td style={{ fontSize: "0.75rem", color: "#64748b" }}>{t.source}</td>
                  <td style={{ fontSize: "0.78rem", fontFamily: "monospace", color: "#94a3b8" }}>{Math.round(t.confidence * 100)}%</td>
                  <td style={{ fontSize: "0.72rem", color: "#475569", whiteSpace: "nowrap" }}>{formatDate(t.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
