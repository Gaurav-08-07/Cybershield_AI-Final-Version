
import { useState, useRef } from "react";
import { Search, Shield, AlertTriangle, CheckCircle, HelpCircle, ExternalLink, Clock } from "lucide-react";
import { scanApi, ScanResult } from "../lib/api";
import { verdictBg, verdictLabel, riskScoreColor, formatDate, severityColor } from "../lib/utils";
import RiskRing from "../components/RiskRing";
import Spinner from "../components/Spinner";
import ErrorBanner from "../components/ErrorBanner";
import VerdictBadge from "../components/VerdictBadge";

const VERDICT_ICONS: Record<string, React.ReactNode> = {
  malicious: <AlertTriangle size={20} color="#f87171"/>,
  suspicious: <AlertTriangle size={20} color="#fbbf24"/>,
  no_threat: <CheckCircle size={20} color="#4ade80"/>,
  inconclusive: <HelpCircle size={20} color="#64748b"/>,
};

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;
    setScanning(true);
    setResult(null);
    setError(null);
    try {
      const res = await scanApi.create(trimmed);
      setResult(res.data);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setScanning(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => { if (e.key === "Enter") handleScan(); };

  return (
    <div className="animate-fade-in" style={{ maxWidth: 860 }}>
      {/* Search box */}
      <div className="cs-card" style={{ marginBottom: "1.5rem", background: "rgba(10,22,40,0.9)" }}>
        <div style={{ fontSize: "0.8rem", color: "#22d3ee", fontWeight: 600, marginBottom: "0.75rem", textTransform: "uppercase", letterSpacing: "0.08em" }}>
          Analyze URL for Threats
        </div>
        <div style={{ display: "flex", gap: "0.75rem" }}>
          <div style={{ flex: 1, position: "relative" }}>
            <Search size={16} style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "#475569" }}/>
            <input
              ref={inputRef}
              className="cs-input"
              style={{ paddingLeft: 38 }}
              placeholder="https://example.com — enter a URL to analyze"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={handleKey}
              disabled={scanning}
            />
          </div>
          <button className="btn-primary" onClick={handleScan} disabled={scanning || !url.trim()}>
            {scanning ? <><Spinner size={14}/>Scanning...</> : <><Shield size={16}/>Scan</>}
          </button>
        </div>
        <div style={{ fontSize: "0.72rem", color: "#334155", marginTop: "0.5rem" }}>
          Only http:// and https:// URLs. Private IPs and loopback addresses are not scanned for security reasons.
        </div>
      </div>

      {error && <ErrorBanner message={error} onClose={() => setError(null)}/>}

      {/* Scanning animation */}
      {scanning && (
        <div className="cs-card" style={{ textAlign: "center", padding: "2.5rem", position: "relative", overflow: "hidden" }}>
          <div className="scan-beam"/>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16, color: "#22d3ee" }}>
            <div style={{ position: "relative", width: 80, height: 80 }}>
              <Shield size={80} color="rgba(34,211,238,0.15)" style={{ position: "absolute" }}/>
              <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Spinner size={32}/>
              </div>
            </div>
            <div style={{ fontWeight: 600 }}>Scanning URL...</div>
            <div style={{ fontSize: "0.78rem", color: "#475569" }}>Querying threat intelligence feeds and analyzing indicators</div>
          </div>
        </div>
      )}

      {/* Result */}
      {result && !scanning && (
        <div className="animate-fade-in">
          {/* Header */}
          <div className="cs-card" style={{ marginBottom: "1rem", borderColor: result.verdict === "malicious" ? "rgba(239,68,68,0.3)" : result.verdict === "suspicious" ? "rgba(251,191,36,0.2)" : result.verdict === "no_threat" ? "rgba(74,222,128,0.2)" : "rgba(34,211,238,0.1)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
              <RiskRing score={result.risk_score} size={90}/>
              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  {VERDICT_ICONS[result.verdict] || VERDICT_ICONS.inconclusive}
                  <VerdictBadge verdict={result.verdict} size="md"/>
                  {result.category && <span style={{ fontSize: "0.75rem", color: "#64748b", background: "rgba(100,116,139,0.1)", padding: "2px 8px", borderRadius: 999 }}>{result.category}</span>}
                </div>
                <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "0.85rem", color: "#94a3b8", wordBreak: "break-all", marginBottom: 6 }}>{result.url}</div>
                <div style={{ fontSize: "0.75rem", color: "#475569", display: "flex", gap: 16 }}>
                  <span><Clock size={12} style={{ verticalAlign: "middle", marginRight: 4 }}/>{formatDate(result.created_at)}</span>
                  {result.confidence !== null && <span>Confidence: {Math.round(result.confidence * 100)}%</span>}
                  <span>Provider: {result.provider_status ?? "N/A"}</span>
                </div>
              </div>
            </div>

            {result.error_message && (
              <div style={{ marginTop: "0.75rem", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 6, padding: "0.6rem 0.75rem", fontSize: "0.8rem", color: "#fca5a5" }}>
                {result.error_message}
              </div>
            )}

            <div style={{ marginTop: "0.75rem", padding: "0.6rem 0.75rem", background: "rgba(34,211,238,0.04)", borderRadius: 6, fontSize: "0.72rem", color: "#475569" }}>
              <strong style={{ color: "#64748b" }}>Disclaimer:</strong> Absence of threat-feed match does not guarantee a URL is safe. Results reflect available threat intelligence at time of scan only.
            </div>
          </div>

          {/* Evidence */}
          {result.evidence.length > 0 && (
            <div className="cs-card">
              <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Detection Evidence ({result.evidence.length})
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {result.evidence.map(ev => (
                  <div key={ev.id} style={{ background: "rgba(15,32,68,0.5)", borderRadius: 6, padding: "0.75rem", border: "1px solid rgba(34,211,238,0.06)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <span style={{ fontSize: "0.72rem", background: "rgba(34,211,238,0.1)", color: "#22d3ee", padding: "1px 8px", borderRadius: 999, fontWeight: 600 }}>{ev.source}</span>
                        <span style={{ fontSize: "0.72rem", color: "#475569" }}>{ev.evidence_type.replace(/_/g, " ")}</span>
                      </div>
                      {ev.severity && <span style={{ fontSize: "0.7rem", color: ev.severity === "high" || ev.severity === "critical" ? "#f87171" : ev.severity === "medium" ? "#fbbf24" : "#4ade80", fontWeight: 600 }}>{ev.severity.toUpperCase()}</span>}
                    </div>
                    {ev.detail && <div style={{ fontSize: "0.8rem", color: "#94a3b8" }}>{ev.detail}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
