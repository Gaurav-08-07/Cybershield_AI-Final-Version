
import { useEffect, useState } from "react";
import { Shield, ShieldCheck, ShieldAlert, RefreshCw, ExternalLink, AlertCircle } from "lucide-react";
import { healthApi } from "../lib/api";
import Spinner from "../components/Spinner";

export default function SafeBrowse() {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = () => {
    setLoading(true);
    healthApi.extensionStatus()
      .then(res => setStatus(res.data))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchStatus(); }, []);

  return (
    <div className="animate-fade-in" style={{ maxWidth: 760 }}>
      {/* Status Card */}
      <div className="cs-card" style={{ marginBottom: "1.5rem", borderColor: status?.status === "operational" ? "rgba(74,222,128,0.2)" : "rgba(239,68,68,0.2)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ width: 64, height: 64, borderRadius: "1rem", background: status?.status === "operational" ? "rgba(74,222,128,0.1)" : "rgba(239,68,68,0.1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            {loading ? <Spinner size={28}/> : status?.status === "operational" ? <ShieldCheck size={32} color="#4ade80"/> : <ShieldAlert size={32} color="#f87171"/>}
          </div>
          <div>
            <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#e2e8f0", marginBottom: 4 }}>CyberShield SafeBrowse</div>
            <div style={{ fontSize: "0.85rem", color: status?.status === "operational" ? "#4ade80" : "#f87171" }}>
              {loading ? "Checking status..." : status?.status === "operational" ? "Protection Backend Operational" : "Backend Unavailable"}
            </div>
            {status && <div style={{ fontSize: "0.75rem", color: "#475569", marginTop: 4 }}>Active rules: {status.active_rules ?? 0} · Last updated: {status.last_updated ? new Date(status.last_updated).toLocaleString() : "N/A"}</div>}
          </div>
          <button className="btn-ghost" onClick={fetchStatus} style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
            <RefreshCw size={14}/> Refresh
          </button>
        </div>
        {error && <div style={{ marginTop: "0.75rem", fontSize: "0.8rem", color: "#f87171" }}>{error}</div>}
        {status?.coverage_note && (
          <div style={{ marginTop: "0.75rem", background: "rgba(34,211,238,0.04)", borderRadius: 6, padding: "0.6rem 0.75rem", fontSize: "0.75rem", color: "#475569" }}>
            <strong style={{ color: "#64748b" }}>Coverage note:</strong> {status.coverage_note}
          </div>
        )}
      </div>

      {/* Installation guide */}
      <div className="cs-card" style={{ marginBottom: "1.5rem" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Extension Installation</div>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          {[
            { step: 1, title: "Open Chrome Extensions", detail: "Navigate to chrome://extensions in your browser" },
            { step: 2, title: "Enable Developer Mode", detail: "Toggle the Developer Mode switch in the top-right corner" },
            { step: 3, title: "Load Unpacked Extension", detail: "Click Load Unpacked and select the /extension folder from the project" },
            { step: 4, title: "Configure Backend URL", detail: "The extension connects to http://localhost:8000 by default" },
            { step: 5, title: "Verify Connection", detail: "The extension popup should show Backend Online status" },
          ].map(s => (
            <div key={s.step} style={{ display: "flex", gap: 16, alignItems: "flex-start" }}>
              <div style={{ width: 28, height: 28, borderRadius: "50%", background: "rgba(34,211,238,0.1)", border: "1px solid rgba(34,211,238,0.2)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#22d3ee" }}>{s.step}</span>
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: "0.85rem", color: "#e2e8f0", marginBottom: 2 }}>{s.title}</div>
                <div style={{ fontSize: "0.78rem", color: "#475569" }}>{s.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* How it works */}
      <div className="cs-card" style={{ background: "rgba(8,20,40,0.5)" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>How SafeBrowse Works</div>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
          {[
            { icon: "01", title: "Rule Synchronization", desc: "The extension fetches confirmed malicious domains from the backend API at startup and on a schedule. Rules are stored locally using Chrome\'s declarativeNetRequest API." },
            { icon: "02", title: "Navigation Interception", desc: "When you navigate to a URL matching a known malicious domain, Chrome\'s declarativeNetRequest engine redirects the request to the extension\'s warning page before the dangerous site loads." },
            { icon: "03", title: "NOT SAFE TO BROWSE Warning", desc: "The warning page clearly shows the threat information, evidence source, and offers a safe way back. It never loads or fetches content from the blocked site." },
            { icon: "04", title: "Known Limitations", desc: "Only URLs with confirmed matching rules are blocked. New threats not yet in the local ruleset will not be blocked until the next sync. The extension cannot block all malware on the internet." },
          ].map(s => (
            <div key={s.icon} style={{ display: "flex", gap: 12 }}>
              <div style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "0.7rem", fontWeight: 700, color: "rgba(34,211,238,0.4)", paddingTop: 2, flexShrink: 0 }}>{s.icon}</div>
              <div>
                <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "#94a3b8", marginBottom: 2 }}>{s.title}</div>
                <div style={{ fontSize: "0.78rem", color: "#475569", lineHeight: 1.5 }}>{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: "1rem", padding: "0.75rem", background: "rgba(239,68,68,0.06)", borderRadius: 6, border: "1px solid rgba(239,68,68,0.15)" }}>
          <div style={{ fontSize: "0.75rem", color: "#fca5a5" }}>
            <AlertCircle size={12} style={{ verticalAlign: "middle", marginRight: 6 }}/>
            <strong>Detection is not perfect.</strong> CyberShield cannot guarantee protection against all threats. Always exercise caution when browsing.
          </div>
        </div>
      </div>
    </div>
  );
}
