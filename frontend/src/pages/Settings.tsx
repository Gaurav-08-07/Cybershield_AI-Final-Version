
import { useState, useEffect } from "react";
import { Save, Key, Globe, ShieldCheck } from "lucide-react";
import { healthApi } from "../lib/api";

export default function Settings() {
  const [health, setHealth] = useState<any>(null);
  const [saved, setSaved] = useState(false);
  const [backendUrl, setBackendUrl] = useState("http://localhost:8000");

  useEffect(() => {
    healthApi.check().then(res => setHealth(res.data)).catch(() => {});
    const stored = localStorage.getItem("cs_backend_url");
    if (stored) setBackendUrl(stored);
  }, []);

  const handleSave = () => {
    localStorage.setItem("cs_backend_url", backendUrl);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="animate-fade-in" style={{ maxWidth: 640 }}>
      <div className="cs-card" style={{ marginBottom: "1rem" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em", display: "flex", alignItems: "center", gap: 8 }}>
          <Globe size={14}/> Backend Connection
        </div>
        <label style={{ fontSize: "0.8rem", color: "#94a3b8", display: "block", marginBottom: 6 }}>Backend API URL</label>
        <input className="cs-input" value={backendUrl} onChange={e => setBackendUrl(e.target.value)} style={{ marginBottom: "0.75rem" }}/>
        <button className="btn-primary" onClick={handleSave} style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Save size={14}/>{saved ? "Saved!" : "Save Settings"}
        </button>
      </div>

      <div className="cs-card" style={{ marginBottom: "1rem" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em", display: "flex", alignItems: "center", gap: 8 }}>
          <Key size={14}/> Threat Intelligence Providers
        </div>
        <div style={{ fontSize: "0.82rem", color: "#94a3b8", marginBottom: "1rem" }}>
          Provider API keys are configured in the backend <code style={{ fontFamily: "monospace", background: "rgba(34,211,238,0.08)", padding: "1px 6px", borderRadius: 4, color: "#22d3ee" }}>.env</code> file — they are never sent to or stored in the frontend.
        </div>
        {health?.providers && Object.entries(health.providers).map(([name, info]: [string, any]) => (
          <div key={name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.6rem 0", borderBottom: "1px solid rgba(34,211,238,0.05)" }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "#e2e8f0" }}>{name}</div>
              <div style={{ fontSize: "0.72rem", color: "#475569" }}>{info.type}</div>
            </div>
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: info.enabled ? "#4ade80" : "#475569" }}>
              {info.enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
        ))}
        <div style={{ marginTop: "0.75rem", fontSize: "0.75rem", color: "#334155" }}>
          To enable VirusTotal: add <code style={{ fontFamily: "monospace", color: "#22d3ee" }}>VIRUSTOTAL_API_KEY=your_key</code> to backend/.env and restart the server.
        </div>
      </div>

      <div className="cs-card" style={{ background: "rgba(8,20,40,0.5)" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "0.75rem", textTransform: "uppercase", letterSpacing: "0.06em", display: "flex", alignItems: "center", gap: 8 }}>
          <ShieldCheck size={14}/> Privacy & Data Retention
        </div>
        <div style={{ fontSize: "0.78rem", color: "#475569", lineHeight: 1.8 }}>
          <div>• URLs submitted for scanning are stored in the local database for history and reporting.</div>
          <div>• No sensitive URL query parameters are stored beyond what is needed for analysis.</div>
          <div>• No user accounts or personal data are collected by default.</div>
          <div>• The Chrome extension sends only the hostname/URL to the backend for scanning — not browsing history.</div>
          <div>• Provider API keys are stored server-side only and never transmitted to the browser.</div>
          <div>• Log content submitted for analysis is stored for job tracking but not shared with third parties.</div>
        </div>
      </div>
    </div>
  );
}
