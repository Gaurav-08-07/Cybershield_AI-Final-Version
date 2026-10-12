
import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { Download, BarChart3 } from "lucide-react";
import { reportApi, ReportSummary } from "../lib/api";
import Spinner from "../components/Spinner";
import ErrorBanner from "../components/ErrorBanner";

const SEV_COLORS: Record<string, string> = { critical: "#ef4444", high: "#f87171", medium: "#fbbf24", low: "#4ade80", info: "#64748b" };

export default function Reports() {
  const [data, setData] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);

  useEffect(() => {
    setLoading(true);
    reportApi.summary(days)
      .then(res => setData(res.data))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [days]);

  const exportJSON = () => {
    if (!data) return;
    const a = document.createElement("a");
    a.href = "data:application/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
    a.download = "cybershield_report.json";
    a.click();
  };

  if (loading) return <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 300, gap: 12, color: "#22d3ee" }}><Spinner size={24}/> Loading report...</div>;
  if (error) return <ErrorBanner message={error}/>;
  if (!data) return null;

  const verdictData = [
    { name: "Malicious", value: data.malicious_count, color: "#ef4444" },
    { name: "Suspicious", value: data.suspicious_count, color: "#f59e0b" },
    { name: "No Threat", value: data.no_threat_count, color: "#4ade80" },
    { name: "Inconclusive", value: data.inconclusive_count, color: "#64748b" },
  ];

  const sevData = Object.entries(data.threat_severity_distribution).map(([k, v]) => ({ name: k, value: v, color: SEV_COLORS[k] ?? "#64748b" }));

  return (
    <div className="animate-fade-in">
      {/* Controls */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", gap: 8 }}>
          {[7, 30, 90].map(d => (
            <button key={d} onClick={() => setDays(d)}
              style={{ padding: "4px 14px", borderRadius: 999, fontSize: "0.8rem", fontWeight: 600, cursor: "pointer", border: "1px solid",
                background: days === d ? "rgba(34,211,238,0.12)" : "transparent",
                borderColor: days === d ? "rgba(34,211,238,0.4)" : "rgba(100,116,139,0.3)",
                color: days === d ? "#22d3ee" : "#64748b" }}>
              {d}d
            </button>
          ))}
        </div>
        <button className="btn-ghost" onClick={exportJSON} style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Download size={15}/> Export JSON
        </button>
      </div>

      {/* Summary stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: "0.75rem", marginBottom: "1.5rem" }}>
        {[
          { label: "Total Scans", value: data.total_scans, color: "#22d3ee" },
          { label: "Malicious", value: data.malicious_count, color: "#ef4444" },
          { label: "Suspicious", value: data.suspicious_count, color: "#f59e0b" },
          { label: "No Threat", value: data.no_threat_count, color: "#4ade80" },
          { label: "Avg Risk Score", value: data.average_risk_score !== null ? data.average_risk_score + "/100" : "N/A", color: "#94a3b8" },
        ].map(s => (
          <div key={s.label} className="cs-card" style={{ textAlign: "center" }}>
            <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>{s.label}</div>
            <div style={{ fontSize: "1.6rem", fontWeight: 800, color: s.color, fontFamily: "JetBrains Mono, monospace" }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem" }}>
        {/* Daily bar chart */}
        <div className="cs-card">
          <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Daily Scan Activity</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={data.daily_activity}>
              <XAxis dataKey="date" tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false}/>
              <YAxis tick={{ fill: "#475569", fontSize: 10 }} axisLine={false} tickLine={false}/>
              <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(34,211,238,0.2)", borderRadius: 8, color: "#e2e8f0", fontSize: 12 }}/>
              <Bar dataKey="count" fill="rgba(34,211,238,0.4)" radius={[3,3,0,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Verdict pie */}
        <div className="cs-card">
          <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Verdict Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={verdictData.filter(d => d.value > 0)} cx="50%" cy="50%" outerRadius={80} innerRadius={40} dataKey="value" strokeWidth={0}>
                {verdictData.filter(d => d.value > 0).map((entry, i) => <Cell key={i} fill={entry.color}/>)}
              </Pie>
              <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(34,211,238,0.2)", borderRadius: 8, color: "#e2e8f0", fontSize: 12 }}/>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center" }}>
            {verdictData.filter(d => d.value > 0).map(d => (
              <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: "0.72rem" }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: d.color }}/>
                <span style={{ color: "#94a3b8" }}>{d.name}: <strong style={{ color: d.color }}>{d.value}</strong></span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top categories */}
      {data.top_categories.length > 0 && (
        <div className="cs-card">
          <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Top Threat Categories</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {data.top_categories.map((cat, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ fontSize: "0.8rem", color: "#94a3b8", width: 120, flexShrink: 0 }}>{cat.category}</div>
                <div style={{ flex: 1, height: 6, background: "rgba(34,211,238,0.08)", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{ height: "100%", background: "rgba(34,211,238,0.6)", borderRadius: 3,
                    width: (cat.count / (data.top_categories[0]?.count || 1) * 100) + "%" }}/>
                </div>
                <span style={{ fontSize: "0.78rem", fontFamily: "monospace", color: "#22d3ee", fontWeight: 600, width: 30, textAlign: "right" }}>{cat.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
