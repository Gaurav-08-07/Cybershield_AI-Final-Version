
import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, Activity, Database, Eye, Zap } from 'lucide-react';
import { AreaChart, Area, PieChart, Pie, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import StatCard from '../components/StatCard';
import Spinner from '../components/Spinner';
import { scanApi, DashboardStats, reportApi, ReportSummary } from '../lib/api';
import { formatDate } from '../lib/utils';

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [report, setReport] = useState<ReportSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([scanApi.dashboard(), reportApi.summary(7)])
      .then(([s, r]) => { setStats(s.data); setReport(r.data); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 300, gap: 12, color: "#22d3ee" }}>
      <Spinner size={28} /><span>Loading dashboard...</span>
    </div>
  );

  if (error) return (
    <div style={{ textAlign: "center", padding: "3rem", color: "#f87171" }}>
      <AlertTriangle size={40} style={{ marginBottom: "1rem" }} />
      <div style={{ marginBottom: 8 }}>{error}</div>
      <div style={{ fontSize: "0.8rem", color: "#475569" }}>Ensure the backend is running on port 8000</div>
    </div>
  );

  const pieData = stats ? [
    { name: "Malicious", value: stats.malicious_count, color: "#ef4444" },
    { name: "Suspicious", value: stats.suspicious_count, color: "#f59e0b" },
    { name: "No Threat", value: stats.no_threat_count, color: "#4ade80" },
    { name: "Inconclusive", value: stats.inconclusive_count, color: "#64748b" },
  ].filter(d => d.value > 0) : [];

  const activityData = report?.daily_activity || [];

  return (
    <div className="animate-fade-in">
      <div className="dashboard-grid" style={{ marginBottom: "1.5rem" }}>
        <StatCard label="Total Scans" value={stats?.total_scans ?? 0} icon={<Activity size={18}/>} color="cyan" sublabel="All time" />
        <StatCard label="Malicious" value={stats?.malicious_count ?? 0} icon={<AlertTriangle size={18}/>} color="red" sublabel="Confirmed threats" />
        <StatCard label="Suspicious" value={stats?.suspicious_count ?? 0} icon={<Eye size={18}/>} color="amber" sublabel="Needs review" />
        <StatCard label="Active Threats" value={stats?.active_threats ?? 0} icon={<Zap size={18}/>} color="red" sublabel="In indicator DB" />
        <StatCard label="Database" value={stats?.db_healthy ? "Healthy" : "Degraded"} icon={<Database size={18}/>} color={stats?.db_healthy ? "green" : "red"} sublabel="Storage layer" />
        <StatCard label="Inconclusive" value={stats?.inconclusive_count ?? 0} icon={<Shield size={18}/>} color="slate" sublabel="Insufficient data" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: "1rem", marginBottom: "1.5rem" }}>
        <div className="cs-card">
          <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Scan Activity — Last 7 Days</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={activityData}>
              <defs>
                <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#22d3ee" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fill: "#475569", fontSize: 11 }} axisLine={false} tickLine={false}/>
              <YAxis tick={{ fill: "#475569", fontSize: 11 }} axisLine={false} tickLine={false}/>
              <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(34,211,238,0.2)", borderRadius: 8, color: "#e2e8f0", fontSize: 12 }}/>
              <Area type="monotone" dataKey="count" stroke="#22d3ee" fill="url(#cyanGrad)" strokeWidth={2} dot={{ fill: "#22d3ee", strokeWidth: 0, r: 3 }}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="cs-card">
          <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "0.75rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Verdict Distribution</div>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" outerRadius={60} innerRadius={35} dataKey="value" strokeWidth={0}>
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color}/>)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(34,211,238,0.2)", borderRadius: 8, color: "#e2e8f0", fontSize: 12 }}/>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {pieData.map(d => (
                  <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "0.75rem" }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: d.color }}/>
                    <span style={{ color: "#94a3b8", flex: 1 }}>{d.name}</span>
                    <span style={{ color: d.color, fontWeight: 600 }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div style={{ textAlign: "center", color: "#475569", padding: "2rem 0", fontSize: "0.85rem" }}>No scan data yet</div>
          )}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "0.75rem" }}>
        {[
          { label: "Backend API", status: true, detail: "v" + (stats?.backend_version ?? "?") },
          { label: "Database", status: stats?.db_healthy, detail: "SQLite / PostgreSQL" },
          { label: "URLhaus Feed", status: true, detail: "Free · No API key" },
          { label: "VirusTotal", status: false, detail: "Set VIRUSTOTAL_API_KEY" },
        ].map(s => (
          <div key={s.label} className="cs-card" style={{ padding: "0.75rem 1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: s.status ? "#4ade80" : "#475569" }}/>
              <span style={{ fontSize: "0.8rem", fontWeight: 600, color: s.status ? "#e2e8f0" : "#64748b" }}>{s.label}</span>
            </div>
            <div style={{ fontSize: "0.72rem", color: "#475569", marginTop: 4, paddingLeft: 16 }}>{s.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
