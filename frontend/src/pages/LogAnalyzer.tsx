
import { useState, useRef, useEffect } from "react";
import { Upload, FileText, AlertTriangle, Activity, ChevronDown, ChevronRight } from "lucide-react";
import { logApi, LogJob } from "../lib/api";
import Spinner from "../components/Spinner";
import ErrorBanner from "../components/ErrorBanner";
import EmptyState from "../components/EmptyState";
import { formatDate } from "../lib/utils";

const SEVERITY_COLORS: Record<string, string> = { critical: "#f87171", high: "#f87171", medium: "#fbbf24", low: "#4ade80", info: "#64748b" };

function JobCard({ job }: { job: LogJob }) {
  const [open, setOpen] = useState(false);
  const summary = job.summary_json ? JSON.parse(job.summary_json) : null;

  return (
    <div className="cs-card" style={{ marginBottom: "0.75rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer" }} onClick={() => setOpen(o => !o)}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <FileText size={16} color="#64748b"/>
          <div>
            <div style={{ fontWeight: 600, fontSize: "0.85rem", color: "#e2e8f0" }}>{job.filename ?? "Unnamed Log"}</div>
            <div style={{ fontSize: "0.72rem", color: "#475569" }}>{formatDate(job.created_at)}</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", gap: 12, fontSize: "0.78rem" }}>
            <span style={{ color: "#f87171" }}>Critical: {job.critical_count}</span>
            <span style={{ color: "#f87171" }}>High: {job.high_count}</span>
            <span style={{ color: "#fbbf24" }}>Med: {job.medium_count}</span>
            <span style={{ color: "#4ade80" }}>Low: {job.low_count}</span>
          </div>
          <span style={{ fontSize: "0.72rem", color: job.status === "completed" ? "#4ade80" : job.status === "failed" ? "#f87171" : "#fbbf24" }}>{job.status}</span>
          {open ? <ChevronDown size={14} color="#64748b"/> : <ChevronRight size={14} color="#64748b"/>}
        </div>
      </div>
      {open && summary && (
        <div style={{ marginTop: "1rem", paddingTop: "1rem", borderTop: "1px solid rgba(34,211,238,0.06)" }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: "0.75rem", marginBottom: "1rem" }}>
            <div className="cs-card" style={{ padding: "0.75rem", background: "rgba(10,22,40,0.5)" }}>
              <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 4 }}>Total Entries</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "#22d3ee", fontFamily: "monospace" }}>{job.total_entries ?? 0}</div>
            </div>
            {summary.data_structure_stats && Object.entries(summary.data_structure_stats).map(([k, v]) => (
              <div key={k} className="cs-card" style={{ padding: "0.75rem", background: "rgba(10,22,40,0.5)" }}>
                <div style={{ fontSize: "0.72rem", color: "#64748b", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>{k.replace(/_/g, " ")}</div>
                <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#94a3b8", fontFamily: "monospace" }}>{String(v)}</div>
              </div>
            ))}
          </div>
          {summary.brute_force_ips && Object.keys(summary.brute_force_ips).length > 0 && (
            <div style={{ background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 6, padding: "0.75rem", marginBottom: "0.75rem" }}>
              <div style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f87171", marginBottom: 6 }}><AlertTriangle size={14} style={{ verticalAlign: "middle", marginRight: 6 }}/>Brute Force IPs Detected</div>
              {Object.entries(summary.brute_force_ips).map(([ip, count]) => (
                <div key={ip} style={{ fontSize: "0.8rem", color: "#fca5a5", fontFamily: "monospace" }}>{ip}: {String(count)} failed attempts</div>
              ))}
            </div>
          )}
          {summary.flag_counts && Object.keys(summary.flag_counts).length > 0 && (
            <div>
              <div style={{ fontSize: "0.78rem", fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Detected Threat Flags</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {Object.entries(summary.flag_counts).map(([flag, count]) => (
                  <span key={flag} style={{ background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.3)", color: "#fbbf24", fontSize: "0.72rem", padding: "2px 10px", borderRadius: 999 }}>
                    {flag.replace(/_/g, " ")} ({String(count)})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function LogAnalyzer() {
  const [logContent, setLogContent] = useState("");
  const [filename, setFilename] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [jobs, setJobs] = useState<LogJob[]>([]);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    logApi.list().then(res => setJobs(res.data)).catch(() => {});
  }, []);

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    const reader = new FileReader();
    reader.onload = ev => setLogContent(ev.target?.result as string ?? "");
    reader.readAsText(file);
  };

  const handleAnalyze = async () => {
    if (!logContent.trim()) return;
    setAnalyzing(true);
    setError(null);
    try {
      const res = await logApi.analyze(logContent, filename || undefined);
      setJobs(prev => [res.data, ...prev]);
      setLogContent("");
      setFilename("");
    } catch(e: any) {
      setError(e.message);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="animate-fade-in">
      {/* Upload / paste area */}
      <div className="cs-card" style={{ marginBottom: "1.5rem" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "1rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>
          Analyze Security Logs
        </div>
        <div style={{ display: "flex", gap: "0.75rem", marginBottom: "0.75rem" }}>
          <button className="btn-ghost" onClick={() => fileRef.current?.click()} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <Upload size={14}/> Upload Log File
          </button>
          <input ref={fileRef} type="file" accept=".log,.txt,.json" style={{ display: "none" }} onChange={handleFile}/>
          {filename && <span style={{ fontSize: "0.78rem", color: "#64748b", alignSelf: "center" }}>{filename}</span>}
        </div>
        <textarea
          className="cs-input"
          style={{ height: 160, resize: "vertical", fontFamily: "JetBrains Mono, monospace", fontSize: "0.78rem" }}
          placeholder="Or paste log content here (plain text, JSON lines, syslog format)...IMPORTANT: Do not paste sensitive credentials or personal data.Log content is analyzed server-side and stored temporarily."
          value={logContent}
          onChange={e => setLogContent(e.target.value)}
        />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "0.75rem" }}>
          <div style={{ fontSize: "0.72rem", color: "#334155" }}>
            Supports: plain text logs, syslog, JSON Lines. Max 5MB. Log content is never executed.
          </div>
          <button className="btn-primary" onClick={handleAnalyze} disabled={analyzing || !logContent.trim()}>
            {analyzing ? <><Spinner size={14}/>Analyzing...</> : <><Activity size={16}/>Analyze Logs</>}
          </button>
        </div>
        {error && <ErrorBanner message={error} onClose={() => setError(null)} />}
      </div>

      {/* Data structure explainer */}
      <div className="cs-card" style={{ marginBottom: "1.5rem", background: "rgba(8,20,40,0.5)" }}>
        <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", marginBottom: "0.75rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>Analysis Engine — Data Structures</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: "0.75rem" }}>
          {[
            { name: "Event Queue", desc: "FIFO processing — O(1) enqueue/dequeue", color: "#22d3ee" },
            { name: "Hash Table", desc: "O(1) event lookup by ID", color: "#4ade80" },
            { name: "BST Index", desc: "Ordered by timestamp — O(log n) range query", color: "#f59e0b" },
            { name: "Op Stack", desc: "Recent operations history — O(1) push/pop", color: "#94a3b8" },
          ].map(ds => (
            <div key={ds.name} style={{ background: "rgba(10,22,40,0.6)", borderRadius: 6, padding: "0.75rem", border: "1px solid rgba(34,211,238,0.06)" }}>
              <div style={{ fontSize: "0.78rem", fontWeight: 700, color: ds.color, marginBottom: 4 }}>{ds.name}</div>
              <div style={{ fontSize: "0.72rem", color: "#475569" }}>{ds.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Job history */}
      <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.75rem" }}>
        Analysis Jobs ({jobs.length})
      </div>
      {jobs.length === 0 ? (
        <EmptyState title="No analysis jobs yet" subtitle="Upload a log file or paste log content above to begin"/>
      ) : (
        jobs.map(job => <JobCard key={job.id} job={job}/>)
      )}
    </div>
  );
}
