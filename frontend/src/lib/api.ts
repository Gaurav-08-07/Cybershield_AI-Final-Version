
import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 35000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.response.use(
  r => r,
  err => {
    const msg = err.response?.data?.detail || err.message || 'Network error';
    return Promise.reject(new Error(msg));
  }
);
export default api;

export interface ScanResult {
  id: string; url: string; hostname: string; verdict: string;
  risk_score: number | null; confidence: number | null; scan_status: string;
  provider_status: string | null; error_message: string | null;
  category: string | null; created_at: string; completed_at: string | null;
  evidence: Evidence[];
}
export interface Evidence { id: string; source: string; evidence_type: string; detail: string | null; severity: string | null; created_at: string; }
export interface ScanListItem { id: string; url: string; hostname: string; verdict: string; risk_score: number | null; category: string | null; scan_status: string; created_at: string; }
export interface PaginatedScans { items: ScanListItem[]; total: number; page: number; per_page: number; pages: number; }
export interface ThreatIndicator { id: string; indicator: string; indicator_type: string; verdict: string; severity: string; category: string | null; source: string; confidence: number; first_seen: string; last_seen: string; active: boolean; }
export interface DashboardStats { total_scans: number; malicious_count: number; suspicious_count: number; inconclusive_count: number; no_threat_count: number; active_threats: number; recent_events: SecurityEvent[]; db_healthy: boolean; backend_version: string; }
export interface SecurityEvent { id: string; event_type: string; severity: string; source: string | null; description: string; created_at: string; acknowledged: boolean; }
export interface LogJob { id: string; filename: string | null; status: string; total_entries: number | null; processed_entries: number; critical_count: number; high_count: number; medium_count: number; low_count: number; summary_json: string | null; error_message: string | null; created_at: string; completed_at: string | null; }
export interface ReportSummary { total_scans: number; malicious_count: number; suspicious_count: number; no_threat_count: number; inconclusive_count: number; top_categories: { category: string; count: number }[]; daily_activity: { date: string; count: number }[]; threat_severity_distribution: Record<string, number>; average_risk_score: number | null; period_days: number; }

export const scanApi = {
  create: (url: string) => api.post<ScanResult>('/scans', { url }),
  list: (params?: Record<string, any>) => api.get<PaginatedScans>('/scans', { params }),
  get: (id: string) => api.get<ScanResult>("/scans/" + id),
  dashboard: () => api.get<DashboardStats>('/dashboard/stats'),
};
export const threatApi = {
  list: (params?: Record<string, any>) => api.get<{ items: ThreatIndicator[]; total: number; page: number; per_page: number; pages: number }>('/threats', { params }),
};
export const logApi = {
  analyze: (content: string, filename?: string) => api.post<LogJob>('/logs/analyze', { content, filename }),
  list: () => api.get<LogJob[]>('/logs'),
  get: (id: string) => api.get<LogJob>("/logs/" + id),
};
export const reportApi = {
  summary: (days?: number) => api.get<ReportSummary>('/reports/summary', { params: { days } }),
};
export const healthApi = {
  check: () => api.get('/health'),
  extensionStatus: () => api.get('/extension/status'),
};
