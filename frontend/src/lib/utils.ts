
export function verdictColor(verdict: string): string {
  switch (verdict) {
    case 'malicious': return 'text-red-400';
    case 'suspicious': return 'text-amber-400';
    case 'no_threat': return 'text-green-400';
    default: return 'text-slate-400';
  }
}

export function verdictBg(verdict: string): string {
  switch (verdict) {
    case 'malicious': return 'badge-malicious';
    case 'suspicious': return 'badge-suspicious';
    case 'no_threat': return 'badge-no_threat';
    default: return 'badge-inconclusive';
  }
}

export function verdictLabel(verdict: string): string {
  switch (verdict) {
    case 'malicious': return 'Malicious';
    case 'suspicious': return 'Suspicious';
    case 'no_threat': return 'No Known Threat';
    case 'inconclusive': return 'Inconclusive';
    default: return verdict;
  }
}

export function riskScoreColor(score: number | null): string {
  if (score === null) return '#64748b';
  if (score >= 80) return '#ef4444';
  if (score >= 50) return '#f59e0b';
  if (score >= 20) return '#f59e0b';
  return '#4ade80';
}

export function severityColor(sev: string): string {
  switch (sev?.toLowerCase()) {
    case 'critical': return 'text-red-400';
    case 'high': return 'text-red-400';
    case 'medium': return 'text-amber-400';
    case 'low': return 'text-green-400';
    default: return 'text-slate-400';
  }
}

export function formatDate(iso: string): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function formatDateShort(iso: string): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function truncate(str: string, n: number): string {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '…' : str;
}
