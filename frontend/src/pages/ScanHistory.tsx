import { useEffect, useState } from 'react';
import { Search, Download, ChevronLeft, ChevronRight } from 'lucide-react';
import { scanApi, ScanListItem, PaginatedScans } from '../lib/api';
import { formatDate, truncate } from '../lib/utils';
import VerdictBadge from '../components/VerdictBadge';
import Spinner from '../components/Spinner';
import EmptyState from '../components/EmptyState';
import ErrorBanner from '../components/ErrorBanner';

export default function ScanHistory() {
  const [data, setData] = useState<PaginatedScans | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState('');
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');

  const fetchData = (p: number, v: string, s: string) => {
    setLoading(true);
    scanApi.list({ page: p, per_page: 20, verdict: v || undefined, search: s || undefined })
      .then(res => setData(res.data))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(page, verdict, search); }, [page, verdict, search]);

  const handleSearch = () => { setSearch(searchInput); setPage(1); };
  const handleVerdictFilter = (v: string) => { setVerdict(v); setPage(1); };

  const exportCSV = () => {
    if (!data?.items) return;
    const header = 'id,url,hostname,verdict,risk_score,category,status,created_at';
    const rows = data.items.map(s =>
      [s.id, s.url, s.hostname, s.verdict, s.risk_score ?? '', s.category ?? '', s.scan_status, s.created_at].join(',')
    );
    const csv = [header, ...rows].join('\n');
    const a = document.createElement('a');
    a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
    a.download = 'cybershield_scans.csv';
    a.click();
  };

  return (
    <div className="animate-fade-in">
      <div className="cs-card" style={{ marginBottom: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: 200, display: 'flex', gap: 8 }}>
            <input className="cs-input" placeholder="Search by hostname..."
              value={searchInput} onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch()} style={{ flex: 1 }}/>
            <button className="btn-ghost" onClick={handleSearch}>
              <Search size={15}/>
            </button>
          </div>
          <select className="cs-input" style={{ width: 160 }} value={verdict}
            onChange={e => handleVerdictFilter(e.target.value)}>
            <option value="">All verdicts</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="no_threat">No Threat</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
          <button className="btn-ghost" onClick={exportCSV}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Download size={15}/> Export CSV
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} onClose={() => setError(null)}/>}

      <div className="cs-card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', gap: 12, color: '#22d3ee' }}>
            <Spinner/> Loading...
          </div>
        ) : !data?.items?.length ? (
          <EmptyState title="No scans found" subtitle="Try adjusting your filters or run a new URL scan"/>
        ) : (
          <>
            <table className="cs-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Verdict</th>
                  <th>Risk Score</th>
                  <th>Category</th>
                  <th>Status</th>
                  <th>Scanned At</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map(s => (
                  <tr key={s.id}>
                    <td>
                      <div style={{ fontWeight: 600, fontSize: '0.85rem', color: '#e2e8f0' }}>{s.hostname}</div>
                      <div style={{ fontSize: '0.7rem', color: '#475569', fontFamily: 'monospace' }}>
                        {truncate(s.url, 60)}
                      </div>
                    </td>
                    <td><VerdictBadge verdict={s.verdict} size="sm"/></td>
                    <td>
                      {s.risk_score !== null
                        ? <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 700,
                            color: s.risk_score >= 80 ? '#f87171' : s.risk_score >= 50 ? '#fbbf24' : '#4ade80' }}>
                            {s.risk_score}
                          </span>
                        : <span style={{ color: '#475569' }}>N/A</span>}
                    </td>
                    <td><span style={{ fontSize: '0.75rem', color: '#64748b' }}>{s.category ?? '—'}</span></td>
                    <td>
                      <span style={{ fontSize: '0.72rem',
                        color: s.scan_status === 'completed' ? '#4ade80' : s.scan_status === 'failed' ? '#f87171' : '#fbbf24' }}>
                        {s.scan_status}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: '#475569', whiteSpace: 'nowrap' }}>
                      {formatDate(s.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '0.75rem 1rem', borderTop: '1px solid rgba(34,211,238,0.06)' }}>
              <span style={{ fontSize: '0.78rem', color: '#475569' }}>
                {data.total} total &middot; Page {data.page} of {data.pages}
              </span>
              <div style={{ display: 'flex', gap: 4 }}>
                <button className="btn-ghost" disabled={page <= 1}
                  onClick={() => setPage(p => p - 1)} style={{ padding: '4px 10px' }}>
                  <ChevronLeft size={14}/>
                </button>
                <button className="btn-ghost" disabled={page >= (data.pages || 1)}
                  onClick={() => setPage(p => p + 1)} style={{ padding: '4px 10px' }}>
                  <ChevronRight size={14}/>
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
