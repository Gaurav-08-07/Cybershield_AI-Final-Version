import { useEffect, useState } from 'react';
import { healthApi } from '../lib/api';
interface Props { title: string; subtitle?: string; }
export default function TopBar({ title, subtitle }: Props) {
  const [online, setOnline] = useState<boolean | null>(null);
  useEffect(() => {
    healthApi.check().then(() => setOnline(true)).catch(() => setOnline(false));
    const i = setInterval(() => { healthApi.check().then(() => setOnline(true)).catch(() => setOnline(false)); }, 30000);
    return () => clearInterval(i);
  }, []);
  return (
    <header style={{ padding: '1rem 1.5rem', borderBottom: '1px solid rgba(34,211,238,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(10,22,40,0.8)', backdropFilter: 'blur(8px)', position: 'sticky', top: 0, zIndex: 10 }}>
      <div>
        <h1 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: '#e2e8f0' }}>{title}</h1>
        {subtitle && <p style={{ margin: 0, fontSize: '0.78rem', color: '#475569' }}>{subtitle}</p>}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem' }}>
        {online === null ? <span style={{ color: '#475569' }}>Checking...</span>
          : online ? <><div className="animate-pulse-cyan" style={{ width: 7, height: 7, borderRadius: '50%', background: '#4ade80' }}/><span style={{ color: '#4ade80' }}>Backend Online</span></>
          : <><div style={{ width: 7, height: 7, borderRadius: '50%', background: '#ef4444' }}/><span style={{ color: '#ef4444' }}>Backend Offline</span></>}
      </div>
    </header>
  );
}
