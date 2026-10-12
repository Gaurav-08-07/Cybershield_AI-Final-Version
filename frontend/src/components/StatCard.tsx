
interface Props {
  label: string; value: string | number;
  icon: React.ReactNode; color: 'cyan' | 'red' | 'amber' | 'green' | 'slate';
  sublabel?: string;
}
const colorMap = {
  cyan: { bg: 'rgba(34,211,238,0.08)', icon: '#22d3ee', border: 'rgba(34,211,238,0.15)' },
  red: { bg: 'rgba(239,68,68,0.08)', icon: '#f87171', border: 'rgba(239,68,68,0.2)' },
  amber: { bg: 'rgba(251,191,36,0.08)', icon: '#fbbf24', border: 'rgba(251,191,36,0.2)' },
  green: { bg: 'rgba(74,222,128,0.08)', icon: '#4ade80', border: 'rgba(74,222,128,0.2)' },
  slate: { bg: 'rgba(148,163,184,0.06)', icon: '#94a3b8', border: 'rgba(148,163,184,0.15)' },
};
export default function StatCard({ label, value, icon, color, sublabel }: Props) {
  const c = colorMap[color];
  return (
    <div className="cs-card animate-fade-in" style={{ borderColor: c.border }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <span style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>{label}</span>
        <div style={{ width: 36, height: 36, borderRadius: '0.5rem', background: c.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: c.icon }}>
          {icon}
        </div>
      </div>
      <div style={{ fontSize: '1.75rem', fontWeight: 800, color: c.icon, fontFamily: 'JetBrains Mono, monospace' }}>{value}</div>
      {sublabel && <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.25rem' }}>{sublabel}</div>}
    </div>
  );
}
