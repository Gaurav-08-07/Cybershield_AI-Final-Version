
import { ShieldQuestion } from 'lucide-react';
interface Props { title: string; subtitle?: string; icon?: React.ReactNode; }
export default function EmptyState({ title, subtitle, icon }: Props) {
  return (
    <div style={{ textAlign: 'center', padding: '3rem 1rem', color: '#475569' }}>
      <div style={{ marginBottom: '1rem', color: '#334155', display: 'flex', justifyContent: 'center' }}>
        {icon || <ShieldQuestion size={48} />}
      </div>
      <div style={{ fontSize: '1rem', fontWeight: 600, color: '#64748b', marginBottom: '0.5rem' }}>{title}</div>
      {subtitle && <div style={{ fontSize: '0.85rem', color: '#475569' }}>{subtitle}</div>}
    </div>
  );
}
