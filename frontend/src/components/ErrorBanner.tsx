
import { AlertTriangle, X } from 'lucide-react';
interface Props { message: string; onClose?: () => void; }
export default function ErrorBanner({ message, onClose }: Props) {
  return (
    <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '0.5rem', padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', gap: '0.75rem', color: '#f87171', marginBottom: '1rem' }}>
      <AlertTriangle size={16} />
      <span style={{ flex: 1, fontSize: '0.875rem' }}>{message}</span>
      {onClose && <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', display: 'flex' }}><X size={14} /></button>}
    </div>
  );
}
