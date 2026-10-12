
import { verdictBg, verdictLabel } from '../lib/utils';

interface Props { verdict: string; size?: 'sm' | 'md' }
export default function VerdictBadge({ verdict, size = 'md' }: Props) {
  const cls = verdictBg(verdict);
  const py = size === 'sm' ? '1px 8px' : '3px 12px';
  const fs = size === 'sm' ? '0.7rem' : '0.78rem';
  return (
    <span className={cls} style={{ borderRadius: '999px', padding: py, fontSize: fs, fontWeight: 600, display: 'inline-block', letterSpacing: '0.02em' }}>
      {verdictLabel(verdict)}
    </span>
  );
}
