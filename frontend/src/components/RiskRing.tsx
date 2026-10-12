
import { riskScoreColor } from '../lib/utils';

interface Props { score: number | null; size?: number; }

export default function RiskRing({ score, size = 80 }: Props) {
  const r = (size / 2) - 8;
  const circ = 2 * Math.PI * r;
  const pct = score !== null ? score / 100 : 0;
  const offset = circ - pct * circ;
  const color = riskScoreColor(score);

  return (
    <div style={{ width: size, height: size, position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="rgba(34,211,238,0.08)" strokeWidth={6} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color}
          strokeWidth={6} strokeLinecap="round" strokeDasharray={circ}
          strokeDashoffset={score !== null ? offset : circ}
          className="risk-ring" />
      </svg>
      <div style={{ textAlign: 'center', zIndex: 1 }}>
        {score !== null ? (
          <><div style={{ fontSize: size > 70 ? 18 : 13, fontWeight: 700, color, fontFamily: 'JetBrains Mono, monospace' }}>{score}</div>
          <div style={{ fontSize: 9, color: '#64748b', marginTop: -2 }}>RISK</div></>
        ) : (
          <div style={{ fontSize: 10, color: '#64748b' }}>N/A</div>
        )}
      </div>
    </div>
  );
}
