
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Search, Shield, Eye, FileText, Clock, BarChart3, Settings, Zap } from 'lucide-react';

const links = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scanner', icon: Search, label: 'URL Scanner' },
  { to: '/safebrowse', icon: Shield, label: 'SafeBrowse' },
  { to: '/threats', icon: Eye, label: 'Threat Intelligence' },
  { to: '/logs', icon: FileText, label: 'Log Analyzer' },
  { to: '/history', icon: Clock, label: 'Scan History' },
  { to: '/reports', icon: BarChart3, label: 'Reports' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  return (
    <aside style={{
      width: 220, flexShrink: 0, height: '100vh', position: 'sticky', top: 0,
      background: 'rgba(10,22,40,0.95)', borderRight: '1px solid rgba(34,211,238,0.08)',
      display: 'flex', flexDirection: 'column', padding: '1.25rem 0.75rem', overflowY: 'auto'
    }}>
      {/* Logo */}
      <div style={{ padding: '0 0.5rem 1.5rem', borderBottom: '1px solid rgba(34,211,238,0.08)', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div style={{ width: 32, height: 32, borderRadius: '0.5rem', background: 'linear-gradient(135deg, #0891b2, #22d3ee)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Zap size={18} color="#020817" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '0.9rem', color: '#e2e8f0', lineHeight: 1.1 }}>CyberShield</div>
            <div style={{ fontSize: '0.65rem', color: '#22d3ee', letterSpacing: '0.1em', fontWeight: 600 }}>AI PLATFORM</div>
          </div>
        </div>
      </div>

      {/* Nav links */}
      <nav style={{ flex: 1 }}>
        {links.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => 'sidebar-link' + (isActive ? ' active' : '')}>
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{ borderTop: '1px solid rgba(34,211,238,0.08)', paddingTop: '1rem', marginTop: '0.5rem' }}>
        <div style={{ fontSize: '0.68rem', color: '#334155', textAlign: 'center' }}>
          CyberShield-AI v1.0.0
        </div>
      </div>
    </aside>
  );
}
