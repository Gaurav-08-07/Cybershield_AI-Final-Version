
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import { Outlet, useLocation } from 'react-router-dom';

const titles: Record<string, [string, string]> = {
  '/': ['Dashboard', 'Security overview and live threat metrics'],
  '/scanner': ['URL Scanner', 'Analyze URLs for threats and malicious indicators'],
  '/safebrowse': ['SafeBrowse Protection', 'Chrome extension threat blocking status'],
  '/threats': ['Threat Intelligence', 'Known malicious indicators and threat data'],
  '/logs': ['Log Analyzer', 'Security log parsing and event analysis'],
  '/history': ['Scan History', 'All historical scan records'],
  '/reports': ['Reports', 'Security analytics and summaries'],
  '/settings': ['Settings', 'Platform configuration'],
};

export default function Layout() {
  const { pathname } = useLocation();
  const [title, subtitle] = titles[pathname] || ['CyberShield-AI', ''];
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#020817' }}>
      <Sidebar />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <TopBar title={title} subtitle={subtitle} />
        <main style={{ flex: 1, padding: '1.5rem', overflowY: 'auto' }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
