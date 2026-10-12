
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import UrlScanner from "./pages/UrlScanner";
import SafeBrowse from "./pages/SafeBrowse";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import LogAnalyzer from "./pages/LogAnalyzer";
import ScanHistory from "./pages/ScanHistory";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout/>}>
          <Route index element={<Dashboard/>}/>
          <Route path="scanner" element={<UrlScanner/>}/>
          <Route path="safebrowse" element={<SafeBrowse/>}/>
          <Route path="threats" element={<ThreatIntelligence/>}/>
          <Route path="logs" element={<LogAnalyzer/>}/>
          <Route path="history" element={<ScanHistory/>}/>
          <Route path="reports" element={<Reports/>}/>
          <Route path="settings" element={<Settings/>}/>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
