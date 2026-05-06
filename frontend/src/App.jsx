import { NavLink, Route, Routes } from "react-router-dom";
import { useMemo } from "react";
import DashboardPage from "./pages/DashboardPage";
import DetectionPage from "./pages/DetectionPage";
import LogsPage from "./pages/LogsPage";
import MonitoringPage from "./pages/MonitoringPage";
import ModelPage from "./pages/ModelPage";
import SettingsPage from "./pages/SettingsPage";
import OnboardingPage from "./pages/OnboardingPage";
import SitesPage from "./pages/SitesPage";

const links = [
  { to: "/", label: "Dashboard" },
  { to: "/detection", label: "Detection" },
  { to: "/logs", label: "Logs & Alerts" },
  { to: "/monitoring", label: "Monitoring" },
  { to: "/onboarding", label: "Website Onboarding" },
  { to: "/sites", label: "Connected Sites" },
  { to: "/model", label: "Model Management" },
  { to: "/settings", label: "Settings" }
];

export default function App() {
  const lastUpdated = useMemo(() => new Date().toLocaleString(), []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">ASTRA AI</div>
        <nav className="nav">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <h1>Cybersecurity Control Center</h1>
            <p>Autonomous threat monitoring and response</p>
          </div>
          <div className="topbar-meta">
            <span className="muted">Last session start</span>
            <strong>{lastUpdated}</strong>
          </div>
        </header>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/detection" element={<DetectionPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/monitoring" element={<MonitoringPage />} />
          <Route path="/onboarding" element={<OnboardingPage />} />
          <Route path="/sites" element={<SitesPage />} />
          <Route path="/model" element={<ModelPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  );
}
