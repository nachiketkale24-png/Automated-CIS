import { useEffect, useState } from "react";
import Sidebar from "./components/layout/Sidebar";
import Topbar from "./components/layout/Topbar";

import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import AuditCenter from "./pages/AuditCenter";
import BenchmarkLibrary from "./pages/BenchmarkLibrary";
import Findings from "./pages/Findings";
import ConfigurationDrift from "./pages/ConfigurationDrift";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";

const pages = {
  overview: Overview,
  assets: Assets,
  audits: AuditCenter,
  benchmarks: BenchmarkLibrary,
  findings: Findings,
  drift: ConfigurationDrift,
  reports: Reports,
  settings: Settings,
};

const themeStorageKey = "cisguard-theme";
const themeOptions = ["light", "dark", "system"];

function getSavedTheme() {
  try {
    const savedTheme = window.localStorage.getItem(themeStorageKey);
    return themeOptions.includes(savedTheme) ? savedTheme : "system";
  } catch (error) {
    console.warn("Unable to read the saved theme preference.", error);
    return "system";
  }
}

export default function App() {
  const [activePage, setActivePage] = useState("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [theme, setTheme] = useState(getSavedTheme);
  const [systemPrefersDark, setSystemPrefersDark] = useState(
    () => window.matchMedia("(prefers-color-scheme: dark)").matches,
  );
  const resolvedTheme =
    theme === "system" ? (systemPrefersDark ? "dark" : "light") : theme;

  const CurrentPage = pages[activePage] || Overview;

  useEffect(() => {
    const preference = window.matchMedia("(prefers-color-scheme: dark)");
    const updateSystemTheme = (event) => setSystemPrefersDark(event.matches);

    preference.addEventListener("change", updateSystemTheme);
    return () => preference.removeEventListener("change", updateSystemTheme);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = resolvedTheme;
    document.documentElement.style.colorScheme = resolvedTheme;
  }, [resolvedTheme]);

  function changeTheme(nextTheme) {
    setTheme(nextTheme);

    try {
      window.localStorage.setItem(themeStorageKey, nextTheme);
    } catch (error) {
      console.warn("Unable to save the theme preference.", error);
    }
  }

  return (
    <div className="app-shell">
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed((current) => !current)}
      />

      <div className="app-main">
        <Topbar
          activePage={activePage}
          theme={theme}
          onThemeChange={changeTheme}
        />

        <main className="page-content">
          <CurrentPage onNavigate={setActivePage} />
          <footer className="app-footer">
            <span>CISGuard · Compliance & Hardening Auditor</span>
            <span>Prototype · Illustrative data only</span>
          </footer>
        </main>
      </div>
    </div>
  );
}