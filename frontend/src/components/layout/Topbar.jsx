import {
  Bell,
  ChevronDown,
  CircleHelp,
  Monitor,
  Moon,
  Sun,
} from "lucide-react";
import { getAppMode } from "../../services/api";

const pageLabels = {
  overview: "Overview",
  assets: "Asset inventory",
  audits: "Audit center",
  benchmarks: "Benchmark library",
  findings: "Security findings",
  drift: "Configuration drift",
  reports: "Reports",
  settings: "Settings",
};

const themeOptions = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

export default function Topbar({ activePage, theme, onThemeChange }) {
  return (
    <header className="topbar">
      <div className="topbar-context">
        <span className="context-dot" />
        <span>CISGuard workspace</span>
        <span className="topbar-divider">/</span>
        <strong>{pageLabels[activePage] || "Overview"}</strong>
      </div>

      <div className="topbar-actions">
        <span className="mode-label">
          <span className="mode-dot" />
          {getAppMode()}
        </span>

        <div className="theme-switch" role="group" aria-label="Color theme">
          {themeOptions.map(({ value, label, Icon }) => (
            <button
              key={value}
              type="button"
              className={`theme-option ${theme === value ? "theme-option-active" : ""}`}
              onClick={() => onThemeChange(value)}
              aria-label={`${label} theme`}
              aria-pressed={theme === value}
              title={`${label} theme`}
            >
              <Icon size={15} aria-hidden="true" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        <button className="icon-button" aria-label="Help">
          <CircleHelp size={19} />
        </button>

        <button className="icon-button" aria-label="Notifications">
          <Bell size={19} />
        </button>

        <div className="profile">
          <div className="avatar">CG</div>
          <div className="profile-copy">
            <strong>Security Admin</strong>
            <span>Administrator</span>
          </div>
          <ChevronDown size={15} />
        </div>
      </div>
    </header>
  );
}