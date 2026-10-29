import {
  LayoutDashboard,
  Server,
  ClipboardCheck,
  BookOpen,
  ShieldAlert,
  GitCompare,
  FileBarChart,
  Settings2,
  ShieldCheck,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import { navigationItems } from "../../data/demoData";

const icons = {
  LayoutDashboard,
  Server,
  ClipboardCheck,
  BookOpen,
  ShieldAlert,
  GitCompare,
  FileBarChart,
  Settings2,
};

export default function Sidebar({ activePage, onNavigate, collapsed, onToggle }) {
  return (
    <aside className={`sidebar ${collapsed ? "sidebar-collapsed" : ""}`}>
      <div className="brand">
        <div className="brand-mark">
          <ShieldCheck size={23} strokeWidth={2.3} />
        </div>

        {!collapsed && (
          <div className="brand-copy">
            <span className="brand-name">CISGuard</span>
            <span className="brand-caption">COMPLIANCE PLATFORM</span>
          </div>
        )}
      </div>

      <div className="nav-section-label">
        {!collapsed && "WORKSPACE"}
      </div>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {navigationItems.map((item) => {
          const Icon = icons[item.icon];

          return (
            <button
              key={item.id}
              className={`nav-item ${
                activePage === item.id ? "nav-item-active" : ""
              }`}
              onClick={() => onNavigate(item.id)}
              title={collapsed ? item.label : undefined}
              aria-current={activePage === item.id ? "page" : undefined}
            >
              <Icon size={19} strokeWidth={1.9} />
              {!collapsed && <span>{item.label}</span>}
              {item.id === "findings" && !collapsed && (
                <span className="nav-count">21</span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="sidebar-bottom">
        {!collapsed && (
          <div className="sidebar-help">
            <div className="help-icon">
              <ShieldCheck size={18} />
            </div>
            <strong>Security posture</strong>
            <p>Review coverage before relying on compliance scores.</p>
          </div>
        )}

        <button
          className="collapse-button"
          onClick={onToggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-expanded={!collapsed}
          title={collapsed ? "Expand sidebar" : undefined}
        >
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
          {!collapsed && <span>Collapse sidebar</span>}
        </button>

        <div className="sidebar-version">
          {!collapsed && "CISGuard · Preview"}
        </div>
      </div>
    </aside>
  );
}