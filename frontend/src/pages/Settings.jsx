import { useState } from "react";
import { Server, Clock3, ShieldCheck, Plug, Save } from "lucide-react";
import PageHeader from "../components/layout/PageHeader";
import { getAppMode } from "../services/api";

const settingGroups = [
  {
    title: "Platform coverage",
    description: "Define which collectors and profiles are enabled for your environment.",
    icon: Server,
    detail: "Linux and Windows demo profiles are shown. Network-device collectors are not configured.",
  },
  {
    title: "Audit scheduling",
    description: "Set recurring assessment windows after scheduling is implemented in the backend.",
    icon: Clock3,
    detail: "Scheduling is not connected yet.",
  },
  {
    title: "Access and audit logs",
    description: "Configure user roles and preserve an auditable record of administrative actions.",
    icon: ShieldCheck,
    detail: "Requires backend authentication and persistent audit logging.",
  },
  {
    title: "Integrations",
    description: "Connect the frontend to the rule engine, asset collectors and persistence layer.",
    icon: Plug,
    detail: "API connection status is controlled by the environment configuration.",
  },
];

export default function Settings() {
  const [saved, setSaved] = useState(false);

  return (
    <>
      <PageHeader
        title="Settings"
        description="Configure how CISGuard connects to assessment services and infrastructure."
      />

      <div className="demo-notice">
        <span className="demo-notice-dot" />
        <strong>{getAppMode()}</strong>
        <span>These panels describe planned settings; they do not change backend configuration.</span>
      </div>

      <section className="panel settings-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">WORKSPACE CONFIGURATION</div>
            <h2>Platform and service settings</h2>
            <p>Implementation status for the current prototype.</p>
          </div>
        </div>

        <div className="settings-list">
          {settingGroups.map((group) => {
            const Icon = group.icon;

            return (
              <div className="settings-row" key={group.title}>
                <div className="settings-icon"><Icon size={20} /></div>
                <div className="settings-copy">
                  <strong>{group.title}</strong>
                  <p>{group.description}</p>
                  <span>{group.detail}</span>
                </div>
                <span className="settings-tag">Not connected</span>
              </div>
            );
          })}
        </div>

        <div className="settings-footer">
          <span>Changes to live security controls must be validated server-side.</span>
          <button className="primary-button" onClick={() => setSaved(true)}>
            <Save size={16} /> Acknowledge
          </button>
        </div>

        {saved && (
          <p className="field-hint">
            Acknowledged for this session. No server-side settings were changed.
          </p>
        )}
      </section>
    </>
  );
}