import { useEffect, useState } from "react";
import { Download, FileBarChart, FileText, ShieldCheck } from "lucide-react";
import PageHeader from "../components/layout/PageHeader";
import { fetchAuditHistory, fetchAudit, fetchAuditFindings, listItems, getAppMode } from "../services/api";

export default function Reports() {
  const [audits, setAudits] = useState([]);
  const [auditId, setAuditId] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => { let active=true; fetchAuditHistory().then(data=>{if(!active)return;const items=listItems(data);setAudits(items);if(items.length)setAuditId(String(items[0].id));}).catch(e=>active&&setError(e.message)).finally(()=>active&&setLoading(false)); return()=>{active=false;}; },[]);

  async function downloadJson() {
    if (!auditId) return;
    setError(""); setMessage("");
    try {
      const [audit, findings] = await Promise.all([fetchAudit(auditId), fetchAuditFindings(auditId)]);
      const report = { audit, findings };
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob); const link = document.createElement("a");
      link.href=url; link.download=`cisguard-audit-${auditId}.json`; link.click(); URL.revokeObjectURL(url);
      setMessage(`Downloaded persisted audit #${auditId} and its findings as JSON.`);
    } catch (e) { setError(e.message || "Could not create the JSON export."); }
  }

  return <>
    <PageHeader title="Reports" description="Export a selected persisted audit and its control level evidence."/>
    <div className="demo-notice"><span className="demo-notice-dot"/><strong>{getAppMode()}</strong><span>The backend has no PDF/CSV/report endpoints. JSON export uses the selected audit detail and findings APIs.</span></div>
    <section className="panel report-history">
      <div className="panel-header"><div><div className="panel-kicker">AUDIT EXPORT</div><h2>Selected audit</h2><p>Only persisted backend content is included.</p></div></div>
      <label className="field-label">Audit run<select value={auditId} onChange={e=>setAuditId(e.target.value)} disabled={loading||!audits.length}><option value="">{loading?"Loading…":"No audits available"}</option>{audits.map(a=><option key={a.id} value={a.id}>Audit #{a.id} · Asset #{a.asset_id} · {a.status}</option>)}</select></label>
      <button className="secondary-button" onClick={downloadJson} disabled={!auditId}><Download size={16}/> Download audit JSON</button>
      {error&&<p role="alert" className="field-hint">{error}</p>}{message&&<p role="status" className="field-hint">{message}</p>}
    </section>
    <div className="feature-card-grid section-spaced">
      <article className="feature-card"><ShieldCheck size={20}/><strong>PDF</strong><p>Not implemented by backend.</p></article>
      <article className="feature-card"><FileText size={20}/><strong>CSV</strong><p>Not implemented by backend.</p></article>
      <article className="feature-card"><FileBarChart size={20}/><strong>JSON</strong><p>Generated from persisted audit detail and findings.</p></article>
    </div>
  </>;
}
