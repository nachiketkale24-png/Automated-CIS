import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, Clock3, ShieldAlert } from "lucide-react";
import MetricCard from "../components/dashboard/MetricCard";
import StatusBadge from "../components/common/StatusBadge";
import DataTable from "../components/common/DataTable";
import PageHeader from "../components/layout/PageHeader";
import { fetchAssets, fetchAuditHistory, fetchAuditFindings, listItems, getAppMode } from "../services/api";

export default function Overview({ onNavigate }) {
  const [assets, setAssets] = useState([]);
  const [audits, setAudits] = useState([]);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const [assetResult, historyResult] = await Promise.all([fetchAssets(), fetchAuditHistory()]);
        const auditItems = listItems(historyResult);
        const recent = auditItems.filter(a => ["COMPLETED", "ERROR"].includes(String(a.status).toUpperCase())).slice(0, 10);
        const findingResults = await Promise.all(recent.map(a => fetchAuditFindings(a.id).catch(() => [])));
        if (active) { setAssets(listItems(assetResult)); setAudits(auditItems); setFindings(findingResults.flat()); }
      } catch (err) { if (active) setError(err.message); }
      finally { if (active) setLoading(false); }
    })();
    return () => { active = false; };
  }, []);

  const latest = [...audits].sort((a,b) => new Date(b.started_at || 0) - new Date(a.started_at || 0))[0];
  const latestFindings = findings;
  const count = status => latestFindings.filter(f => String(f.status).toUpperCase() === status).length;
  const metrics = [
    { label: "Compliance score", value: latest?.score == null ? "—" : `${latest.score}%`, detail: latest ? `Audit #${latest.id}` : "No completed audit", icon: "ShieldCheck", tone: "blue" },
    { label: "Assets discovered", value: assets.length, detail: "From backend inventory", icon: "Server", tone: "violet" },
    { label: "Failed controls", value: count("FAIL"), detail: `Across ${new Set(audits.slice(0,10).map(a => a.id)).size} recent audits`, icon: "ShieldAlert", tone: "orange" },
    { label: "Audit coverage", value: latest?.coverage_pct == null ? "—" : `${latest.coverage_pct}%`, detail: "Most recent run", icon: "Layers3", tone: "green" },
  ];
  const findingRows = latestFindings.filter(f => f.status === "FAIL").slice(0, 5).map(f => ({ id: f.rule_id, title: f.rule_id, asset: "Persisted audit finding", severity: f.severity }));
  const columns = [{key:"id",label:"CONTROL ID"},{key:"title",label:"CONTROL"},{key:"asset",label:"SOURCE"},{key:"severity",label:"SEVERITY",render:v=><StatusBadge status={v}/>}];
  const history = [...audits].sort((a,b)=>new Date(b.started_at || 0)-new Date(a.started_at || 0)).slice(0,5);
  return <>
    <PageHeader title="Security overview" description="Compliance posture and assessment activity from persisted backend data." actionLabel="Open audit center" onAction={()=>onNavigate("audits")}/>
    <div className="demo-notice"><span className="demo-notice-dot"/><strong>{getAppMode()}</strong><span>{loading ? "Loading backend results…" : "Metrics reflect stored audits and findings."}</span></div>
    {error && <div className="info-callout" role="alert">Could not load dashboard data: {error}</div>}
    <section className="metrics-grid">{metrics.map(metric=><MetricCard key={metric.label} metric={metric}/>)}</section>
    <section className="content-grid overview-main-grid">
      <article className="panel coverage-panel"><div className="panel-header"><div><div className="panel-kicker">INVENTORY</div><h2>Asset coverage</h2><p>Assessment status by registered asset</p></div><button className="text-button" onClick={()=>onNavigate("assets")}>View inventory <ArrowRight size={15}/></button></div>
        <div className="coverage-list">{assets.length ? assets.map(asset=>{const done=audits.some(a=>a.asset_id===asset.id);return <div className="coverage-row" key={asset.id}><div className="coverage-platform"><strong>{asset.name}</strong><span>{asset.hostname} · {asset.platform || asset.asset_type}</span></div><div className="coverage-percent"><StatusBadge status={done?"Assessed":"Not assessed"}/></div></div>}) : <p className="empty-state">{loading?"Loading assets…":"No assets registered."}</p>}</div>
      </article>
      <article className="panel posture-panel"><div className="panel-header"><div><div className="panel-kicker">LATEST ASSESSMENT</div><h2>Control outcomes</h2><p>{latest ? `Audit #${latest.id} · ${latest.is_simulated?"Simulated":"Collected"}` : "No audit available"}</p></div></div>
       <div className="posture-breakdown">{["PASS","FAIL","MANUAL","ERROR","NOT_APPLICABLE"].map(s=><div key={s}><span>{s.replace("NOT_APPLICABLE","Not applicable")}</span><strong>{count(s)}</strong></div>)}</div>
      </article>
    </section>
    <section className="content-grid overview-lower-grid"><article className="panel findings-panel"><div className="panel-header"><div><div className="panel-kicker">FAILED CONTROLS</div><h2>Recent findings</h2><p>Findings from the ten most recent completed audits</p></div><button className="text-button" onClick={()=>onNavigate("findings")}>All findings <ArrowRight size={15}/></button></div>{loading?<p>Loading findings…</p>:<DataTable columns={columns} rows={findingRows}/>}</article>
    <article className="panel activity-panel"><div className="panel-header"><div><div className="panel-kicker">LATEST ACTIVITY</div><h2>Audit history</h2></div><Clock3 size={17}/></div><div className="activity-list">{history.map(a=><div className="activity-item" key={a.id}><div className="activity-icon">{a.status==="COMPLETED"?<CheckCircle2 size={18}/>:<ShieldAlert size={18}/>}</div><div className="activity-copy"><strong>Asset #{a.asset_id} · Audit #{a.id}</strong><span>{a.benchmark_version || "Benchmark unavailable"}</span><small>{a.started_at?new Date(a.started_at).toLocaleString():"Date unavailable"}</small></div><StatusBadge status={a.status}/></div>)}{!loading&&!history.length&&<p className="empty-state">No audit history yet.</p>}</div></article></section>
  </>;
}
