import { BookOpen, ShieldCheck, Network, Server } from "lucide-react";
import StatusBadge from "../components/common/StatusBadge";
import DataTable from "../components/common/DataTable";
import PageHeader from "../components/layout/PageHeader";

const ruleProfiles = [
  { name:"Linux rule catalog", platform:"Linux", version:"Rules directory", controls:"Loaded by audit engine", coverage:"Implemented", status:"Available" },
  { name:"Cisco / network rule catalog", platform:"Network devices", version:"Rules directory", controls:"Loaded by audit engine", coverage:"Implemented", status:"Available" },
  { name:"Windows benchmark", platform:"Windows", version:"Unavailable", controls:"0 registered", coverage:"No rules", status:"Unavailable" },
];

export default function BenchmarkLibrary() {
 const columns=[{key:"name",label:"RULE PROFILE"},{key:"platform",label:"PLATFORM"},{key:"version",label:"VERSION"},{key:"controls",label:"CONTROLS"},{key:"coverage",label:"IMPLEMENTATION"},{key:"status",label:"STATUS",render:v=><StatusBadge status={v}/>}];
 return <><PageHeader title="Benchmark library" description="Implemented rule catalogs available to the current audit engine."/><div className="demo-notice"><span className="demo-notice-dot"/><strong>Backend rule coverage</strong><span>These are implementation summaries; the project does not expose a benchmark catalogue API or claim official CIS certification.</span></div>
 <div className="feature-card-grid"><article className="feature-card"><Server size={20}/><span>Operating systems</span><strong>Linux</strong><p>Linux rules are present. Live collection is supported on Linux.</p></article><article className="feature-card"><Network size={20}/><span>Network infrastructure</span><strong>Cisco fixture rules</strong><p>Fixtures are simulated and use the network rule catalog.</p></article><article className="feature-card"><ShieldCheck size={20}/><span>Control traceability</span><strong>Persisted findings</strong><p>Audit controls include expected/actual values and evidence where available.</p></article></div>
 <section className="panel table-panel section-spaced"><div className="panel-header"><div><div className="panel-kicker">AVAILABLE RULE SETS</div><h2>Implemented coverage</h2></div><BookOpen size={21} className="muted-icon"/></div><DataTable columns={columns} rows={ruleProfiles}/></section></>;
}
