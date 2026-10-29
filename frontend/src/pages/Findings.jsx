
import { useEffect, useMemo, useState } from "react";
import { Search, ShieldAlert, ChevronDown, ChevronRight, RefreshCw, GitCompare, Sparkles } from "lucide-react";
import StatusBadge from "../components/common/StatusBadge";
import DataTable from "../components/common/DataTable";
import PageHeader from "../components/layout/PageHeader";
import {
  fetchAssets,
  fetchAuditHistory,
  fetchAuditFindings,
  fetchAudit,
  fetchDrift,
  fetchAuditCorrelations,
  getAppMode,
  listItems,
} from "../services/api";

export default function Findings() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const [statusFilter, setStatusFilter] = useState("All statuses");
  const [assetFilter, setAssetFilter] = useState("All assets");
  const [assets, setAssets] = useState([]);
  const [audits, setAudits] = useState([]);
  const [selectedAuditId, setSelectedAuditId] = useState("");
  const [findings, setFindings] = useState([]);
  const [auditDetail, setAuditDetail] = useState(null);
  const [drift, setDrift] = useState(null);
  const [correlations, setCorrelations] = useState([]);
  const [correlationsLoading, setCorrelationsLoading] = useState(false);
  const [correlationsError, setCorrelationsError] = useState("");
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    async function loadInitialData() {
      setLoading(true);
      setError("");

      try {
        const [assetData, auditData] = await Promise.all([
          fetchAssets(),
          fetchAuditHistory(),
        ]);

        const assetList = listItems(assetData);
        const auditList = listItems(auditData)
          .filter((audit) => ["COMPLETED", "ERROR"].includes(String(audit.status || "").toUpperCase()))
          .sort((a, b) => {
            const dateA = new Date(
              a.started_at || a.created_at || 0
            ).getTime();
            const dateB = new Date(
              b.started_at || b.created_at || 0
            ).getTime();

            return dateB - dateA || (b.id || 0) - (a.id || 0);
          });

        setAssets(assetList);
        setAudits(auditList);

        if (auditList.length > 0) {
          setSelectedAuditId(String(auditList[0].id));
        }
      } catch (err) {
        setError(err.message || "Unable to load audit history.");
        setLoading(false);
      }
    }

    loadInitialData();
  }, []);

  useEffect(() => {
    if (!selectedAuditId) {
      return;
    }

    let cancelled = false;

    async function loadSelectedAuditData() {
      setLoading(true);
      setError("");
      setFindings([]);
      setAuditDetail(null);
      setDrift(null);
      setCorrelations([]);
      setCorrelationsError("");
      setCorrelationsLoading(true);
      setExpandedId(null);

      try {
        const [detail, findingData, driftResult, correlationData] = await Promise.all([
          fetchAudit(selectedAuditId),
          fetchAuditFindings(selectedAuditId),
          fetchDrift(selectedAuditId).catch((err) => ({ _error: err.message || "Drift data is unavailable for this audit." })),
          fetchAuditCorrelations(selectedAuditId),
        ]);
        const items = Array.isArray(findingData) ? findingData : findingData?.items || [];
        const correlationItems = Array.isArray(correlationData) ? correlationData : null;

        if (!cancelled) {
          setAuditDetail(detail);
          setDrift(driftResult);
          setCorrelations(correlationItems || []);
          if (!correlationItems) setCorrelationsError("The API returned an unexpected correlation response.");
          setFindings(
            items.map((item) => ({
              ...item,
              audit_id: Number(selectedAuditId),
            }))
          );
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "Unable to load findings.");
          setCorrelationsError(err.message || "Unable to load exposure correlations.");
        }
      } finally {
        if (!cancelled) { setLoading(false); setCorrelationsLoading(false); }
      }
    }

    loadSelectedAuditData();

    return () => {
      cancelled = true;
    };
  }, [selectedAuditId, reloadToken]);

  const retryCorrelations = async () => {
    if (!selectedAuditId) return;
    const requestAuditId = selectedAuditId;
    setCorrelationsLoading(true);
    setCorrelationsError("");
    try {
      const data = await fetchAuditCorrelations(selectedAuditId);
      if (!Array.isArray(data)) throw new Error("The API returned an unexpected correlation response.");
      if (requestAuditId === selectedAuditId) setCorrelations(data);
    } catch (err) { if (requestAuditId === selectedAuditId) setCorrelationsError(err.message || "Unable to load exposure correlations."); }
    finally { if (requestAuditId === selectedAuditId) setCorrelationsLoading(false); }
  };

  const rows = useMemo(() => {
    return findings.map((item) => {
      const audit = audits.find(
        (candidate) => String(candidate.id) === String(item.audit_id)
      );

      const assetId = item.asset_id ?? audit?.asset_id;
      const asset = assets.find(
        (candidate) => String(candidate.id) === String(assetId)
      );

      return {
        ...item,
        id: String(item.rule_id ?? item.control_id ?? item.id),
        title:
          item.title ||
          item.rule_title ||
          item.description ||
          item.rule_id ||
          "Untitled control",
        asset:
          item.asset_name ||
          asset?.name ||
          `Asset #${assetId ?? "â€”"}`,
        asset_id: assetId,
        platform: asset?.platform || asset?.asset_type || "Unknown",
        benchmark:
          item.benchmark_version ||
          audit?.benchmark_version ||
          "CIS benchmark",
        severity: item.severity || "Unknown",
        status: String(item.status || "UNKNOWN").toUpperCase(),
      };
    });
  }, [findings, audits, assets]);

  const filtered = useMemo(() => {
    const search = query.toLowerCase();

    return rows.filter((item) => {
      const matchesSearch = [
        item.title,
        item.id,
        item.asset,
        item.benchmark,
        item.status,
        item.evidence_source,
        item.remediation,
      ].some((value) => String(value || "").toLowerCase().includes(search));

      const matchesSeverity =
        severity === "All severities" ||
        String(item.severity).toLowerCase() === severity.toLowerCase();
      const matchesStatus = statusFilter === "All statuses" || item.status === statusFilter;
      const matchesAsset = assetFilter === "All assets" || String(item.asset_id ?? "") === assetFilter;
      return matchesSearch && matchesSeverity && matchesStatus && matchesAsset;
    });
  }, [rows, query, severity, statusFilter, assetFilter]);

  const severityCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

    rows.forEach((item) => {
      const level = Object.keys(counts).find(
        (key) => key.toLowerCase() === String(item.severity).toLowerCase()
      );

      if (level) counts[level] += 1;
    });

    return counts;
  }, [rows]);

  const columns = [
    {
      key: "details",
      label: "",
      render: (_, row) => (
        <button
          className="icon-button"
          aria-label={
            expandedId === row.id ? "Hide details" : "Show details"
          }
          onClick={() =>
            setExpandedId((current) => current === row.id ? null : row.id)
          }
        >
          {expandedId === row.id
            ? <ChevronDown size={16} />
            : <ChevronRight size={16} />}
        </button>
      ),
    },
    { key: "id", label: "CONTROL ID" },
    {
      key: "title",
      label: "FINDING",
      render: (value, row) => (
        <div className="stacked-cell">
          <strong>{value}</strong>
          <span>{row.benchmark}</span>
        </div>
      ),
    },
    { key: "asset", label: "ASSET" },
    { key: "platform", label: "PLATFORM" },
    {
      key: "severity",
      label: "SEVERITY",
      render: (value) => <StatusBadge status={value} />,
    },
    {
      key: "status",
      label: "STATUS",
      render: (value) => <StatusBadge status={value} />,
    },
  ];

  const selectedAudit = audits.find(
    (audit) => String(audit.id) === String(selectedAuditId)
  );

  return (
    <>
      <PageHeader
        title="Security findings"
        description="Prioritise non-compliant controls and inspect control-level evidence."
      />

      <div className="demo-notice findings-mode">
        <span className="demo-notice-dot" />
        <strong>{getAppMode()}</strong>
        <span>
          {loading
            ? "Loading findings..."
            : `Showing results for audit #${selectedAuditId || "â€”"}.`}
        </span>
      </div>

      <section className="panel table-panel findings-table-panel">
        <div className="table-toolbar findings-toolbar">
          <label className="field-label">
            Audit run
            <select
              value={selectedAuditId}
              onChange={(event) => setSelectedAuditId(event.target.value)}
              disabled={loading || audits.length === 0}
            >
              {audits.length === 0 && (
                <option value="">No completed audits</option>
              )}
              {audits.map((audit) => (
                <option key={audit.id} value={String(audit.id)}>
                  Audit #{audit.id} â€” Asset #{audit.asset_id ?? "â€”"} â€”{" "}
                  {audit.status}
                </option>
              ))}
            </select>
          </label>

          <label className="field-label filter-field">
            Search controls
            <div className="search-field">
              <Search size={17} />
              <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search controls, assets, evidence..."
              aria-label="Search findings"
            />
            </div>
          </label>

          <label className="field-label filter-field">Severity
            <select value={severity} onChange={(event) => setSeverity(event.target.value)}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>
          </label>
          <label className="field-label filter-field">Status
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option>All statuses</option><option>PASS</option><option>FAIL</option><option>MANUAL</option><option>ERROR</option><option>NOT_APPLICABLE</option></select>
          </label>
          <label className="field-label filter-field">Asset
            <select value={assetFilter} onChange={event=>setAssetFilter(event.target.value)}><option>All assets</option>{assets.map(asset=><option key={asset.id} value={String(asset.id)}>{asset.name}</option>)}</select>
          </label>
        </div>

        <div className="finding-summary-grid">
          <div className="finding-summary critical">
            <span>Critical</span>
            <strong>{severityCounts.Critical}</strong>
          </div>
          <div className="finding-summary high">
            <span>High</span>
            <strong>{severityCounts.High}</strong>
          </div>
          <div className="finding-summary medium">
            <span>Medium</span>
            <strong>{severityCounts.Medium}</strong>
          </div>
          <div className="finding-summary low">
            <span>Low</span>
            <strong>{severityCounts.Low}</strong>
          </div>
        </div>

        {selectedAudit && (
          <p className="field-hint">
            {selectedAudit.is_simulated
              ? "Simulated fixture results"
              : "Audit results"}{" "}
            Â· {selectedAudit.benchmark_version || "Benchmark version unavailable"}
          </p>
        )}

        {auditDetail && <div className="info-callout"><div><strong>Selected audit context</strong><p>Asset: {assets.find(a=>String(a.id)===String(auditDetail.asset_id))?.name || `Asset #${auditDetail.asset_id}`} Â· Status: {auditDetail.status || "Not provided"} Â· Score: {auditDetail.score == null ? "Not provided" : `${auditDetail.score}%`} Â· {auditDetail.is_simulated ? "Simulated results" : "Live/collected results"}</p></div></div>}

        {loading ? (
          <p className="field-hint">Loading audit findings...</p>
        ) : error ? (
          <p className="field-hint" role="alert">Error: {error}</p>
        ) : (
          <>
            <DataTable columns={columns} rows={filtered} />

            {filtered.map((row) =>
              expandedId === row.id ? (
                <div className="info-callout section-spaced" key={`${row.audit_id}-${row.id}`}>
                  <ShieldAlert size={19} />
                  <div>
                    <strong>{row.id} â€” Control details</strong>
                    <p><strong>Expected:</strong> {row.expected ?? "Not provided"}</p>
                    <p><strong>Actual:</strong> {row.actual ?? "Not provided"}</p>
                    <p><strong>Evidence source:</strong> {row.evidence_source || "Not provided"}</p>
                    <p><strong>Evidence:</strong></p>
                    <pre>{JSON.stringify(row.evidence ?? {}, null, 2)}</pre>
                    <p><strong>Remediation:</strong> {row.remediation || "Not provided"}</p>
                  </div>
                </div>
              ) : null
            )}

            {filtered.length === 0 && (
              <p className="field-hint">
                No findings match this audit and your current filters.
              </p>
            )}
          </>
        )}
      </section>

      <section className="panel section-spaced correlation-panel">
        <div className="panel-header"><div><div className="panel-kicker">TASK 5 Â· EXPOSURE CORRELATION</div><h2>Correlated exposures</h2><p>Computed by the backend for audit #{selectedAuditId || "â€”"}; findings from other audits are not included.</p></div><button className="secondary-button" onClick={()=>{setReloadToken(token=>token+1); retryCorrelations();}} disabled={!selectedAuditId || correlationsLoading}><RefreshCw size={15}/> Retry</button></div>
        {correlationsLoading ? <p className="field-hint" role="status">Retrieving exposure correlations for audit #{selectedAuditId}â€¦</p> : correlationsError ? <div className="info-callout" role="alert"><div><strong>Could not load correlations</strong><p>{correlationsError}</p><button className="secondary-button" onClick={retryCorrelations}><RefreshCw size={15}/> Retry</button></div></div> : correlations.length === 0 ? <div className="empty-state"><Sparkles size={20}/><strong>No exposure correlations were identified for this audit.</strong><p>The correlation engine found no matching rules. This does not mean the asset has zero security risks.</p></div> : <div className="correlation-list">{correlations.map((correlation,index)=><article className="correlation-card" key={correlation.correlation_id || `${correlation.rule_id || "correlation"}-${index}`}>
          <div className="correlation-heading"><div><div className="panel-kicker">{correlation.rule_id || "Correlation"}</div><h3>{correlation.title || "Untitled correlation"}</h3></div><div className="correlation-badges"><StatusBadge status={correlation.severity || "Unknown"}/>{correlation.status && <StatusBadge status={correlation.status}/>}</div></div>
          {correlation.explanation && <div className="correlation-section"><h4>Explanation</h4><p>{correlation.explanation}</p></div>}
          <div className="correlation-meta"><div><span>Supporting findings</span><strong>{Array.isArray(correlation.finding_ids)&&correlation.finding_ids.length ? correlation.finding_ids.map((id,i)=><button key={`${id}-${i}`} className="finding-id-chip" onClick={()=>{setQuery(String(id));document.querySelector(".findings-table-panel")?.scrollIntoView({behavior:"smooth",block:"start"});}}>{`#${id}`}</button>) : "Not supplied"}</strong></div><div><span>Simulated result</span><strong>{typeof correlation.is_simulated === "boolean" ? (correlation.is_simulated ? "Yes · fixture data" : "No · collected data") : "Not supplied"}</strong></div><div><span>Attack path confirmed</span><strong>{typeof correlation.attack_path_confirmed === "boolean" ? (correlation.attack_path_confirmed ? "Yes" : "No") : "Not supplied"}</strong></div></div>
          {correlation.recommendation && <div className="correlation-section recommendation-section"><h4>Recommendation</h4><p>{correlation.recommendation}</p></div>}
          {Array.isArray(correlation.asset_ids) && <p><strong>Related asset IDs:</strong> {correlation.asset_ids.join(", ") || "None supplied"}</p>}
          {Array.isArray(correlation.evidence) && correlation.evidence.length>0 && <details className="evidence-disclosure"><summary>Supporting evidence <span>{correlation.evidence.length} item{correlation.evidence.length===1?"":"s"}</span></summary><pre>{JSON.stringify(correlation.evidence,null,2)}</pre></details>}
          {correlation.is_simulated === true && <p className="field-hint">This correlation comes from simulated fixture audit data.</p>}
        </article>)}</div>}
      </section>

      <section className="panel section-spaced drift-comparison">
        <div className="panel-header"><div><div className="panel-kicker">CONFIGURATION DRIFT</div><h2>Selected audit comparison</h2><p>Snapshot comparison returned for this audit.</p></div><GitCompare size={18}/></div>
        {drift?._error ? <p className="field-hint" role="alert">{drift._error}</p> : drift ? <>
          <p className="drift-context-line">{drift.message || `Baseline audit #${drift.baseline_audit_id ?? "unavailable"} ? current audit #${drift.current_audit_id ?? selectedAuditId}`}{typeof drift.is_simulated === "boolean" ? ` · ${drift.is_simulated ? "Simulated" : "Collected"} evidence` : ""}</p>
          {Array.isArray(drift.changes) && drift.changes.length > 0 ? <div className="drift-change-list">{drift.changes.map((change,i)=><article className="drift-change" key={`${change.setting}-${i}`}><strong className="drift-setting-name">{change.setting}</strong><span className="drift-change-type">{change.change_type}</span><div className="drift-values"><div><span>Before</span><code>{change.before == null ? "—" : typeof change.before === "object" ? JSON.stringify(change.before) : String(change.before)}</code></div><span className="drift-arrow">?</span><div><span>After</span><code>{change.after == null ? "—" : typeof change.after === "object" ? JSON.stringify(change.after) : String(change.after)}</code></div></div></article>)}</div> : <p className="field-hint">No configuration changes were returned.</p>}
          {Array.isArray(drift.newly_failing_controls) && drift.newly_failing_controls.length > 0 && <div className="drift-control-group newly-failing"><h3>Newly failing controls</h3><div>{drift.newly_failing_controls.map(item=><span className="drift-control-chip" key={item.rule_id}>{item.rule_id}</span>)}</div></div>}
          {Array.isArray(drift.resolved_controls) && drift.resolved_controls.length > 0 && <div className="drift-control-group resolved-controls"><h3>Resolved controls</h3><div>{drift.resolved_controls.map(item=><span className="drift-control-chip" key={item.rule_id}>{item.rule_id}</span>)}</div></div>}
        </> : <p className="field-hint">Select an audit to load drift information.</p>}
      </section>
    </>
  );
}
