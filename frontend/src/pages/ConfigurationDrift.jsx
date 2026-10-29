
import { useCallback, useEffect, useState } from "react";
import {
  GitCompare,
  History,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Settings2,
  ArrowRight,
} from "lucide-react";

import { fetchAssets, fetchAuditHistory, fetchDrift, listItems, getAppMode } from "../services/api";
import StatusBadge from "../components/common/StatusBadge";
import PageHeader from "../components/layout/PageHeader";

function displayValue(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export default function ConfigurationDrift() {
  const [audits, setAudits] = useState([]);
  const [assets, setAssets] = useState([]);
  const [selectedAuditId, setSelectedAuditId] = useState("");
  const [drift, setDrift] = useState(null);

  const [loadingAudits, setLoadingAudits] = useState(true);
  const [loadingDrift, setLoadingDrift] = useState(false);
  const [driftError, setDriftError] = useState("");
  const [activeTab, setActiveTab] = useState("changes");

  const loadAuditHistory = useCallback(async () => {
    setLoadingAudits(true);
    setDriftError("");

    try {
      const [auditResponse, assetResponse] = await Promise.all([
        fetchAuditHistory(),
        fetchAssets(),
      ]);

      const auditItems = listItems(auditResponse);
      const assetItems = listItems(assetResponse);

      setAudits(auditItems);
      setAssets(assetItems);

      setSelectedAuditId((previousId) => {
        if (
          previousId &&
          auditItems.some((audit) => String(audit.id) === previousId)
        ) {
          return previousId;
        }

        const latestAudit = auditItems.find(
          (audit) => audit.status?.toUpperCase() === "COMPLETED"
        );

        return latestAudit ? String(latestAudit.id) : "";
      });
    } catch (err) {
      setDriftError(
        err.message ||
          "Could not load audit history. Check the backend connection."
      );
    } finally {
      setLoadingAudits(false);
    }
  }, []);

  const loadDrift = useCallback(async (id) => {
    if (!id) {
      setDrift(null);
      return;
    }

    setLoadingDrift(true);
    setDriftError("");

    try {
      const result = await fetchDrift(id);
      setDrift(result);
    } catch (err) {
      setDrift(null);
      setDriftError(
        err.message ||
          "Could not load this comparison. The audit may not have a saved snapshot."
      );
    } finally {
      setLoadingDrift(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => loadAuditHistory(), 0);
    return () => clearTimeout(timer);
  }, [loadAuditHistory]);

  useEffect(() => {
    if (selectedAuditId) { const timer = setTimeout(() => loadDrift(selectedAuditId), 0); return () => clearTimeout(timer); }
  }, [selectedAuditId, loadDrift]);

  const changes = drift?.changes ?? [];
  const newlyFailing = drift?.newly_failing_controls ?? [];
  const resolved = drift?.resolved_controls ?? [];

  const assetById = Object.fromEntries(
    assets.map((asset) => [String(asset.id), asset])
  );

  const selectedAudit = audits.find(
    (audit) => String(audit.id) === selectedAuditId
  );

  const asset = drift
    ? assetById[String(drift.asset_id)]
    : selectedAudit
      ? assetById[String(selectedAudit.asset_id)]
      : null;

  const currentAudit = drift?.current_audit_id
    ? audits.find(
        (audit) => String(audit.id) === String(drift.current_audit_id)
      )
    : selectedAudit;

  const baselineAudit = drift?.baseline_audit_id
    ? audits.find(
        (audit) => String(audit.id) === String(drift.baseline_audit_id)
      )
    : null;

  const totalAudits = audits.length;

  return (
    <>
      <PageHeader
        title="Configuration drift"
        description="Track configuration changes and identify potential CIS compliance regressions."
      />

      {/* Compact audit selector */}
      <section className="panel drift-toolbar">
        <div className="drift-toolbar-copy">
          <div className="panel-kicker">AUDIT COMPARISON</div>
          <h2>Select an audit</h2>
              <p>
            Compare a completed snapshot with the previous eligible baseline.
          </p>
        </div>

        <div className="drift-toolbar-actions">
          <div className="drift-select-wrap">
            <label htmlFor="drift-audit-select">Current audit</label>
            <select
              id="drift-audit-select"
              value={selectedAuditId}
              onChange={(event) => setSelectedAuditId(event.target.value)}
              disabled={loadingAudits || audits.length === 0}
            >
              <option value="">
                {loadingAudits ? "Loading audits..." : "Select an audit"}
              </option>

              {audits.map((audit) => (
                <option
                  key={audit.id}
                  value={String(audit.id)}
                  disabled={audit.status?.toUpperCase() !== "COMPLETED"}
                >
                  Audit #{audit.id} · Asset #{audit.asset_id} ·{" "}
                  {audit.status}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            className="drift-refresh-button"
            onClick={() => {
              loadAuditHistory();
              if (selectedAuditId) loadDrift(selectedAuditId);
            }}
            disabled={loadingAudits || loadingDrift}
            title="Refresh audit history and comparison"
          >
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>
      </section>

      {driftError && (
        <div className="drift-error" role="alert">
          <AlertTriangle size={18} />
          <div>
            <strong>Unable to load drift data</strong>
            <p>{driftError}</p>
          </div>
        </div>
      )}

      {!loadingAudits && totalAudits === 0 && (
        <div className="empty-state drift-empty">
          <History size={22} />
          <strong>No audits found</strong>
          <p>Create an audit before comparing configuration snapshots.</p>
        </div>
      )}

      {selectedAudit && !drift && !loadingDrift && !driftError && <div className="empty-state drift-empty">This audit has no comparison data available.</div>}

      {drift && (
        <>
          {/* Compact context bar */}
          <div className="drift-context">
            <div className="drift-context-main">
              <span
                className={`drift-context-dot ${
                  drift.is_simulated ? "simulated" : "collected"
                }`}
              />

              <div>
                <strong>
                  {drift.is_simulated
                    ? "Simulated evidence"
                    : "Collected evidence"}
                </strong>
                <span>
                  {asset?.name ?? `Asset #${drift.asset_id}`}
                  {" · "}
                  {baselineAudit
                    ? `Baseline #${drift.baseline_audit_id} → Audit #${drift.current_audit_id}`
                    : "No previous matching baseline"}
                </span>
              </div>
            </div>

            {currentAudit && (
              <div className="drift-audit-meta">
                <span>Score</span>
                <strong>
                  {currentAudit.score == null
                    ? "—"
                    : `${currentAudit.score}%`}
                </strong>
              </div>
            )}
          </div>

          {/* Summary metrics */}
          <div className="drift-metrics">
            <article className="drift-metric">
              <div className="drift-metric-icon neutral">
                <Settings2 size={18} />
              </div>
              <div>
                <span>Configuration changes</span>
                <strong>{changes.length}</strong>
              </div>
            </article>

            <article className="drift-metric">
              <div className="drift-metric-icon warning">
                <AlertTriangle size={18} />
              </div>
              <div>
                <span>Newly failing controls</span>
                <strong>{newlyFailing.length}</strong>
              </div>
            </article>

            <article className="drift-metric">
              <div className="drift-metric-icon success">
                <CheckCircle2 size={18} />
              </div>
              <div>
                <span>Resolved controls</span>
                <strong>{resolved.length}</strong>
              </div>
            </article>
          </div>

          {drift.baseline_audit_id == null && (
            <div className="drift-baseline-note">
              This is the first eligible snapshot for this asset and evidence
              type. Future completed audits can be compared against it.
            </div>
          )}

          {/* Main comparison panel */}
          <section className="panel drift-results-panel">
            <div className="drift-results-header">
              <div>
                <div className="panel-kicker">COMPARISON RESULTS</div>
                <h2>Audit differences</h2>
              </div>

              <span className="drift-result-count">
                {changes.length + newlyFailing.length + resolved.length}{" "}
                reported items
              </span>
            </div>

            <div className="drift-tabs" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === "changes"}
                className={activeTab === "changes" ? "active" : ""}
                onClick={() => setActiveTab("changes")}
              >
                <GitCompare size={15} />
                Changes
                <span>{changes.length}</span>
              </button>

              <button
                type="button"
                role="tab"
                aria-selected={activeTab === "failing"}
                className={activeTab === "failing" ? "active" : ""}
                onClick={() => setActiveTab("failing")}
              >
                <AlertTriangle size={15} />
                Regressions
                <span>{newlyFailing.length}</span>
              </button>

              <button
                type="button"
                role="tab"
                aria-selected={activeTab === "resolved"}
                className={activeTab === "resolved" ? "active" : ""}
                onClick={() => setActiveTab("resolved")}
              >
                <CheckCircle2 size={15} />
                Resolved
                <span>{resolved.length}</span>
              </button>
            </div>

            {loadingDrift ? (
              <div className="drift-loading">
                <RefreshCw size={18} className="drift-spin" />
                Loading comparison...
              </div>
            ) : (
              <>
                {activeTab === "changes" && (
                  <div className="drift-table-wrap">
                    {changes.length === 0 ? (
                      <div className="drift-inline-empty">
                        <CheckCircle2 size={20} />
                        <strong>No configuration changes detected</strong>
                        <span>
                          The selected snapshot has no recorded differences
                          from its eligible baseline.
                        </span>
                      </div>
                    ) : (
                      <table className="drift-table">
                        <thead>
                          <tr>
                            <th>Setting</th>
                            <th>Change</th>
                            <th>Before</th>
                            <th aria-label="Direction" />
                            <th>After</th>
                          </tr>
                        </thead>
                        <tbody>
                          {changes.map((change, index) => (
                            <tr
                              key={`${change.setting}-${index}`}
                            >
                              <td>
                                <strong className="drift-setting">
                                  {change.setting}
                                </strong>
                              </td>
                              <td>
                                <StatusBadge status={change.change_type} />
                              </td>
                              <td>
                                <code className="drift-value before">
                                  {displayValue(change.before)}
                                </code>
                              </td>
                              <td className="drift-direction">
                                <ArrowRight size={16} />
                              </td>
                              <td>
                                <code
                                  className={`drift-value ${
                                    change.change_type === "removed"
                                      ? "after-removed"
                                      : "after"
                                  }`}
                                >
                                  {displayValue(change.after)}
                                </code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}

                {activeTab === "failing" && (
                  <div className="drift-control-list">
                    {newlyFailing.length === 0 ? (
                      <div className="drift-inline-empty">
                        <CheckCircle2 size={20} />
                        <strong>No newly failing controls</strong>
                        <span>
                          No new PASS-to-FAIL regressions were reported.
                        </span>
                      </div>
                    ) : (
                      newlyFailing.map((control) => (
                        <article
                          className="drift-control-row"
                          key={control.rule_id}
                        >
                          <div className="drift-control-icon warning">
                            <AlertTriangle size={17} />
                          </div>
                          <div className="drift-control-info">
                            <strong>{control.rule_id}</strong>
                            <span>
                              {control.previous_status ?? "No previous finding"}
                              {" → "}
                              {control.current_status}
                            </span>
                          </div>
                          <span className="drift-severity">
                            {control.severity ?? "Unknown"} severity
                          </span>
                          <StatusBadge status={control.current_status} />
                        </article>
                      ))
                    )}
                  </div>
                )}

                {activeTab === "resolved" && (
                  <div className="drift-control-list">
                    {resolved.length === 0 ? (
                      <div className="drift-inline-empty">
                        <History size={20} />
                        <strong>No resolved controls</strong>
                        <span>
                          No FAIL-to-PASS resolutions were reported.
                        </span>
                      </div>
                    ) : (
                      resolved.map((control) => (
                        <article
                          className="drift-control-row"
                          key={control.rule_id}
                        >
                          <div className="drift-control-icon success">
                            <CheckCircle2 size={17} />
                          </div>
                          <div className="drift-control-info">
                            <strong>{control.rule_id}</strong>
                            <span>
                              {control.previous_status}
                              {" → "}
                              {control.current_status}
                            </span>
                          </div>
                          <span className="drift-severity">
                            {control.severity ?? "Unknown"} severity
                          </span>
                          <StatusBadge status={control.current_status} />
                        </article>
                      ))
                    )}
                  </div>
                )}
              </>
            )}
          </section>

          <p className="drift-footnote">
            {getAppMode()} · Audit history refreshes from the API. Drift
            comparisons use persisted snapshots and findings.
          </p>
        </>
      )}
    </>
  );
}
