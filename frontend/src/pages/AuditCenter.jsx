import { useEffect, useState } from "react";
import { ClipboardCheck, Play, Clock3, ShieldCheck } from "lucide-react";
import StatusBadge from "../components/common/StatusBadge";
import DataTable from "../components/common/DataTable";
import PageHeader from "../components/layout/PageHeader";
import {
  getAppMode,
  fetchAssets,
  fetchAuditHistory,
  startAudit,
  listItems,
} from "../services/api";

export default function AuditCenter() {
  const [assets, setAssets] = useState([]);
  const [history, setHistory] = useState([]);
  const [assetId, setAssetId] = useState("");
  const [fixture, setFixture] = useState("cisco_baseline");
  const [benchmark, setBenchmark] = useState("CIS_Cisco_IOS_17_v2.1.0");
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadData() {
    setLoading(true);
    setError("");

    try {
      const [assetData, auditData] = await Promise.all([
        fetchAssets(),
        fetchAuditHistory(),
      ]);

      const assetList = listItems(assetData);
      const auditList = listItems(auditData);

      setAssets(assetList);
      setHistory(auditList);

      if (assetList.length > 0) {
        setAssetId((current) =>
          current && assetList.some((asset) => String(asset.id) === current)
            ? current
            : String(assetList[0].id)
        );
      }
    } catch (err) {
      setError(err.message || "Could not load assets and audit history.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const timer = setTimeout(() => loadData(), 0);
    return () => clearTimeout(timer);
  }, []);

  async function handleRunAudit() {
    if (!assetId) {
      setError("Please select an asset before running the audit.");
      return;
    }

    setRunning(true);
    setError("");
    setMessage("");

    try {
      const result = await startAudit({
        asset_id: Number(assetId),
        fixture_name: fixture || null,
        benchmark_version: benchmark.trim() || null,
      });

      const counts = result.finding_counts || {};
      setMessage(`Audit #${result.audit_id} ${result.is_simulated ? "(simulated fixture)" : "(live collection)"} · ${result.status} · Score ${result.score == null ? "N/A" : `${result.score}%`} · Coverage ${result.coverage_pct ?? "N/A"}% · PASS ${counts.pass ?? 0}, FAIL ${counts.fail ?? 0}, MANUAL ${counts.manual ?? 0}, ERROR ${counts.error ?? 0}, N/A ${counts.not_applicable ?? 0}.`);

      await loadData();
    } catch (err) {
      setError(err.message || "The audit could not be completed.");
    } finally {
      setRunning(false);
    }
  }

  const columns = [
    {
      key: "id",
      label: "AUDIT ID",
      render: (value, row) => value ?? row.audit_id ?? "—",
    },
    {
      key: "target",
      label: "TARGET",
      render: (_, row) => {
        const asset = assets.find(
          (item) => item.id === (row.asset_id ?? row.asset?.id)
        );
        return row.asset_name || row.asset?.name || asset?.name || `Asset #${row.asset_id ?? "—"}`;
      },
    },
    {
      key: "benchmark",
      label: "BENCHMARK",
      render: (value, row) =>
        value || row.benchmark_version || "—",
    },
    {
      key: "started",
      label: "STARTED",
      render: (value, row) => {
        const date = value || row.started_at || row.created_at;
        return date ? new Date(date).toLocaleString() : "—";
      },
    },
    {
      key: "passed",
      label: "PASSED",
      render: (value, row) => (
        <span className="text-success">
          {value ?? row.finding_counts?.PASS ?? "—"}
        </span>
      ),
    },
    {
      key: "failed",
      label: "FAILED",
      render: (value, row) => (
        <span className="text-danger">
          {value ?? row.finding_counts?.FAIL ?? "—"}
        </span>
      ),
    },
    {
      key: "result",
      label: "RESULT",
      render: (value, row) => (
        <StatusBadge status={value || row.status || "Unknown"} />
      ),
    },
  ];

  const selectedAsset = assets.find(a => String(a.id) === assetId);

  return (
    <>
      <PageHeader
        title="Audit center"
        description="Configure assessments, review past runs and inspect control-level results."
      />

      <div className="demo-notice">
        <span className="demo-notice-dot" />
        <strong>{getAppMode()}</strong>
        <span>
          {getAppMode() === "API mode"
            ? "Connected to the audit backend."
            : "Enable API mode to execute audits."}
        </span>
      </div>

      <section className="panel audit-config-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">NEW ASSESSMENT</div>
            <h2>Configure an audit</h2>
            <p>Choose a supported assessment method and asset.</p>
          </div>
          <div className="panel-icon">
            <ClipboardCheck size={21} />
          </div>
        </div>

        <div className="audit-form-grid">
          <label className="field-label">
            Target asset
            <select
              value={assetId}
              onChange={(event) => {
                const newAssetId = event.target.value;
                setAssetId(newAssetId);
                const ast = assets.find(a => String(a.id) === newAssetId);
                if (ast && !fixture) {
                  if (ast.asset_type?.toLowerCase() === "windows") {
                    setBenchmark("CIS_Windows_Server_2022_v1.0_ILLUSTRATIVE");
                  } else if (ast.asset_type?.toLowerCase() === "linux") {
                    setBenchmark("CIS_Ubuntu_Linux_22.04_v1.0");
                  }
                }
              }}
              disabled={loading || assets.length === 0 || running}
            >
              {assets.length === 0 && (
                <option value="">No assets available</option>
              )}
              {assets.map((asset) => (
                <option key={asset.id} value={String(asset.id)}>
                  {asset.name} (ID: {asset.id} · {asset.platform || asset.asset_type})
                </option>
              ))}
            </select>
          </label>

          <label className="field-label">
            Audit fixture
            <select
              value={fixture}
              onChange={(event) => {
                const value = event.target.value;
                setFixture(value);
                if (value.startsWith("windows")) {
                  setBenchmark("CIS_Windows_Server_2022_v1.0_ILLUSTRATIVE");
                } else if (value.startsWith("cisco")) {
                  setBenchmark("CIS_Cisco_IOS_17_v2.1.0");
                } else if (!value) {
                  const ast = assets.find(a => String(a.id) === assetId);
                  if (ast?.asset_type?.toLowerCase() === "windows") {
                    setBenchmark("CIS_Windows_Server_2022_v1.0_ILLUSTRATIVE");
                  } else {
                    setBenchmark("CIS_Ubuntu_Linux_22.04_v1.0");
                  }
                }
              }}
              disabled={running}
            >
              <option value="cisco_baseline">
                Cisco baseline — passing configuration
              </option>
              <option value="cisco_modified">
                Cisco modified — configuration issues
              </option>
              <option value="windows_baseline">
                Windows baseline — passing configuration
              </option>
              <option value="windows_hardened">
                Windows hardened — configuration issues
              </option>
              <option value="">
                Live collection (Linux or Windows host)
              </option>
            </select>
          </label>
        </div>

        <div className="audit-form-grid">
          <label className="field-label">
            Benchmark version
            <input
              value={benchmark}
              onChange={(event) => setBenchmark(event.target.value)}
              placeholder="Enter benchmark version"
              disabled={running}
            />
          </label>
        </div>

        <div className="audit-config-footer">
          <span>
            <ShieldCheck size={16} />
            {fixture
              ? "Simulated fixture audit"
              : "Live host collection attempt"}
          </span>
          <button
            className="primary-button"
            onClick={handleRunAudit}
            disabled={
              loading ||
              running ||
              !assetId ||
              (!fixture && !["linux", "windows"].includes(selectedAsset?.asset_type?.toLowerCase()))
            }
          >
            <Play size={16} />
            {running ? "Running audit..." : "Run audit"}
          </button>
        </div>

        <p className="field-hint">
          Cisco fixtures assess Cisco network rules. Windows fixtures assess Windows Server CIS rules. Live collection is supported for Linux and Windows assets.
        </p>

        {loading && <p className="field-hint">Loading assets and audit history...</p>}

        {error && (
          <p role="alert" className="field-hint">
            Error: {error}
          </p>
        )}

        {message && (
          <p role="status" className="field-hint">
            {message}
          </p>
        )}
      </section>

      <section className="panel table-panel section-spaced">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">ASSESSMENT RECORDS</div>
            <h2>Audit history</h2>
            <p>Records retrieved from the backend.</p>
          </div>
          <div className="header-icon-label">
            <Clock3 size={16} /> Recent runs
          </div>
        </div>

        {loading ? (
          <p className="field-hint">Loading audit history...</p>
        ) : (
          <DataTable columns={columns} rows={history} />
        )}

        {!loading && history.length === 0 && !error && (
          <p className="field-hint">
            No audit records found. Select an asset and run your first audit.
          </p>
        )}
      </section>
    </>
  );
}
