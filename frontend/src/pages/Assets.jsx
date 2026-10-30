import { useEffect, useMemo, useState } from "react";
import { Search, SlidersHorizontal, Server, Plus, X, CheckCircle2 } from "lucide-react";
import { fetchAssets, fetchAuditHistory, createAsset, listItems, getAppMode } from "../services/api";
import StatusBadge from "../components/common/StatusBadge";
import DataTable from "../components/common/DataTable";
import PageHeader from "../components/layout/PageHeader";

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [query, setQuery] = useState("");
  const [platform, setPlatform] = useState("All platforms");
  const [status, setStatus] = useState("All statuses");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Add Asset form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [assetType, setAssetType] = useState("windows");
  const [assetPlatform, setAssetPlatform] = useState("Windows 10/11");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [submitSuccess, setSubmitSuccess] = useState("");

  async function loadAssets() {
    try {
      setLoading(true);
      setError("");

      const [data, history] = await Promise.all([fetchAssets(), fetchAuditHistory()]);
      const assetList = listItems(data);
      const audits = listItems(history);
      setAssets(assetList.map(asset => {
        const last = audits.find(a => a.asset_id === asset.id);
        return {
          ...asset,
          score: last?.score ?? null,
          benchmark: last?.benchmark_version ?? "—",
          lastAudit: last?.started_at ? new Date(last.started_at).toLocaleString() : "Never",
          assessmentStatus: last?.status || "Not assessed",
        };
      }));
    } catch (err) {
      setError(err.message || "Could not load assets.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAssets();
  }, []);

  async function handleCreateAsset(e) {
    e.preventDefault();
    if (!name.trim() || !hostname.trim()) {
      setSubmitError("Please provide both name and hostname/IP address.");
      return;
    }

    setSubmitting(true);
    setSubmitError("");
    setSubmitSuccess("");

    try {
      const created = await createAsset({
        name: name.trim(),
        hostname: hostname.trim(),
        asset_type: assetType,
        platform: assetPlatform.trim() || null,
      });

      setSubmitSuccess(`Asset "${created.name}" (ID #${created.id}) registered successfully!`);
      setName("");
      setHostname("");
      await loadAssets();
      setTimeout(() => {
        setShowAddForm(false);
        setSubmitSuccess("");
      }, 1500);
    } catch (err) {
      setSubmitError(err.message || "Failed to register asset.");
    } finally {
      setSubmitting(false);
    }
  }

  const rows = useMemo(
    () =>
      assets.map((asset) => ({
        id: asset.id,
        name: asset.name,
        address: asset.hostname,
        platform: asset.platform || asset.asset_type || "Unknown",
        benchmark: asset.benchmark,
        score: asset.score,
        lastAudit: asset.lastAudit,
        status: asset.assessmentStatus,
      })),
    [assets]
  );

  const filteredAssets = useMemo(() => {
    const search = query.toLowerCase();

    return rows.filter((asset) => {
      const matchesSearch =
        asset.name.toLowerCase().includes(search) ||
        (asset.address || "").toLowerCase().includes(search) ||
        asset.platform.toLowerCase().includes(search);

      return (
        matchesSearch &&
        (platform === "All platforms" || asset.platform === platform) &&
        (status === "All statuses" || asset.status === status)
      );
    });
  }, [rows, query, platform, status]);

  const columns = [
    {
      key: "name",
      label: "ASSET",
      render: (value, row) => (
        <div className="asset-cell">
          <div className="asset-cell-icon"><Server size={17} /></div>
          <div>
            <strong>{value}</strong>
            <span>{row.id} · {row.address || "No hostname"}</span>
          </div>
        </div>
      ),
    },
    { key: "platform", label: "PLATFORM" },
    { key: "benchmark", label: "BENCHMARK" },
    {
      key: "score",
      label: "SCORE",
      render: (value) =>
        value == null
          ? <span className="muted-text">Not assessed</span>
          : <strong>{value}%</strong>,
    },
    { key: "lastAudit", label: "LAST AUDIT" },
    {
      key: "status",
      label: "STATUS",
      render: (value) => <StatusBadge status={value} />,
    },
  ];

  return (
    <>
      <PageHeader
        title="Asset inventory"
        description="Search, register and review infrastructure across operating systems and network devices."
        actionLabel="Register asset"
        onAction={() => setShowAddForm(prev => !prev)}
      />

      <div className="demo-notice">
        <span className="demo-notice-dot" />
        <strong>{getAppMode()}</strong>
        <span>
          {loading
            ? "Loading assets from your backend..."
            : "Asset inventory connected to your backend."}
        </span>
      </div>

      {showAddForm && (
        <section className="panel audit-config-panel section-spaced">
          <div className="panel-header">
            <div>
              <div className="panel-kicker">NEW INFRASTRUCTURE</div>
              <h2>Register an asset</h2>
              <p>Add a new server, desktop or network device to the compliance audit inventory.</p>
            </div>
            <button className="icon-button" onClick={() => setShowAddForm(false)} aria-label="Close">
              <X size={18} />
            </button>
          </div>

          <form onSubmit={handleCreateAsset}>
            <div className="audit-form-grid">
              <label className="field-label">
                Asset name
                <input
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. My-Windows-PC or prod-db-01"
                />
              </label>

              <label className="field-label">
                Asset type
                <select
                  value={assetType}
                  onChange={(e) => {
                    const t = e.target.value;
                    setAssetType(t);
                    if (t === "windows") setAssetPlatform("Windows 10/11");
                    else if (t === "linux") setAssetPlatform("Ubuntu Linux 22.04");
                    else if (t === "router") setAssetPlatform("Cisco IOS 17");
                    else if (t === "firewall") setAssetPlatform("Cisco ASA / Perimeter FW");
                  }}
                >
                  <option value="windows">Windows (Workstation / Server)</option>
                  <option value="linux">Linux Server</option>
                  <option value="router">Router</option>
                  <option value="firewall">Firewall</option>
                  <option value="switch">Switch</option>
                  <option value="network_device">Network Device</option>
                </select>
              </label>
            </div>

            <div className="audit-form-grid">
              <label className="field-label">
                Hostname or IP address
                <input
                  required
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder="e.g. localhost, 127.0.0.1, or pc.domain.local"
                />
              </label>

              <label className="field-label">
                Platform specification (optional)
                <input
                  value={assetPlatform}
                  onChange={(e) => setAssetPlatform(e.target.value)}
                  placeholder="e.g. Windows 11 Home, Ubuntu 22.04 LTS"
                />
              </label>
            </div>

            {submitError && <p className="field-hint" style={{ color: "#ef4444" }} role="alert">{submitError}</p>}
            {submitSuccess && <p className="field-hint" style={{ color: "#22c55e" }} role="status">{submitSuccess}</p>}

            <div className="audit-config-footer">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setShowAddForm(false)}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="primary-button"
                disabled={submitting || !name.trim() || !hostname.trim()}
              >
                <Plus size={16} />
                {submitting ? "Registering..." : "Save asset"}
              </button>
            </div>
          </form>
        </section>
      )}

      {error && (
        <div className="demo-notice">
          <strong>Could not load assets</strong>
          <span>{error}</span>
        </div>
      )}

      <div className="summary-strip">
        <div><span>Total assets</span><strong>{assets.length}</strong></div>
        <div>
          <span>Assessed</span>
          <strong>{assets.filter((a) => a.score != null).length}</strong>
        </div>
        <div>
          <span>Not assessed</span>
          <strong>{assets.filter((a) => a.score == null).length}</strong>
        </div>
      </div>
      {error && <button className="secondary-button" onClick={() => window.location.reload()}>Retry loading assets</button>}

      <section className="panel table-panel">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={17} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search assets, IPs, platforms..."
              aria-label="Search assets"
            />
          </div>

          <div className="filter-controls">
            <SlidersHorizontal size={16} />
            <select value={platform} onChange={(event) => setPlatform(event.target.value)}>
              <option>All platforms</option>
              {[...new Set(rows.map(a => a.platform))].map(value => <option key={value}>{value}</option>)}
            </select>
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option>All statuses</option>
              {[...new Set(rows.map(a => a.status))].map(value => <option key={value}>{value}</option>)}
            </select>
          </div>
        </div>

        {loading ? (
          <p className="muted-text">Loading assets...</p>
        ) : (
          <DataTable columns={columns} rows={filteredAssets} />
        )}

        <div className="table-footer">
          Showing {filteredAssets.length} of {assets.length} backend assets
        </div>
      </section>
    </>
  );
}
