
import { useEffect, useMemo, useState } from "react";
import { Search, SlidersHorizontal, Server } from "lucide-react";
import { fetchAssets, fetchAuditHistory, listItems, getAppMode } from "../services/api";
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

  useEffect(() => {
    let active = true;

    async function loadAssets() {
      try {
        setLoading(true);
        setError("");

        const [data, history] = await Promise.all([fetchAssets(), fetchAuditHistory()]);
        const assetList = listItems(data);
        const audits = listItems(history);
        if (active) setAssets(assetList.map(asset => {
          const last = audits.find(a => a.asset_id === asset.id);
          return {...asset, score:last?.score ?? null, benchmark:last?.benchmark_version ?? "—", lastAudit:last?.started_at || "Never", assessmentStatus:last?.status || "Not assessed"};
        }));
      } catch (err) {
        if (active) setError(err.message || "Could not load assets.");
      } finally {
        if (active) setLoading(false);
      }
    }

    loadAssets();

    return () => {
      active = false;
    };
  }, []);

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
        description="Search and review infrastructure across operating systems and network devices."
      />

      <div className="demo-notice">
        <span className="demo-notice-dot" />
        <strong>{getAppMode()}</strong>
        <span>
          {loading
            ? "Loading assets from your backend..."
            : "Asset inventory from your backend."}
        </span>
      </div>

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
      {error && <button className="secondary-button" onClick={()=>window.location.reload()}>Retry loading assets</button>}

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
              {[...new Set(rows.map(a => a.platform))].map(value=><option key={value}>{value}</option>)}
            </select>
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option>All statuses</option>
              {[...new Set(rows.map(a => a.status))].map(value=><option key={value}>{value}</option>)}
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
