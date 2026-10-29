export default function StatusBadge({ status }) {
  const normalized = String(status || "Unknown")
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "-");

  return (
    <span className={`status-badge status-${normalized}`}>
      <span className="status-dot" />
      {status || "Unknown"}
    </span>
  );
}