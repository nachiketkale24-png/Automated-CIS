export default function DataTable({
  columns,
  rows,
  rowKey = "id",
  emptyMessage = "No records found.",
}) {
  if (!rows.length) {
    return <div className="empty-state">{emptyMessage}</div>;
  }

  return (
    <div
      className="table-scroll"
      role="region"
      aria-label="Scrollable data table"
      tabIndex="0"
    >
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.label}</th>
            ))}
          </tr>
        </thead>

        <tbody>
          {rows.map((row, index) => (
            <tr key={row[rowKey] ?? `${row.name ?? "row"}-${index}`}>
              {columns.map((column) => (
                <td key={column.key}>
                  {column.render
                    ? column.render(row[column.key], row)
                    : row[column.key] ?? "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}