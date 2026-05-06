import { useEffect, useMemo, useState } from "react";
import StatusPill from "../components/StatusPill";
import { getLogs } from "../services/api";

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [page, setPage] = useState(1);
  const pageSize = 8;

  useEffect(() => {
    getLogs().then(setLogs);
  }, []);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return logs.filter((log) => {
      const typeMatches = typeFilter === "all" || log.attack.toLowerCase() === typeFilter;
      const queryMatches =
        log.attack.toLowerCase().includes(q) ||
        log.sourceIp.toLowerCase().includes(q) ||
        log.explanation.toLowerCase().includes(q);
      return typeMatches && queryMatches;
    });
  }, [logs, query, typeFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pagedRows = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, page]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Logs & Alerts</h2>
        <input
          className="search"
          placeholder="Filter by attack, source IP, explanation..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="inline-row wrap between">
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="all">All types</option>
            <option value="normal">Normal</option>
            <option value="attack">Attack</option>
          </select>
          <span className="muted">
            Showing {pagedRows.length} of {filtered.length} records
          </span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Source IP</th>
                <th>Action</th>
                <th>Explanation</th>
              </tr>
            </thead>
            <tbody>
              {pagedRows.map((row) => (
                <tr key={row.id}>
                  <td>{new Date(row.timestamp).toLocaleString()}</td>
                  <td>
                    <StatusPill value={row.attack} />
                  </td>
                  <td>{row.sourceIp}</td>
                  <td>{row.action}</td>
                  <td>{row.explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="inline-row between">
          <button className="secondary-btn" disabled={page === 1} onClick={() => setPage((p) => p - 1)}>
            Previous
          </button>
          <span className="muted">
            Page {page} / {totalPages}
          </span>
          <button className="secondary-btn" disabled={page === totalPages} onClick={() => setPage((p) => p + 1)}>
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
