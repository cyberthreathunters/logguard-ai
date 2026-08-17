import { useEffect, useState } from "react";
import { listDevices, searchLogs, logStats } from "../api.js";

const PAGE_SIZE = 50;

const TIME_PRESETS = [
  { label: "Last 15m", ms: 15 * 60 * 1000 },
  { label: "Last 1h", ms: 60 * 60 * 1000 },
  { label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { label: "Last 7d", ms: 7 * 24 * 60 * 60 * 1000 },
  { label: "All time", ms: null },
];

function formatTimestamp(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

export default function Logs() {
  const [devices, setDevices] = useState([]);
  const [deviceId, setDeviceId] = useState("");
  const [query, setQuery] = useState("");
  const [type, setType] = useState("");
  const [account, setAccount] = useState("");
  const [srcIp, setSrcIp] = useState("");
  const [presetIndex, setPresetIndex] = useState(2); // default: last 24h
  const [results, setResults] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [stats, setStats] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    listDevices()
      .then((data) => setDevices(data.devices))
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    logStats(deviceId || undefined)
      .then((data) => setStats(data.stats))
      .catch(() => {});
  }, [deviceId, results]);

  async function runSearch(newPage = 0) {
    setLoading(true);
    setError(null);
    try {
      const preset = TIME_PRESETS[presetIndex];
      const from = preset.ms ? new Date(Date.now() - preset.ms).toISOString() : "";

      const data = await searchLogs({
        device_id: deviceId,
        q: query,
        type,
        account,
        src_ip: srcIp,
        from,
        limit: PAGE_SIZE,
        offset: newPage * PAGE_SIZE,
      });
      setResults(data.logs);
      setTotal(data.total);
      setPage(newPage);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    runSearch(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleSubmit(e) {
    e.preventDefault();
    runSearch(0);
  }

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="logs-view">
      <form className="search-bar" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Search raw log text..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="search-input"
        />
        <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">All devices</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>{d.hostname || `Device #${d.id}`}</option>
          ))}
        </select>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">All types</option>
          <option value="ssh">ssh (logon)</option>
          <option value="firewall">firewall</option>
          <option value="malware">malware</option>
          <option value="system">system</option>
          <option value="unknown">unknown</option>
        </select>
        <select value={presetIndex} onChange={(e) => setPresetIndex(Number(e.target.value))}>
          {TIME_PRESETS.map((p, i) => (
            <option key={p.label} value={i}>{p.label}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="account"
          value={account}
          onChange={(e) => setAccount(e.target.value)}
          className="search-input-small"
        />
        <input
          type="text"
          placeholder="src_ip"
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          className="search-input-small"
        />
        <button type="submit" disabled={loading}>{loading ? "Searching..." : "Search"}</button>
      </form>

      {stats.length > 0 && (
        <div className="stats-row">
          {stats.map((s) => (
            <button
              key={s.type}
              className={`stat-pill ${type === s.type ? "active" : ""}`}
              onClick={() => { setType(s.type); runSearch(0); }}
            >
              {s.type}: {s.count}
            </button>
          ))}
        </div>
      )}

      {error && <div className="banner-error">{error}</div>}

      <div className="results-meta">
        {total.toLocaleString()} events {query || type || account || srcIp ? "matching" : "total"}
      </div>

      <div className="log-table">
        <div className="log-row log-row-head">
          <span>Time</span>
          <span>Type</span>
          <span>Event ID</span>
          <span>Account</span>
          <span>Source IP</span>
          <span>Raw</span>
        </div>
        {results.map((log) => (
          <div key={log.id} className="log-row">
            <span className="mono">{formatTimestamp(log.event_timestamp)}</span>
            <span className={`type-tag type-${log.type}`}>{log.type}</span>
            <span className="mono">{log.event_id ?? "—"}</span>
            <span>{log.account || "—"}</span>
            <span className="mono">{log.src_ip || "—"}</span>
            <span className="mono raw-cell" title={log.raw}>{log.raw}</span>
          </div>
        ))}
        {results.length === 0 && !loading && (
          <div className="empty-note">No matching log events.</div>
        )}
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button disabled={page === 0} onClick={() => runSearch(page - 1)}>Previous</button>
          <span>Page {page + 1} of {totalPages}</span>
          <button disabled={page + 1 >= totalPages} onClick={() => runSearch(page + 1)}>Next</button>
        </div>
      )}
    </div>
  );
}
