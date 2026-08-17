import { useEffect, useRef, useState } from "react";
import { listDevices, listAlerts } from "../api.js";
import Logs from "./Logs.jsx";

const POLL_INTERVAL_MS = 8000;

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function severityLabel(severity) {
  return severity ? severity.toUpperCase() : "INFO";
}

function timeAgo(isoString) {
  if (!isoString) return "";
  const normalized = isoString.includes("T")
    ? isoString
    : isoString.replace(" ", "T") + "Z";
  const diffMs = Date.now() - new Date(normalized).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function AlertsView({ devices, selectedDeviceId }) {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (!selectedDeviceId) return;

    async function fetchAlerts() {
      try {
        const data = await listAlerts(selectedDeviceId);
        setAlerts(data.alerts);
        setError(null);
      } catch (err) {
        setError(err.message);
      }
    }

    fetchAlerts();
    pollRef.current = setInterval(fetchAlerts, POLL_INTERVAL_MS);
    return () => clearInterval(pollRef.current);
  }, [selectedDeviceId]);

  const sortedAlerts = [...alerts].sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (sevDiff !== 0) return sevDiff;
    return new Date(b.created_at) - new Date(a.created_at);
  });

  const counts = alerts.reduce((acc, a) => {
    acc[a.severity || "info"] = (acc[a.severity || "info"] || 0) + 1;
    return acc;
  }, {});

  return (
    <main className="alert-panel">
      <div className="stat-row">
        <div className="stat-chip critical">{counts.critical || 0} critical</div>
        <div className="stat-chip high">{counts.high || 0} high</div>
        <div className="stat-chip medium">{counts.medium || 0} medium</div>
      </div>

      {error && <div className="banner-error">{error}</div>}

      {sortedAlerts.length === 0 && !error && (
        <div className="empty-note">No alerts yet for this device.</div>
      )}

      <div className="alert-list">
        {sortedAlerts.map((a) => (
          <div key={a.id} className={`alert-card sev-${a.severity || "info"}`}>
            <div className="alert-top">
              <span className={`sev-badge sev-${a.severity || "info"}`}>
                {severityLabel(a.severity)}
              </span>
              <span className="alert-type">{a.type.replaceAll("_", " ")}</span>
              <span className="alert-time">{timeAgo(a.created_at)}</span>
            </div>
            <div className="alert-detail">{a.detail.raw}</div>
          </div>
        ))}
      </div>
    </main>
  );
}

export default function Dashboard({ onLogout }) {
  const [devices, setDevices] = useState([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [view, setView] = useState("alerts"); // "alerts" | "logs"

  useEffect(() => {
    listDevices().then((data) => {
      setDevices(data.devices);
      if (data.devices.length > 0) setSelectedDeviceId(data.devices[0].id);
    });
  }, []);

  useEffect(() => {
    const t = setInterval(() => setLastUpdated(new Date()), POLL_INTERVAL_MS);
    return () => clearInterval(t);
  }, []);

  function handleLogout() {
    localStorage.removeItem("lg_token");
    onLogout();
  }

  return (
    <div className="dashboard">
      <header className="dash-header">
        <div className="logo">
          LogGuard <span className="dot">AI</span>
        </div>
        <nav className="view-tabs">
          <button className={view === "alerts" ? "active" : ""} onClick={() => setView("alerts")}>
            Alerts
          </button>
          <button className={view === "logs" ? "active" : ""} onClick={() => setView("logs")}>
            Search Logs
          </button>
        </nav>
        <div className="dash-header-right">
          <span className="last-updated">Updated {timeAgo(lastUpdated.toISOString())}</span>
          <button className="logout-btn" onClick={handleLogout}>Sign out</button>
        </div>
      </header>

      <div className="dash-body">
        {view === "alerts" && (
          <>
            <aside className="device-list">
              <h3>Devices</h3>
              {devices.length === 0 && <p className="empty-note">No devices enrolled yet</p>}
              {devices.map((d) => (
                <button
                  key={d.id}
                  className={`device-item ${d.id === selectedDeviceId ? "active" : ""}`}
                  onClick={() => setSelectedDeviceId(d.id)}
                >
                  <div className="device-host">{d.hostname || `Device #${d.id}`}</div>
                  <div className="device-seen">
                    {d.last_seen_at ? `seen ${timeAgo(d.last_seen_at)}` : "never checked in"}
                  </div>
                </button>
              ))}
            </aside>
            <AlertsView devices={devices} selectedDeviceId={selectedDeviceId} />
          </>
        )}

        {view === "logs" && (
          <main className="alert-panel logs-panel">
            <Logs />
          </main>
        )}
      </div>
    </div>
  );
}
