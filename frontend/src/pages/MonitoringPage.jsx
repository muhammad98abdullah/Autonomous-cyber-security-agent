import { useEffect, useMemo, useState } from "react";
import { getLogs, startMonitoring, stopMonitoring } from "../services/api";
import { DEFAULT_SETTINGS } from "../config";

export default function MonitoringPage() {
  const [running, setRunning] = useState(false);
  const [feed, setFeed] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);
  const pollMs = DEFAULT_SETTINGS.pollIntervalMs;

  useEffect(() => {
    if (!running) {
      return undefined;
    }

    const id = setInterval(async () => {
      const latest = await getLogs();
      setFeed(latest);
      setLastUpdate(new Date());
    }, pollMs);

    return () => clearInterval(id);
  }, [running, pollMs]);

  const latestEvents = useMemo(() => feed.slice(0, 10), [feed]);

  const toggle = async () => {
    setLoading(true);
    if (running) {
      await stopMonitoring();
      setRunning(false);
      setLoading(false);
      return;
    }

    await startMonitoring();
    const latest = await getLogs();
    setFeed(latest);
    setLastUpdate(new Date());
    setRunning(true);
    setLoading(false);
  };

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Network Monitoring</h2>
        <p>Control packet capture and view live detection events.</p>
        <div className="inline-row wrap between">
          <button onClick={toggle} disabled={loading}>
            {loading ? "Updating..." : running ? "Stop Monitoring" : "Start Monitoring"}
          </button>
          <span className={`status-text ${running ? "ok" : "neutral"}`}>
            {running ? "Monitoring active" : "Monitoring stopped"}
          </span>
        </div>
        <p className="muted">Poll interval: {pollMs / 1000}s</p>
      </div>

      <div className="card">
        <h2>Live Feed</h2>
        {latestEvents.length === 0 ? (
          <p>No events yet. Start monitoring to stream detections.</p>
        ) : (
          <ul className="feed">
            {latestEvents.map((entry) => (
              <li key={entry.id}>
                <strong>{new Date(entry.timestamp).toLocaleTimeString()}</strong> {entry.attack} from {entry.sourceIp} -{" "}
                {entry.action}
              </li>
            ))}
          </ul>
        )}
        {lastUpdate ? <p className="muted">Last updated: {lastUpdate.toLocaleTimeString()}</p> : null}
      </div>
    </section>
  );
}
