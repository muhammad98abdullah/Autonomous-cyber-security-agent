import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import StatCard from "../components/StatCard";
import StatusPill from "../components/StatusPill";
import { getMetrics, getSystemStatus } from "../services/api";

export default function DashboardPage() {
  const [metrics, setMetrics] = useState(null);
  const [status, setStatus] = useState("loading");

  useEffect(() => {
    const load = async () => {
      const [statusResponse, metricsResponse] = await Promise.all([getSystemStatus(), getMetrics()]);
      setStatus(statusResponse.status || "running");
      setMetrics(metricsResponse);
    };
    load();
  }, []);

  return (
    <section className="page-grid">
      <div className="card">
        <h2>System Status</h2>
        <div className="inline-row">
          <span>Current:</span>
          <StatusPill value={status} />
        </div>
      </div>

      <div className="stats-grid">
        <StatCard title="Packets Processed" value={metrics?.packetsProcessed ?? "--"} subtitle="Network ingress analyzed" />
        <StatCard title="Attacks Detected" value={metrics?.attacksDetected ?? "--"} subtitle="Flagged by AI + ML model" />
        <StatCard title="Actions Taken" value={metrics?.actionsTaken ?? "--"} subtitle="Response workflow executions" />
      </div>

      <div className="card chart-card">
        <h2>Detection Trend</h2>
        <ResponsiveContainer width="100%" height={280}>
          <LineChart data={metrics?.trend ?? []}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="normal" stroke="#2563eb" name="Normal" />
            <Line type="monotone" dataKey="attack" stroke="#dc2626" name="Attack" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="card quick-actions">
        <h2>Quick Actions</h2>
        <div className="inline-row wrap">
          <Link className="ghost-btn" to="/detection">
            Run Manual Detection
          </Link>
          <Link className="ghost-btn" to="/monitoring">
            Open Live Monitoring
          </Link>
          <Link className="ghost-btn" to="/logs">
            Review Alerts
          </Link>
        </div>
      </div>
    </section>
  );
}
