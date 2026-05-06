import { useEffect, useState } from "react";
import StatusPill from "../components/StatusPill";
import { getSiteOverview, getSites, updateSitePolicy } from "../services/api";

export default function SitesPage() {
  const [sites, setSites] = useState([]);
  const [overview, setOverview] = useState({});
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    const allSites = await getSites();
    setSites(allSites);
    const entries = await Promise.all(allSites.map((site) => getSiteOverview(site.id)));
    const map = {};
    entries.forEach((item) => {
      map[item.siteId] = item;
    });
    setOverview(map);
    setLoading(false);
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 7000);
    return () => clearInterval(timer);
  }, []);

  const setMode = async (siteId, mode) => {
    await updateSitePolicy(siteId, mode);
    await load();
  };

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Connected Sites</h2>
        {loading ? <p className="muted">Loading sites...</p> : null}
        {sites.length === 0 ? <p>No sites connected yet. Use Website Onboarding first.</p> : null}
        <div className="site-grid">
          {sites.map((site) => {
            const item = overview[site.id] || {};
            const online = Boolean(item.lastHeartbeatAt);
            return (
              <div key={site.id} className="card site-card">
                <div className="inline-row between">
                  <h3>{site.name}</h3>
                  <StatusPill value={online ? "Running" : "Pending"} />
                </div>
                <p className="muted">{site.domain || "No domain provided"}</p>
                <p>
                  <strong>Mode:</strong> {item.mode || site.mode}
                </p>
                <p>
                  <strong>Total Events:</strong> {item.totalEvents ?? 0}
                </p>
                <p>
                  <strong>Attacks Detected:</strong> {item.attacksDetected ?? 0}
                </p>
                <p>
                  <strong>Last Heartbeat:</strong>{" "}
                  {item.lastHeartbeatAt ? new Date(item.lastHeartbeatAt).toLocaleString() : "Not received yet"}
                </p>
                <div className="inline-row wrap">
                  <button className="secondary-btn" onClick={() => setMode(site.id, "monitor")}>
                    Monitor Only
                  </button>
                  <button onClick={() => setMode(site.id, "autoprotect")}>Auto Protect</button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
