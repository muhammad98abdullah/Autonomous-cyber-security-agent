import { useState } from "react";
import { createSite, getSiteInstallCommand } from "../services/api";

const initial = {
  name: "",
  domain: "",
  serverType: "nginx",
  osType: "linux"
};

export default function OnboardingPage() {
  const [form, setForm] = useState(initial);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const created = await createSite(form);
      const siteId = created.site.id;
      const installData = await getSiteInstallCommand(siteId);
      setResult({
        site: created.site,
        token: created.agentToken,
        command: installData.command
      });
      setForm(initial);
    } catch (err) {
      setError(err.message || "Failed to create site.");
    } finally {
      setLoading(false);
    }
  };

  const copy = async (text) => {
    await navigator.clipboard.writeText(text);
  };

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Website Onboarding Wizard</h2>
        <p>Add a new client website and generate one command to connect the ASTRA agent.</p>
        <form className="form" onSubmit={submit}>
          <label htmlFor="name">Website label</label>
          <input id="name" value={form.name} onChange={(e) => update("name", e.target.value)} placeholder="Client Production Site" />

          <label htmlFor="domain">Domain</label>
          <input id="domain" value={form.domain} onChange={(e) => update("domain", e.target.value)} placeholder="example.com" />

          <label htmlFor="serverType">Server type</label>
          <select id="serverType" value={form.serverType} onChange={(e) => update("serverType", e.target.value)}>
            <option value="nginx">Nginx</option>
            <option value="apache">Apache</option>
            <option value="node">Node.js</option>
            <option value="other">Other</option>
          </select>

          <label htmlFor="osType">Operating system</label>
          <select id="osType" value={form.osType} onChange={(e) => update("osType", e.target.value)}>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
          </select>

          <button type="submit" disabled={loading}>
            {loading ? "Creating..." : "Create Site & Generate Install Command"}
          </button>
          {error ? <p className="error">{error}</p> : null}
        </form>
      </div>

      {result ? (
        <div className="card">
          <h2>Deployment Details</h2>
          <p>
            <strong>Site ID:</strong> {result.site.id}
          </p>
          <p>
            <strong>Agent Token:</strong> {result.token}
          </p>
          <label htmlFor="cmd">Install command</label>
          <textarea id="cmd" readOnly rows={5} value={result.command} />
          <div className="inline-row wrap">
            <button type="button" className="secondary-btn" onClick={() => copy(result.command)}>
              Copy Command
            </button>
            <button type="button" className="secondary-btn" onClick={() => copy(result.token)}>
              Copy Token
            </button>
          </div>
          <p className="muted">
            After installation, run <code>astra_agent.py</code> on the client infrastructure with the generated arguments.
          </p>
        </div>
      ) : null}
    </section>
  );
}
