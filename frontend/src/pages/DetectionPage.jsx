import { useState } from "react";
import StatusPill from "../components/StatusPill";
import { detect } from "../services/api";

const sample = Array.from({ length: 77 }, (_, i) => (i === 0 ? 128 : i === 1 ? 1 : 0));

export default function DetectionPage() {
  const [jsonInput, setJsonInput] = useState(JSON.stringify(sample));
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [featureCount, setFeatureCount] = useState(sample.length);

  const onInputChange = (value) => {
    setJsonInput(value);
    try {
      const parsed = JSON.parse(value);
      setFeatureCount(Array.isArray(parsed) ? parsed.length : 0);
    } catch {
      setFeatureCount(0);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const parsed = JSON.parse(jsonInput);
      if (!Array.isArray(parsed)) {
        throw new Error("Features must be a JSON array.");
      }
      if (parsed.length === 0) {
        throw new Error("Features array cannot be empty.");
      }
      const response = await detect(parsed);
      setResult(response);
    } catch (err) {
      setError(err.message || "Invalid input or request failed.");
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Manual Threat Detection</h2>
        <p>Provide model features as a JSON array and submit for analysis. Tip: current model expects 77 values.</p>
        <form onSubmit={handleSubmit} className="form">
          <label htmlFor="features">Features JSON</label>
          <textarea id="features" value={jsonInput} onChange={(e) => onInputChange(e.target.value)} rows={9} />
          <div className="inline-row wrap between">
            <span className="muted">Detected feature count: {featureCount}</span>
            <div className="inline-row wrap">
              <button type="button" className="secondary-btn" onClick={() => onInputChange(JSON.stringify(sample))}>
                Load Sample
              </button>
              <button type="button" className="secondary-btn" onClick={() => onInputChange("[]")}>
                Clear
              </button>
            </div>
          </div>
          <button type="submit" disabled={loading}>
            {loading ? "Analyzing..." : "Run Detection"}
          </button>
        </form>
        {error ? <p className="error">{error}</p> : null}
      </div>

      <div className="card">
        <h2>Detection Result</h2>
        {result ? (
          <div className="result">
            <div className="inline-row">
              <span>Attack:</span>
              <StatusPill value={result.attack} />
            </div>
            <p>
              <strong>Explanation:</strong> {result.explanation}
            </p>
            <p>
              <strong>Action:</strong> {result.action}
            </p>
          </div>
        ) : (
          <p>No result yet. Submit features to view analysis.</p>
        )}
      </div>
    </section>
  );
}
