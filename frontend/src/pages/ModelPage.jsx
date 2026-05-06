import { useState } from "react";
import { retrainModel } from "../services/api";

export default function ModelPage() {
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleRetrain = async () => {
    setLoading(true);
    const response = await retrainModel();
    setMessage(response.message || "Retraining triggered.");
    setLoading(false);
  };

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Model Management</h2>
        <p>Trigger model retraining and manage datasets.</p>
        <button onClick={handleRetrain} disabled={loading}>
          {loading ? "Queueing..." : "Retrain Model"}
        </button>
        {message ? <p>{message}</p> : null}
      </div>

      <div className="card">
        <h2>Dataset Upload (Placeholder)</h2>
        <input type="file" />
        <p className="muted">Connect this control to a backend upload endpoint when available.</p>
      </div>
    </section>
  );
}
