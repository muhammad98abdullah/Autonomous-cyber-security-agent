import { useEffect, useState } from "react";
import { DEFAULT_SETTINGS } from "../config";

const STORAGE_KEY = "astra-settings";

export default function SettingsPage() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved, setSaved] = useState(false);
  const [saveTime, setSaveTime] = useState("");

  useEffect(() => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      setSettings({ ...DEFAULT_SETTINGS, ...JSON.parse(raw) });
    }
  }, []);

  const update = (key, value) => {
    setSaved(false);
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

  const save = (event) => {
    event.preventDefault();
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
    setSaved(true);
    setSaveTime(new Date().toLocaleTimeString());
  };

  return (
    <section className="page-grid">
      <div className="card">
        <h2>Settings</h2>
        <form className="form" onSubmit={save}>
          <label>
            <input
              type="checkbox"
              checked={settings.autoResponseEnabled}
              onChange={(e) => update("autoResponseEnabled", e.target.checked)}
            />
            Enable automated responses
          </label>

          <label htmlFor="threshold">Detection threshold ({settings.detectionThreshold})</label>
          <input
            id="threshold"
            type="range"
            min="0.1"
            max="1"
            step="0.05"
            value={settings.detectionThreshold}
            onChange={(e) => update("detectionThreshold", Number(e.target.value))}
          />

          <label htmlFor="email">Notification email</label>
          <input id="email" value={settings.notificationEmail} onChange={(e) => update("notificationEmail", e.target.value)} />

          <label htmlFor="api-key">API key</label>
          <input id="api-key" value={settings.apiKey} onChange={(e) => update("apiKey", e.target.value)} />

          <button type="submit">Save Settings</button>
          {saved ? <p className="success">Saved locally at {saveTime}.</p> : null}
        </form>
      </div>
    </section>
  );
}
