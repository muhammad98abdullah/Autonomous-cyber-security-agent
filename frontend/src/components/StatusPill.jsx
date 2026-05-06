export default function StatusPill({ value }) {
  const normalized = String(value || "").toLowerCase();
  const className =
    normalized === "running" || normalized === "normal" ? "ok" : normalized === "attack" ? "danger" : "neutral";

  return <span className={`pill ${className}`}>{value || "Unknown"}</span>;
}
