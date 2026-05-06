export default function StatCard({ title, value, subtitle }) {
  return (
    <div className="card stat-card">
      <p className="stat-title">{title}</p>
      <h3 className="stat-value">{value}</h3>
      <p className="stat-subtitle">{subtitle}</p>
    </div>
  );
}
