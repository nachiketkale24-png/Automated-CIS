import {
  ShieldCheck,
  Server,
  ShieldAlert,
  Layers3,
  ArrowUpRight,
} from "lucide-react";

const icons = {
  ShieldCheck,
  Server,
  ShieldAlert,
  Layers3,
};

export default function MetricCard({ metric }) {
  const Icon = icons[metric.icon] || ShieldCheck;
  const featured = metric.label === "Compliance score";

  return (
    <article className={`metric-card ${featured ? "metric-card-featured" : ""}`}>
      <div className={`metric-icon tone-${metric.tone}`}>
        <Icon size={20} />
      </div>

      <div className="metric-copy">
        <p className="metric-label">{metric.label}</p>
        <div className="metric-value">{metric.value}</div>
        <p className="metric-detail">{metric.detail}</p>
      </div>

      <ArrowUpRight className="metric-arrow" size={17} />
    </article>
  );
}