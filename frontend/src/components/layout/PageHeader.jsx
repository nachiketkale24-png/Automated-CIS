import { ArrowUpRight } from "lucide-react";

export default function PageHeader({
  eyebrow = "CISGUARD WORKSPACE",
  title,
  description,
  actionLabel,
  onAction,
}) {
  return (
    <div className="page-header">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>

      {actionLabel && (
        <button className="primary-button" onClick={onAction}>
          {actionLabel}
          <ArrowUpRight size={17} />
        </button>
      )}
    </div>
  );
}