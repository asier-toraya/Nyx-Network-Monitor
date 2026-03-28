interface SummaryCardProps {
  label: string;
  value: number;
  tone: "safe" | "unknown" | "suspicious" | "neutral";
  detail: string;
  active?: boolean;
  onClick?: () => void;
}

export function SummaryCard({
  label,
  value,
  tone,
  detail,
  active = false,
  onClick
}: SummaryCardProps) {
  const className = `summary-card tone-${tone} ${active ? "is-active" : ""}`;

  if (onClick) {
    return (
      <button type="button" className={className} onClick={onClick}>
        <div className="summary-card__heading">
          <p className="summary-card__label">{label}</p>
          {active ? <span className="summary-card__flag">Filtered</span> : null}
        </div>
        <strong>{value}</strong>
        <p className="summary-card__detail">{detail}</p>
      </button>
    );
  }

  return (
    <article className={className}>
      <div className="summary-card__heading">
        <p className="summary-card__label">{label}</p>
      </div>
      <strong>{value}</strong>
      <p className="summary-card__detail">{detail}</p>
    </article>
  );
}
