import { satsToBtc } from "../lib/pricing";
import { fmtUsd } from "../lib/format";

// Plain-language settlement preview: what you walk away with at expiry, in BTC,
// for each side of the strike. The branch the current spot points to is lit up.
export function OutcomePanel({
  depositSats,
  strikeUsd,
  premiumSats,
  spot,
  expiryDate,
}: {
  depositSats: number;
  strikeUsd: number;
  premiumSats: number;
  spot: number;
  expiryDate: number;
}) {
  const deposit = satsToBtc(depositSats);
  const premium = satsToBtc(premiumSats);
  const calledBtc = Math.min(deposit, (deposit * strikeUsd) / spot);
  const live: "below" | "above" = spot > strikeUsd ? "above" : "below";

  const date = new Date(expiryDate).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  const Row = ({
    side,
    cond,
    total,
    note,
  }: {
    side: "below" | "above";
    cond: string;
    total: number;
    note: string;
  }) => {
    const on = live === side;
    return (
      <div
        className="row between center"
        style={{
          padding: "11px 12px",
          borderRadius: 10,
          border: `1px solid ${on ? "var(--ark-lime-600)" : "var(--ark-border)"}`,
          background: on ? "rgba(200,255,61,0.06)" : "var(--ark-bg)",
        }}
      >
        <div className="col" style={{ gap: 2, minWidth: 0, flex: 1 }}>
          <span style={{ fontSize: 12.5, fontWeight: 600 }}>{cond}</span>
          <span className="faint" style={{ fontSize: 11 }}>{note}</span>
        </div>
        <div className="col" style={{ gap: 0, alignItems: "flex-end", flexShrink: 0 }}>
          <span className="mono" style={{ fontSize: 15, fontWeight: 600, color: on ? "var(--ark-lime)" : "var(--ark-text)" }}>
            {total.toFixed(4)} BTC
          </span>
          {on && <span className="faint" style={{ fontSize: 10 }}>← at current spot</span>}
        </div>
      </div>
    );
  };

  return (
    <div className="col" style={{ gap: 8 }}>
      <span className="faint" style={{ fontSize: 11.5 }}>
        On <b style={{ color: "var(--ark-text)" }}>{date}</b> (expiry), you receive:
      </span>
      <Row
        side="below"
        cond={`If BTC < ${fmtUsd(strikeUsd)}`}
        total={deposit + premium}
        note={`keep ${deposit.toFixed(4)} BTC + ${premium.toFixed(6)} premium`}
      />
      <Row
        side="above"
        cond={`If BTC ≥ ${fmtUsd(strikeUsd)}`}
        total={calledBtc + premium}
        note={`called away at strike + ${premium.toFixed(6)} premium`}
      />
    </div>
  );
}
