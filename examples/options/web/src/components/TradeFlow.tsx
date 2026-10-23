import { useStore, type LadderRow } from "../state/store";
import { Badge, Button, Card } from "../ui";
import { OutcomePanel } from "./OutcomePanel";
import { EXPIRY_DAYS } from "../lib/options";
import { btcToSats, satsToBtc } from "../lib/pricing";
import { fmtUsd } from "../lib/format";

const DEPOSIT_CHIPS = [0.05, 0.1, 0.25, 0.5];

function StrikeCard({
  row,
  selected,
  onClick,
}: {
  row: LadderRow;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="strike-card"
      style={{
        borderColor: selected ? "var(--ark-lime-600)" : "var(--ark-border)",
        background: selected ? "rgba(200,255,61,0.07)" : "var(--ark-bg)",
        boxShadow: selected ? "0 0 0 1px var(--ark-lime-600)" : "none",
      }}
    >
      <span className="faint" style={{ fontSize: 10 }}>+{Math.round(row.offsetPct * 100)}%</span>
      <span className="mono" style={{ fontSize: 13.5, fontWeight: 650 }}>{fmtUsd(row.strikeUsd)}</span>
      <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: "var(--ark-lime)" }}>
        {row.best.apyPct.toFixed(1)}%
      </span>
      <span className="faint" style={{ fontSize: 9.5, textTransform: "uppercase", letterSpacing: "0.06em" }}>
        APY
      </span>
    </button>
  );
}

export function TradeFlow() {
  const {
    deposit,
    setDeposit,
    spot,
    quoting,
    ladder,
    selectedStrike,
    selectStrike,
    requestQuotes,
    accept,
  } = useStore();

  const selectedRow = ladder?.find((r) => r.strikeUsd === selectedStrike) ?? null;

  return (
    <Card title="Earn yield on your BTC">
      <div className="col" style={{ gap: 16 }}>
        {/* Step 1 — amount */}
        <div className="col" style={{ gap: 10 }}>
          <div className="row between center">
            <span className="ark-label">Deposit</span>
            <Badge tone="cyan">{EXPIRY_DAYS}-day call</Badge>
          </div>
          <div className="row center grow" style={{ gap: 8, background: "var(--ark-bg)", border: "1px solid var(--ark-border)", borderRadius: 9, padding: "8px 12px" }}>
            <input
              aria-label="BTC deposit amount"
              className="grow"
              style={{ background: "transparent", border: "none", outline: "none", color: "var(--ark-text)", fontFamily: "var(--ark-mono)", fontSize: 18, width: "100%" }}
              type="number"
              step={0.01}
              min={0}
              value={Number.isFinite(deposit) ? deposit : ""}
              onChange={(e) => setDeposit(parseFloat(e.target.value))}
            />
            <span className="mono muted">BTC</span>
          </div>
          <div className="row wrap" style={{ gap: 6 }}>
            {DEPOSIT_CHIPS.map((c) => (
              <Button key={c} size="sm" variant={deposit === c ? "primary" : "ghost"} onClick={() => setDeposit(c)}>
                {c} BTC
              </Button>
            ))}
            <span className="grow" />
            <Button variant="primary" onClick={requestQuotes} disabled={quoting}>
              {quoting ? "Requesting…" : ladder ? "Refresh quotes" : "Request quotes"}
            </Button>
          </div>
        </div>

        {quoting && (
          <div className="col center" style={{ gap: 8, padding: "20px 0" }}>
            <div className="rfq-spinner" />
            <span className="faint" style={{ fontSize: 12.5 }}>
              Requesting quotes from market makers…
            </span>
          </div>
        )}

        {/* Step 2 — pick a strike */}
        {ladder && !quoting && (
          <div className="col" style={{ gap: 12 }}>
            <div className="row between center">
              <span className="ark-label">Pick a strike · 5 quotes</span>
              <span className="faint" style={{ fontSize: 11 }}>spot {fmtUsd(spot)}</span>
            </div>
            <div className="strike-grid">
              {ladder.map((row) => (
                <StrikeCard
                  key={row.strikeUsd}
                  row={row}
                  selected={selectedStrike === row.strikeUsd}
                  onClick={() => selectStrike(row.strikeUsd)}
                />
              ))}
            </div>

            {selectedRow && (
              <div className="col" style={{ gap: 12, marginTop: 2 }}>
                {/* RFQ maker breakdown */}
                <div className="col" style={{ gap: 6 }}>
                  <span className="ark-label">Market-maker quotes</span>
                  {selectedRow.quotes.map((q) => {
                    const isBest = q.maker === selectedRow.best.maker;
                    return (
                      <div
                        key={q.maker}
                        className="row between center wrap"
                        style={{
                          gap: 8,
                          padding: "8px 11px",
                          borderRadius: 9,
                          border: `1px solid ${isBest ? "var(--ark-lime-600)" : "var(--ark-border)"}`,
                          background: isBest ? "rgba(200,255,61,0.05)" : "var(--ark-bg)",
                        }}
                      >
                        <div className="row center" style={{ gap: 8 }}>
                          <Badge tone={q.tone}>{q.maker}</Badge>
                          {isBest && <Badge tone="green">BEST</Badge>}
                          <span className="faint" style={{ fontSize: 10.5 }}>IV {Math.round(q.iv * 100)}%</span>
                        </div>
                        <div className="row center" style={{ gap: 12 }}>
                          <span className="mono" style={{ fontSize: 12.5 }}>
                            {satsToBtc(q.premiumSats).toFixed(6)} BTC
                          </span>
                          <span className="mono" style={{ fontSize: 12.5, color: isBest ? "var(--ark-lime)" : "var(--ark-muted)" }}>
                            {q.apyPct.toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Outcome */}
                <OutcomePanel
                  depositSats={btcToSats(deposit)}
                  strikeUsd={selectedRow.strikeUsd}
                  premiumSats={selectedRow.best.premiumSats}
                  spot={spot}
                  expiryDate={Date.now() + EXPIRY_DAYS * 864e5}
                />

                <Button variant="primary" onClick={() => accept(selectedRow)}>
                  Sell {fmtUsd(selectedRow.strikeUsd)} call · earn{" "}
                  {satsToBtc(selectedRow.best.premiumSats).toFixed(6)} BTC ({selectedRow.best.apyPct.toFixed(1)}% APY)
                </Button>
                <span className="faint" style={{ fontSize: 11 }}>
                  Locks {deposit} BTC in an Arkade vault and pays the premium now. Settles in BTC in {EXPIRY_DAYS} days.
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
