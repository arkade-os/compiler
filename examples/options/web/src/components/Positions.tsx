import { useStore } from "../state/store";
import { Badge, Button, Card } from "../ui";
import { OutcomePanel } from "./OutcomePanel";
import { projectOutcome, BLOCKS_PER_DAY, type Position } from "../lib/options";
import { satsToBtc } from "../lib/pricing";
import { fmtUsd, shortHex } from "../lib/format";

function MiniStat({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="col" style={{ gap: 2 }}>
      <span className="faint" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.07em" }}>
        {k}
      </span>
      <span className="mono" style={{ fontSize: 14 }}>{v}</span>
    </div>
  );
}

function PositionCard({ p }: { p: Position }) {
  const { snapshot, spot, settle } = useStore();
  const height = snapshot.height;
  const matured = height >= p.expiryHeight;
  const blocksLeft = Math.max(0, p.expiryHeight - height);
  const daysLeft = (blocksLeft / BLOCKS_PER_DAY).toFixed(1);
  const proj = projectOutcome(p, spot);
  const liveCalled = proj.live === "called";

  return (
    <Card>
      <div className="row between center wrap" style={{ gap: 8, marginBottom: 12 }}>
        <div className="row center" style={{ gap: 8 }}>
          {p.status === "active" ? (
            <Badge tone="lime" dot>active</Badge>
          ) : (
            <Badge tone={p.outcome?.branch === "called" ? "cyan" : "green"}>settled</Badge>
          )}
          <span style={{ fontWeight: 600, fontSize: 13 }}>{fmtUsd(p.strikeUsd)} call</span>
          <Badge tone="violet">{p.makerName}</Badge>
        </div>
        <Badge tone="green">+{p.apyPct.toFixed(1)}% APY</Badge>
      </div>

      <div className="stat-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", marginBottom: 12 }}>
        <MiniStat k="Deposit" v={`${satsToBtc(p.depositSats).toFixed(4)} BTC`} />
        <MiniStat k="Premium earned" v={<span className="up">+{satsToBtc(p.premiumSats).toFixed(6)}</span>} />
        <MiniStat k="Strike" v={fmtUsd(p.strikeUsd)} />
      </div>

      {p.status === "active" ? (
        <div className="col" style={{ gap: 12 }}>
          <OutcomePanel
            depositSats={p.depositSats}
            strikeUsd={p.strikeUsd}
            premiumSats={p.premiumSats}
            spot={spot}
            expiryDate={p.expiryDate}
          />
          <div className="row between center wrap" style={{ gap: 10 }}>
            <span className="faint" style={{ fontSize: 11.5 }}>
              {matured
                ? "Ready to settle at current spot"
                : `Expires in ${blocksLeft.toLocaleString()} blocks (~${daysLeft}d) · #${p.expiryHeight.toLocaleString()}`}
            </span>
            <Button
              size="sm"
              variant={matured ? "primary" : "ghost"}
              disabled={!matured}
              onClick={() => settle(p.id)}
            >
              {matured ? `Settle → ${liveCalled ? "called away" : "keep BTC"}` : "Settle at expiry"}
            </Button>
          </div>
        </div>
      ) : (
        <div
          className="row between center"
          style={{ padding: "11px 12px", borderRadius: 10, border: "1px solid var(--ark-border)", background: "var(--ark-bg)" }}
        >
          <div className="col" style={{ gap: 2 }}>
            <span style={{ fontSize: 12.5, fontWeight: 600 }}>
              {p.outcome?.branch === "called" ? "Called away at strike" : "Expired worthless — BTC kept"}
            </span>
            <span className="faint" style={{ fontSize: 11 }}>
              spot at settle {fmtUsd(p.outcome?.spotAtSettle ?? 0)}
            </span>
          </div>
          <span className="mono up" style={{ fontSize: 15, fontWeight: 600 }}>
            {satsToBtc((p.outcome?.payoutSats ?? 0) + p.premiumSats).toFixed(4)} BTC
          </span>
        </div>
      )}

      <div className="faint mono mono-wrap" style={{ fontSize: 10.5, marginTop: 10 }}>
        vault {shortHex(p.instance.address, 14)} · compiled from covered_call.ark
      </div>
    </Card>
  );
}

export function Positions() {
  const { positions } = useStore();
  if (positions.length === 0) {
    return (
      <Card title="Your positions">
        <div className="faint" style={{ padding: "24px 4px", textAlign: "center" }}>
          No positions yet. Request quotes and sell a call to start earning.
        </div>
      </Card>
    );
  }
  return (
    <div className="col" style={{ gap: 14 }}>
      {positions.map((p) => (
        <PositionCard key={p.id} p={p} />
      ))}
    </div>
  );
}
