import { useState } from "react";
import { useStore } from "../state/store";
import { Badge, Button, Card, Segmented } from "../ui";
import type { Position } from "../lib/coveredCall";
import { getVariant, renderAsm } from "../lib/contract";
import { isItm } from "../lib/pricing";
import { fmtUsd, fmtBtc, fmtStable, shortHex, signed } from "../lib/format";
import { stableUnitsToUsd } from "../lib/pricing";
import type { TapleafPath } from "../lib/arkadeScript";

function StatusBadge({ p }: { p: Position }) {
  const tone =
    p.status === "active"
      ? "lime"
      : p.status === "exercised"
        ? "cyan"
        : p.status === "reclaimed"
          ? "amber"
          : "default";
  return <Badge tone={tone as never} dot={p.status === "active"}>{p.status}</Badge>;
}

function Timeline({ p, height }: { p: Position; height: number }) {
  const reclaimH = p.terms.expiryHeight + p.terms.graceBlocks;
  const stage =
    height < p.terms.expiryHeight ? 0 : height < reclaimH ? 1 : 2;
  const items = [
    { label: "Pre-expiry", h: p.createdHeight, active: stage === 0 },
    { label: "Exercise window", h: p.terms.expiryHeight, active: stage === 1 },
    { label: "Reclaim", h: reclaimH, active: stage === 2 },
  ];
  return (
    <div className="row" style={{ gap: 0 }}>
      {items.map((it, i) => (
        <div key={i} className="col grow center" style={{ gap: 4, position: "relative" }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: it.active ? "var(--ark-lime)" : "var(--ark-border)",
              boxShadow: it.active ? "0 0 10px var(--ark-lime)" : "none",
              zIndex: 1,
            }}
          />
          {i < items.length - 1 && (
            <div
              style={{
                position: "absolute",
                top: 4,
                left: "50%",
                width: "100%",
                height: 2,
                background: stage > i ? "var(--ark-lime-600)" : "var(--ark-border)",
              }}
            />
          )}
          <span className="faint" style={{ fontSize: 10 }}>{it.label}</span>
          <span className="mono faint" style={{ fontSize: 10 }}>#{it.h.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

function Inspector({ p }: { p: Position }) {
  const coop = getVariant(p.inst, "exercise", true);
  const exit = getVariant(p.inst, "exercise", false);
  const coopAsm = renderAsm(p.inst, coop, {});
  const exitAsm = renderAsm(p.inst, exit, {});
  return (
    <div className="col" style={{ gap: 10, marginTop: 10 }}>
      <div className="mono faint" style={{ fontSize: 11 }}>
        vault: {p.inst.address}
      </div>
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div className="col" style={{ gap: 4 }}>
          <Badge tone="lime">cooperative tapleaf · virtual</Badge>
          <pre className="mono" style={preStyle}>{coopAsm.join("\n")}</pre>
        </div>
        <div className="col" style={{ gap: 4 }}>
          <Badge tone="cyan">exit tapleaf · onchain + CSV</Badge>
          <pre className="mono" style={preStyle}>{exitAsm.join("\n")}</pre>
        </div>
      </div>
    </div>
  );
}

const preStyle: React.CSSProperties = {
  background: "var(--ark-bg)",
  border: "1px solid var(--ark-border)",
  borderRadius: 8,
  padding: "8px 10px",
  fontSize: 10.5,
  lineHeight: 1.45,
  maxHeight: 200,
  overflow: "auto",
  color: "var(--ark-muted)",
  margin: 0,
};

function PositionCard({ p }: { p: Position }) {
  const { snapshot, spot, exercisePosition, reclaimPosition, transferPosition, user } =
    useStore();
  const height = snapshot.height;
  const [path, setPath] = useState<TapleafPath>(p.chain === "virtual" ? "cooperative" : "exit");
  const [open, setOpen] = useState(false);

  const reclaimH = p.terms.expiryHeight + p.terms.graceBlocks;
  const itm = isItm(spot, p.terms.strikeUsd);
  const intrinsic = Math.max(0, spot - p.terms.strikeUsd) * p.terms.notionalBtc;
  const userIsSeller = p.sellerPk === user.pubkey;
  const userPnl = userIsSeller
    ? p.terms.premiumUsd - intrinsic
    : intrinsic - p.terms.premiumUsd;

  const canTransfer = p.status === "active" && height < p.terms.expiryHeight;
  const canExercise = p.status === "active" && height >= p.terms.expiryHeight;
  const canReclaim = p.status === "active" && height >= reclaimH;

  return (
    <Card>
      <div className="row between center wrap" style={{ gap: 10, marginBottom: 10 }}>
        <div className="row center" style={{ gap: 8 }}>
          <StatusBadge p={p} />
          <Badge tone={p.chain === "virtual" ? "lime" : "cyan"}>
            {p.chain === "virtual" ? "⚡ virtual" : "⛓ onchain"}
          </Badge>
          <Badge tone={itm ? "green" : "amber"}>{itm ? "ITM" : "OTM"}</Badge>
          <span className="muted" style={{ fontSize: 12 }}>
            {p.terms.notionalBtc} BTC @ {fmtUsd(p.terms.strikeUsd)} call
          </span>
        </div>
        <Badge tone={userIsSeller ? "lime" : "cyan"}>
          you: {userIsSeller ? "WRITER" : "HOLDER"}
        </Badge>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 12 }}>
        <MiniStat k="Collateral" v={fmtBtc(p.btcSats)} />
        <MiniStat k="Strike pay" v={fmtStable(p.strikeUnits)} />
        <MiniStat k="Premium" v={fmtUsd(p.terms.premiumUsd)} />
        <MiniStat
          k="Your PnL (mark)"
          v={<span className={userPnl >= 0 ? "up" : "down"}>{signed(userPnl, fmtUsd)}</span>}
        />
      </div>

      <Timeline p={p} height={height} />

      <div className="row between center wrap" style={{ gap: 10, marginTop: 14 }}>
        <div className="row center" style={{ gap: 8 }}>
          <span className="faint" style={{ fontSize: 11 }}>path</span>
          <Segmented
            value={path}
            onChange={setPath}
            tone={path === "cooperative" ? "lime" : "cyan"}
            options={[
              { value: "cooperative", label: "⚡ cooperative" },
              { value: "exit", label: "⛓ exit" },
            ]}
          />
        </div>
        <div className="row center wrap" style={{ gap: 8 }}>
          {canTransfer && (
            <>
              <Button size="sm" onClick={() => transferPosition(p.id, "seller")}>
                Transfer seller
              </Button>
              <Button size="sm" onClick={() => transferPosition(p.id, "buyer")}>
                Transfer buyer
              </Button>
            </>
          )}
          {canExercise && (
            <Button size="sm" variant="primary" onClick={() => exercisePosition(p.id, path)}>
              Exercise ({p.buyerLabel})
            </Button>
          )}
          {canReclaim && (
            <Button size="sm" variant="danger" onClick={() => reclaimPosition(p.id, path)}>
              Reclaim ({p.sellerLabel})
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => setOpen((o) => !o)}>
            {open ? "Hide script" : "Inspect script"}
          </Button>
        </div>
      </div>

      {p.status === "active" && !canExercise && !canReclaim && (
        <div className="faint" style={{ fontSize: 11, marginTop: 8 }}>
          exercise opens at #{p.terms.expiryHeight.toLocaleString()} · reclaim at #
          {reclaimH.toLocaleString()} · {Math.max(0, p.terms.expiryHeight - height)} blocks to expiry
        </div>
      )}

      <div className="faint mono" style={{ fontSize: 10.5, marginTop: 8 }}>
        seller {shortHex(p.sellerPk)} · buyer {shortHex(p.buyerPk)} · intrinsic{" "}
        {fmtUsd(intrinsic)} · strike {fmtUsd(stableUnitsToUsd(p.strikeUnits))}
      </div>

      {open && <Inspector p={p} />}
    </Card>
  );
}

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

export function Positions() {
  const { positions } = useStore();
  if (positions.length === 0) {
    return (
      <Card title="Positions">
        <div className="faint" style={{ padding: "26px 4px", textAlign: "center" }}>
          No open positions. Write or buy a covered call to get started.
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
