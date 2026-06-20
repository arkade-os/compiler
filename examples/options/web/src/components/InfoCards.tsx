import { useStore } from "../state/store";
import { Badge, Card } from "../ui";
import { STABLE } from "../lib/coveredCall";
import { coveredCallAbi } from "../abi";
import { fmtBtc, fmtStable, shortHex } from "../lib/format";

export function CounterpartiesCard() {
  const { user, maker, operator, emu } = useStore();
  const rows = [
    { w: user, role: "Embedded wallet", tone: "cyan" as const },
    { w: maker, role: "RFQ market maker", tone: "lime" as const },
    { w: operator, role: "Arkade Operator (co-signer)", tone: "amber" as const },
  ];
  return (
    <Card title="Parties">
      <div className="col" style={{ gap: 10 }}>
        {rows.map(({ w, role, tone }) => {
          const b = emu.balance(w.pubkey, STABLE.id);
          return (
            <div key={w.pubkey} className="row between center">
              <div className="col" style={{ gap: 2 }}>
                <div className="row center" style={{ gap: 8 }}>
                  <Badge tone={tone}>{w.label}</Badge>
                  <span className="faint" style={{ fontSize: 11 }}>{role}</span>
                </div>
                <span className="mono faint" style={{ fontSize: 10.5 }}>{shortHex(w.pubkey, 10)}</span>
              </div>
              <div className="col" style={{ gap: 1, alignItems: "flex-end" }}>
                <span className="mono" style={{ fontSize: 11.5 }}>
                  {fmtBtc(b.virtual.sats + b.onchain.sats)}
                </span>
                <span className="mono faint" style={{ fontSize: 10.5 }}>
                  {fmtStable(b.virtual.asset + b.onchain.asset)}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

export function AboutCard() {
  return (
    <Card title="How it works">
      <div className="col muted" style={{ gap: 9, fontSize: 12.5 }}>
        <p style={{ margin: 0 }}>
          A Bitcoin-native, single-locked, physically-settled European covered call —
          faithful to Rysk. The <b style={{ color: "var(--ark-text)" }}>writer locks BTC</b>;
          the <b style={{ color: "var(--ark-text)" }}>holder brings the strike</b> in
          {" "}{STABLE.symbol} only if they exercise in the money.
        </p>
        <p style={{ margin: 0 }}>
          Every function compiles to two tapleaves:
          <Badge tone="lime">cooperative</Badge> settles instantly on the
          {" "}<b style={{ color: "var(--ark-text)" }}>virtual</b> chain with the Operator
          co-signature; <Badge tone="cyan">exit</Badge> is a unilateral
          {" "}<b style={{ color: "var(--ark-text)" }}>onchain</b> N-of-N path that matures
          after the CSV <span className="kbd">exit</span> delay.
        </p>
        <p style={{ margin: 0 }}>
          The contract has <b style={{ color: "var(--ark-text)" }}>no oracle</b> — the
          holder's exercise decision is the settlement signal. Drag the spot price to flip
          moneyness, then mine blocks to cross expiry.
        </p>
        <div className="faint mono" style={{ fontSize: 10.5, marginTop: 2 }}>
          ABI: {coveredCallAbi.contractName} · {coveredCallAbi.compiler.name}@
          {coveredCallAbi.compiler.version} · {coveredCallAbi.functions.length} tapleaves
        </div>
      </div>
    </Card>
  );
}
