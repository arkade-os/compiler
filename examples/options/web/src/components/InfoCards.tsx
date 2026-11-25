import { Card, Badge } from "../ui";
import { coveredCallAbi } from "../abi";

export function AboutCard() {
  return (
    <Card title="How it works">
      <div className="col muted" style={{ gap: 9, fontSize: 12.5 }}>
        <p style={{ margin: 0 }}>
          Sell a <b style={{ color: "var(--ark-text)" }}>covered call</b> on your BTC. You
          deposit BTC, a market maker pays you a premium now, and at expiry it settles in
          BTC — no stablecoins, no oracle.
        </p>
        <p style={{ margin: 0 }}>
          <b style={{ color: "var(--ark-text)" }}>Request quotes</b> and five market makers
          price the same option off their own vol. You take the best. If BTC stays
          <b style={{ color: "var(--ark-text)" }}> below</b> the strike at expiry you keep all
          your BTC plus the premium; <b style={{ color: "var(--ark-text)" }}>above</b> it your
          BTC is sold at the strike — capped upside, premium kept either way.
        </p>
        <p style={{ margin: 0 }}>
          Settlement runs on Arkade, which treats an on-chain{" "}
          <Badge tone="lime">UTXO</Badge> and a <Badge tone="cyan">virtual UTXO</Badge> the
          same way — so there is nothing to bridge or choose. Drag the spot to see how it
          would resolve, then mine blocks to reach expiry.
        </p>
        <div className="faint mono" style={{ fontSize: 10.5 }}>
          vault: compiled {coveredCallAbi.contractName} · {coveredCallAbi.compiler.name}@
          {coveredCallAbi.compiler.version}
        </div>
      </div>
    </Card>
  );
}
