import { useStore } from "../state/store";
import { Badge, Button, Logo, Segmented } from "../ui";
import { STABLE } from "../lib/coveredCall";
import { fmtBtc, fmtStable, shortHex } from "../lib/format";

export function Header() {
  const {
    user,
    emu,
    snapshot,
    selectedChain,
    selectChain,
    mine,
    faucet,
    resetWallet,
  } = useStore();

  const bal = emu.balance(user.pubkey, STABLE.id);
  const chainBal = bal[selectedChain];
  const pending = snapshot.txs.filter((t) => t.status === "pending").length;

  return (
    <header className="col" style={{ gap: 16, marginBottom: 18 }}>
      <div className="row between center wrap" style={{ gap: 12 }}>
        <Logo />
        <div className="row center wrap" style={{ gap: 10 }}>
          <Badge tone="lime" dot>
            block {snapshot.height.toLocaleString()}
          </Badge>
          {pending > 0 && <Badge tone="amber" dot>{pending} mempool</Badge>}
          <Button size="sm" onClick={() => mine(1)} title="Mine 1 block">
            ⛏ +1
          </Button>
          <Button size="sm" onClick={() => mine(10)}>
            +10
          </Button>
        </div>
      </div>

      <div className="row between center wrap" style={{ gap: 12 }}>
        <Segmented
          value={selectedChain}
          onChange={(c) => selectChain(c)}
          tone={selectedChain === "virtual" ? "lime" : "cyan"}
          options={[
            { value: "virtual", label: "⚡ Virtual (Ark)" },
            { value: "onchain", label: "⛓ Onchain (L1)" },
          ]}
        />

        <div className="row center wrap" style={{ gap: 10 }}>
          <div
            className="row center"
            style={{
              gap: 12,
              padding: "8px 14px",
              border: "1px solid var(--ark-border)",
              borderRadius: 10,
              background: "var(--ark-surface)",
            }}
          >
            <div className="col" style={{ gap: 1 }}>
              <span className="faint" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Embedded wallet · {selectedChain}
              </span>
              <span className="mono" style={{ fontSize: 12.5 }}>
                {fmtBtc(chainBal.sats)} · {fmtStable(chainBal.asset)}
              </span>
            </div>
            <Badge tone="cyan">{shortHex(user.pubkey)}</Badge>
          </div>
          <Button size="sm" onClick={faucet} title={`Fund wallet on ${selectedChain}`}>
            💧 Faucet
          </Button>
          <Button size="sm" variant="ghost" onClick={resetWallet} title="Generate a fresh key">
            ↻
          </Button>
        </div>
      </div>
    </header>
  );
}
