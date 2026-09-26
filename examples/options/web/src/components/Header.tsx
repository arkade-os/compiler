import { useStore } from "../state/store";
import { Badge, Button, Logo } from "../ui";
import { fmtBtc, shortHex } from "../lib/format";

export function Header() {
  const { user, emu, snapshot, mine, faucet, reset } = useStore();
  const sats = emu.balance(user.pubkey).virtual.sats;

  return (
    <header className="row between center wrap" style={{ gap: 12, marginBottom: 18 }}>
      <Logo />
      <div className="row center wrap" style={{ gap: 10 }}>
        <Badge tone="lime" dot>
          block {snapshot.height.toLocaleString()}
        </Badge>
        <Button size="sm" onClick={() => mine(1)} title="Advance 1 block">
          ⛏ +1
        </Button>
        <Button size="sm" onClick={() => mine(10)}>
          +10
        </Button>
        <div
          className="row center"
          style={{
            gap: 10,
            padding: "7px 12px",
            border: "1px solid var(--ark-border)",
            borderRadius: 10,
            background: "var(--ark-surface)",
          }}
        >
          <div className="col" style={{ gap: 1 }}>
            <span className="faint" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              Wallet
            </span>
            <span className="mono" style={{ fontSize: 13 }}>{fmtBtc(sats)}</span>
          </div>
          <Badge tone="cyan">{shortHex(user.pubkey)}</Badge>
        </div>
        <Button size="sm" onClick={faucet} title="Add test BTC">
          💧
        </Button>
        <Button size="sm" variant="ghost" onClick={reset} title="New wallet">
          ↻
        </Button>
      </div>
    </header>
  );
}
