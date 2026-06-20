import { useMemo, useState } from "react";
import { useStore, type OpenForm } from "../state/store";
import { Badge, Button, Card, Field, NumberInput, Segmented, Stat } from "../ui";
import { PayoffChart } from "./PayoffChart";
import { premiumUsd as bsPremium, isItm } from "../lib/pricing";
import { fmtUsd } from "../lib/format";

const BLOCKS_PER_DAY = 144;

// The RFQ trade ticket. The user picks a side (write/buy a covered call), terms,
// and chain; the MM auto-quotes a premium via Black-Scholes. On submit the
// position is funded through the Arkade Script builder on the chosen chain.
export function TradePanel() {
  const { spot, vol, selectedChain, openPosition } = useStore();

  const [side, setSide] = useState<"seller" | "buyer">("seller");
  const [notionalBtc, setNotional] = useState(1);
  const [strikeUsd, setStrike] = useState(110_000);
  const [expiryDays, setExpiryDays] = useState(7);
  const [graceBlocks, setGrace] = useState(144);
  const [exitBlocks, setExit] = useState(144);
  const [autoPremium, setAuto] = useState(true);
  const [manualPremium, setManualPremium] = useState(2000);

  const tYears = (expiryDays * BLOCKS_PER_DAY) / (BLOCKS_PER_DAY * 365);
  const quoted = useMemo(
    () => bsPremium({ spot, strike: strikeUsd, t: tYears, vol }, notionalBtc),
    [spot, strikeUsd, tYears, vol, notionalBtc],
  );
  const premiumUsd = autoPremium ? Math.max(0, quoted) : manualPremium;

  const itm = isItm(spot, strikeUsd);
  const yieldPct = (premiumUsd / (notionalBtc * spot)) * 100;

  const submit = () => {
    const form: OpenForm = {
      side,
      notionalBtc,
      strikeUsd,
      premiumUsd,
      volPct: vol * 100,
      expiryInBlocks: expiryDays * BLOCKS_PER_DAY,
      graceBlocks,
      exitBlocks,
      chain: selectedChain,
    };
    openPosition(form);
  };

  return (
    <Card title="Trade ticket · Covered Call">
      <div className="col" style={{ gap: 14 }}>
        <div className="row between center wrap" style={{ gap: 10 }}>
          <Segmented
            value={side}
            onChange={setSide}
            options={[
              { value: "seller", label: "Write (sell)" },
              { value: "buyer", label: "Buy" },
            ]}
          />
          <Badge tone={itm ? "green" : "amber"} dot>
            {itm ? "ITM" : "OTM"} @ {fmtUsd(spot)}
          </Badge>
        </div>

        <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
          <Field label="Notional (BTC)">
            <NumberInput value={notionalBtc} onChange={setNotional} step={0.1} min={0.01} />
          </Field>
          <Field label="Strike (USD)">
            <NumberInput value={strikeUsd} onChange={setStrike} step={1000} min={1000} />
          </Field>
          <Field label="Expiry (days)" hint={`${expiryDays * BLOCKS_PER_DAY} blocks`}>
            <NumberInput value={expiryDays} onChange={setExpiryDays} step={1} min={1} />
          </Field>
          <Field label="Grace (blocks)" hint="buyer exercise window">
            <NumberInput value={graceBlocks} onChange={setGrace} step={12} min={1} />
          </Field>
          <Field label="Exit timelock (blocks)" hint="CSV on unilateral path">
            <NumberInput value={exitBlocks} onChange={setExit} step={12} min={1} />
          </Field>
          <Field label="Premium (aUSD)" hint={autoPremium ? "Black-Scholes auto-quote" : "manual"}>
            <div className="row center" style={{ gap: 6 }}>
              <NumberInput
                value={autoPremium ? Math.round(premiumUsd) : manualPremium}
                onChange={setManualPremium}
                step={50}
                min={0}
                disabled={autoPremium}
              />
              <Button
                size="sm"
                variant={autoPremium ? "primary" : "ghost"}
                onClick={() => setAuto((a) => !a)}
                title="Toggle auto quote"
              >
                {autoPremium ? "AUTO" : "MANUAL"}
              </Button>
            </div>
          </Field>
        </div>

        <div className="row between wrap" style={{ gap: 14 }}>
          <Stat k="Premium" v={fmtUsd(premiumUsd)} sub={`${yieldPct.toFixed(2)}% of notional`} />
          <Stat k="Strike notional" v={fmtUsd(strikeUsd * notionalBtc)} sub="buyer pays at exercise" />
          <Stat
            k={side === "seller" ? "You collateralize" : "MM collateralizes"}
            v={`${notionalBtc} BTC`}
            sub="single-locked"
          />
        </div>

        <div style={{ borderRadius: 10, background: "var(--ark-bg)", border: "1px solid var(--ark-border)", padding: "8px 4px" }}>
          <PayoffChart
            strike={strikeUsd}
            premiumUsd={premiumUsd}
            notionalBtc={notionalBtc}
            spot={spot}
            side={side}
          />
        </div>

        <Button variant="primary" onClick={submit}>
          {side === "seller" ? "Write covered call" : "Buy covered call"} · {selectedChain}
        </Button>
        <span className="faint" style={{ fontSize: 11.5 }}>
          {side === "seller"
            ? "You lock BTC and receive the premium now. Counterparty: Arkade MM (buyer)."
            : "You pay the premium now. Arkade MM locks the BTC. You may exercise after expiry if ITM."}
        </span>
      </div>
    </Card>
  );
}
