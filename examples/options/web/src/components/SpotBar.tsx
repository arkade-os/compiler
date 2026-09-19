import { useStore } from "../state/store";
import { Card } from "../ui";
import { fmtUsd } from "../lib/format";

// BTC spot. There is no oracle in the contract — at expiry the spot decides
// which way a position settles, so this slider is how you simulate the market.
export function SpotBar() {
  const { spot, setSpot } = useStore();
  return (
    <Card tight>
      <div className="row between center wrap" style={{ gap: 18 }}>
        <div className="row center" style={{ gap: 12 }}>
          <span className="ark-logo" style={{ width: 30, height: 30, fontSize: 15 }}>
            ₿
          </span>
          <div className="col" style={{ gap: 1 }}>
            <span className="faint" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.08em" }}>
              BTC / USD · simulated spot
            </span>
            <span className="mono" style={{ fontSize: 22, fontWeight: 600 }}>{fmtUsd(spot)}</span>
          </div>
        </div>
        <input
          className="grow"
          type="range"
          aria-label="Simulated BTC spot price (USD)"
          min={20000}
          max={250000}
          step={500}
          value={spot}
          onChange={(e) => setSpot(parseFloat(e.target.value))}
          style={{ minWidth: 200, maxWidth: 520 }}
        />
      </div>
    </Card>
  );
}
