import { useStore } from "../state/store";
import { Card, Stat } from "../ui";
import { fmtUsd } from "../lib/format";

// BTC spot + implied-vol controls. The spot is the buyer's ITM/OTM oracle (the
// contract has no oracle — exercise is the settlement signal), so it drives every
// position's moneyness badge and payoff marker.
export function MarketBar() {
  const { spot, vol, setSpot, setVol } = useStore();
  return (
    <Card tight>
      <div className="row between center wrap" style={{ gap: 20 }}>
        <Stat k="BTC / USD (spot)" v={fmtUsd(spot)} sub="drag to simulate the market" />
        <div className="grow" style={{ minWidth: 220, maxWidth: 420 }}>
          <input
            className="ark-range"
            type="range"
            min={20000}
            max={250000}
            step={500}
            value={spot}
            onChange={(e) => setSpot(parseFloat(e.target.value))}
            style={{ width: "100%" }}
          />
        </div>
        <div className="row center" style={{ gap: 12 }}>
          <Stat k="Implied vol" v={`${Math.round(vol * 100)}%`} />
          <input
            type="range"
            min={10}
            max={150}
            step={5}
            value={Math.round(vol * 100)}
            onChange={(e) => setVol(parseFloat(e.target.value) / 100)}
            style={{ width: 130 }}
          />
        </div>
      </div>
    </Card>
  );
}
