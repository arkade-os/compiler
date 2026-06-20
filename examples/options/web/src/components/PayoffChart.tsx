import { useMemo } from "react";
import { payoffCurve } from "../lib/pricing";
import { fmtUsd } from "../lib/format";

// Lightweight SVG payoff chart for a covered call. Shows the chosen side's PnL
// across spot, with strike, break-even, and current spot markers.
export function PayoffChart({
  strike,
  premiumUsd,
  notionalBtc,
  spot,
  side,
}: {
  strike: number;
  premiumUsd: number;
  notionalBtc: number;
  spot: number;
  side: "seller" | "buyer";
}) {
  const W = 520;
  const H = 220;
  const pad = { l: 52, r: 16, t: 16, b: 28 };

  const { pts, lo, hi, yMin, yMax } = useMemo(() => {
    const lo = Math.max(1, strike * 0.5);
    const hi = strike * 1.6;
    const pts = payoffCurve(strike, premiumUsd, notionalBtc, [lo, hi], 80);
    const ys = pts.map((p) => (side === "seller" ? p.seller : p.buyer));
    let yMin = Math.min(...ys);
    let yMax = Math.max(...ys);
    const padY = (yMax - yMin) * 0.15 || 1;
    yMin -= padY;
    yMax += padY;
    return { pts, lo, hi, yMin, yMax };
  }, [strike, premiumUsd, notionalBtc, side]);

  const x = (s: number) => pad.l + ((s - lo) / (hi - lo)) * (W - pad.l - pad.r);
  const y = (v: number) => pad.t + (1 - (v - yMin) / (yMax - yMin)) * (H - pad.t - pad.b);

  const line = pts
    .map((p, i) => `${i === 0 ? "M" : "L"}${x(p.spot).toFixed(1)},${y(side === "seller" ? p.seller : p.buyer).toFixed(1)}`)
    .join(" ");

  const zeroY = y(0);
  const color = side === "seller" ? "var(--ark-lime)" : "var(--ark-cyan)";

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="payoff chart">
      {/* zero line */}
      <line x1={pad.l} x2={W - pad.r} y1={zeroY} y2={zeroY} stroke="var(--ark-border)" strokeDasharray="3 4" />
      {/* strike marker */}
      <line x1={x(strike)} x2={x(strike)} y1={pad.t} y2={H - pad.b} stroke="var(--ark-faint)" strokeDasharray="2 4" />
      <text x={x(strike)} y={H - 12} fill="var(--ark-muted)" fontSize="10" textAnchor="middle">
        strike
      </text>
      {/* spot marker */}
      {spot >= lo && spot <= hi && (
        <>
          <line x1={x(spot)} x2={x(spot)} y1={pad.t} y2={H - pad.b} stroke="var(--ark-magenta)" strokeWidth="1.5" opacity="0.7" />
          <text x={x(spot)} y={pad.t + 2} fill="var(--ark-magenta)" fontSize="10" textAnchor="middle">
            spot
          </text>
        </>
      )}
      {/* PnL fill + line */}
      <path d={`${line} L${x(hi)},${zeroY} L${x(lo)},${zeroY} Z`} fill={color} opacity="0.08" />
      <path d={line} fill="none" stroke={color} strokeWidth="2.5" />
      {/* y labels */}
      <text x={pad.l - 8} y={y(yMax) + 4} fill="var(--ark-muted)" fontSize="10" textAnchor="end">
        {fmtUsd(yMax)}
      </text>
      <text x={pad.l - 8} y={zeroY + 4} fill="var(--ark-muted)" fontSize="10" textAnchor="end">
        $0
      </text>
      <text x={pad.l - 8} y={y(yMin) + 4} fill="var(--ark-muted)" fontSize="10" textAnchor="end">
        {fmtUsd(yMin)}
      </text>
    </svg>
  );
}
