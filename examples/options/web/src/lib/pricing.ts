// Option pricing & payoff math.
//
// A compact Black-Scholes so the market maker can quote a realistic premium for
// a covered call, plus the covered-call payoff curve the UI charts. Prices are
// in USD; amounts convert to stablecoin base units (6 dp, USDT/USDC-style).

const STABLE_DECIMALS = 6;
export const STABLE_UNIT = 10 ** STABLE_DECIMALS;
export const SATS_PER_BTC = 100_000_000;

/** Standard normal CDF (Abramowitz & Stegun 7.1.26). */
function normCdf(x: number): number {
  const t = 1 / (1 + 0.2316419 * Math.abs(x));
  const d = 0.3989422804014327 * Math.exp(-0.5 * x * x);
  let p =
    d *
    t *
    (0.31938153 +
      t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
  if (x > 0) p = 1 - p;
  return 1 - p;
}

export interface BsParams {
  spot: number; // BTC/USD
  strike: number; // USD
  /** time to expiry in years. */
  t: number;
  /** annualized volatility, e.g. 0.6 = 60%. */
  vol: number;
  /** risk-free rate, annualized. */
  rate?: number;
}

/** Black-Scholes price of a European call, per 1 BTC of notional, in USD. */
export function callPrice({ spot, strike, t, vol, rate = 0 }: BsParams): number {
  if (t <= 0) return Math.max(0, spot - strike);
  const sqrtT = Math.sqrt(t);
  const d1 = (Math.log(spot / strike) + (rate + 0.5 * vol * vol) * t) / (vol * sqrtT);
  const d2 = d1 - vol * sqrtT;
  return spot * normCdf(d1) - strike * Math.exp(-rate * t) * normCdf(d2);
}

/** Premium in USD for `notionalBtc` of a call. */
export function premiumUsd(p: BsParams, notionalBtc: number): number {
  return callPrice(p) * notionalBtc;
}

export function usdToStableUnits(usd: number): number {
  return Math.round(usd * STABLE_UNIT);
}

export function stableUnitsToUsd(units: number): number {
  return units / STABLE_UNIT;
}

export function btcToSats(btc: number): number {
  return Math.round(btc * SATS_PER_BTC);
}

export function satsToBtc(sats: number): number {
  return sats / SATS_PER_BTC;
}

/** Is a call in-the-money at `spot`? */
export function isItm(spot: number, strike: number): boolean {
  return spot > strike;
}

export interface PayoffPoint {
  spot: number;
  /** Seller PnL in USD (covered call writer). */
  seller: number;
  /** Buyer PnL in USD (option holder). */
  buyer: number;
}

/**
 * Covered-call payoff at expiry for both legs, net of premium.
 *  - Seller writes the call, holds BTC. Caps upside at strike, keeps premium.
 *  - Buyer pays premium; profits on the upside above strike.
 */
export function payoffCurve(
  strike: number,
  premiumUsd_: number,
  notionalBtc: number,
  spotRange: [number, number],
  steps = 60,
): PayoffPoint[] {
  const [lo, hi] = spotRange;
  const pts: PayoffPoint[] = [];
  for (let i = 0; i <= steps; i++) {
    const spot = lo + ((hi - lo) * i) / steps;
    const intrinsic = Math.max(0, spot - strike) * notionalBtc;
    // Seller starts long BTC at the strike reference; the covered call caps the
    // BTC appreciation at the strike and adds the premium.
    const seller = premiumUsd_ - intrinsic;
    const buyer = intrinsic - premiumUsd_;
    pts.push({ spot, seller, buyer });
  }
  return pts;
}
