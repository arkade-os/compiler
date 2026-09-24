// Simulated RFQ. Three desks quote a Black-Scholes premium, r = 0.
// A covered call is priced as a vanilla call. A limited put is priced as a
// put spread struck at K and K/2, which matches the payoff until the cap.
// The quote is in USD, then converted to sats at the spot used for the request.

const DESKS = [
  { name: "Northbridge", vol: 0.48 },
  { name: "Harbor", vol: 0.55 },
  { name: "Kestrel", vol: 0.62 },
];

function erf(x) {
  const sign = x < 0 ? -1 : 1;
  const a = Math.abs(x);
  const t = 1 / (1 + 0.3275911 * a);
  const y = 1 - (((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t) * Math.exp(-a * a);
  return sign * y;
}

function normCdf(x) {
  return 0.5 * (1 + erf(x / Math.SQRT2));
}

export function bsCall(spot, strike, years, vol) {
  if (years <= 0 || vol <= 0 || spot <= 0 || strike <= 0) return Math.max(0, spot - strike);
  const s = vol * Math.sqrt(years);
  const d1 = (Math.log(spot / strike) + (0.5 * vol * vol * years)) / s;
  const d2 = d1 - s;
  return spot * normCdf(d1) - strike * normCdf(d2);
}

export function bsPut(spot, strike, years, vol) {
  return bsCall(spot, strike, years, vol) - spot + strike;
}

export function deskQuotes({ kind, spotCents, strikeCents, years, collateralSats }) {
  const spot = spotCents / 100;
  const strike = strikeCents / 100;
  const notional = Number(collateralSats) / 1e8;
  return DESKS.map((desk) => {
    const usd = kind === 0
      ? bsCall(spot, strike, years, desk.vol) * notional
      : Math.max(0, bsPut(spot, strike, years, desk.vol) - bsPut(spot, strike / 2, years, desk.vol)) * notional;
    const sats = BigInt(Math.max(0, Math.round((usd / spot) * 1e8)));
    return { name: desk.name, vol: desk.vol, usd, sats };
  });
}

export function bestQuote(rows, side) {
  return rows.reduce((best, row) => {
    if (side === 0) return row.sats > best.sats ? row : best;
    return row.sats < best.sats ? row : best;
  });
}
