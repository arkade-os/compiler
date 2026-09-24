// Integer settlement for OptionVault. Branch order matches option_vault.ark.
// Prices are USD cents. Notional, premium, and payoffs are sats.
// Division truncates toward zero, same as the covenant's OP_DIV.

export const DUST = 330n;
export const PRICE_MAX = 1_000_000_000n;
export const Q_MAX = 1_000_000_000n;
export const Q_MIN = 10_000n;

const TICKER = [0x42, 0x54, 0x43, 0x55, 0x53, 0x44];

export function median3(a, b, c) {
  if (a <= b && b <= c) return b;
  if (a <= c && c <= b) return c;
  if (b <= a && a <= c) return a;
  if (b <= c && c <= a) return c;
  if (c <= a && a <= b) return a;
  return b;
}

export function max3(a, b, c) {
  if (a >= b && a >= c) return a;
  if (b >= a && b >= c) return b;
  return c;
}

export function min3(a, b, c) {
  if (a <= b && a <= c) return a;
  if (b <= a && b <= c) return b;
  return c;
}

export function sliceError(times, lo, hi) {
  const top = max3(times[0], times[1], times[2]);
  const bot = min3(times[0], times[1], times[2]);
  if (top - bot > 60n) return "oracle spread";
  if (top < lo) return "slice early";
  if (top > hi) return "slice late";
  return null;
}

export function windows(expiry) {
  return {
    open: [expiry - 1800n, expiry - 1740n],
    mid: [expiry - 960n, expiry - 900n],
    close: [expiry, expiry + 60n],
  };
}

export function distinct(ids) {
  return ids[0] !== ids[1] && ids[0] !== ids[2] && ids[1] !== ids[2];
}

export function twap(m0, m1, m2) {
  return (m0 * 900n + m1 * 900n + m2 * 60n) / 1860n;
}

export function holderPayoff(kind, settlement, strike, collateral) {
  let ph = 0n;
  if (kind === 0 && settlement > strike) {
    ph = (collateral * (settlement - strike)) / settlement;
  }
  if (kind === 1 && settlement < strike) {
    ph = (collateral * (strike - settlement)) / settlement;
    if (ph > collateral) ph = collateral;
  }
  return ph;
}

// Mirrors the vault's output rules. A holder leg at or below dust pays the
// whole coin to the writer, including when the writer leg is dust too.
export function settlementOutputs(ph, locked) {
  const writerAmt = locked - ph;
  if (ph > DUST && writerAmt > DUST) {
    return { mode: "split", holder: ph, writer: writerAmt };
  }
  if (ph <= DUST) return { mode: "writer", holder: 0n, writer: locked };
  return { mode: "holder", holder: locked, writer: 0n };
}

export function oraclePreimage(price, time) {
  const out = new Uint8Array(22);
  out.set(TICKER, 0);
  const view = new DataView(out.buffer);
  view.setBigUint64(6, price, true);
  view.setBigUint64(14, time, true);
  return out;
}

export function settle(position, slices) {
  if (position.collateral < Q_MIN || position.collateral > Q_MAX) {
    return { error: "collateral" };
  }
  if (position.strike <= 0n || position.strike > PRICE_MAX) return { error: "strike" };
  const names = ["open", "mid", "close"];
  const bounds = windows(position.expiry);
  const medians = [];
  for (let i = 0; i < 3; i += 1) {
    const slice = slices[i];
    if (!distinct(slice.who)) return { error: "same oracle" };
    const bad = sliceError(slice.time, bounds[names[i]][0], bounds[names[i]][1]);
    if (bad) return { error: bad };
    for (const price of slice.price) {
      if (price <= 0n || price > PRICE_MAX) return { error: "price" };
    }
    medians.push(median3(slice.price[0], slice.price[1], slice.price[2]));
  }
  const settlement = twap(medians[0], medians[1], medians[2]);
  if (settlement <= 0n) return { error: "zero twap" };
  const ph = holderPayoff(position.kind, settlement, position.strike, position.collateral);
  const outputs = settlementOutputs(ph, position.collateral);
  return { settlement, medians, ph, outputs };
}
