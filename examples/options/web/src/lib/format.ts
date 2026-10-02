import { satsToBtc, stableUnitsToUsd } from "./pricing";

export function fmtUsd(n: number, dp = 0): string {
  return n.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: dp,
    maximumFractionDigits: dp,
  });
}

export function fmtNum(n: number, dp = 0): string {
  return n.toLocaleString("en-US", { minimumFractionDigits: dp, maximumFractionDigits: dp });
}

export function fmtBtc(sats: number): string {
  const btc = satsToBtc(sats);
  return `${btc.toFixed(btc < 1 ? 4 : 3)} BTC`;
}

export function fmtSats(sats: number): string {
  return `${sats.toLocaleString("en-US")} sats`;
}

export function fmtStable(units: number): string {
  return `${stableUnitsToUsd(units).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })} aUSD`;
}

export function shortHex(h: string, n = 6): string {
  if (h.length <= n * 2 + 1) return h;
  return `${h.slice(0, n)}…${h.slice(-4)}`;
}

export function signed(n: number, fmt: (x: number) => string): string {
  return (n >= 0 ? "+" : "") + fmt(n);
}
