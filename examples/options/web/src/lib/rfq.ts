// Simulated RFQ (request-for-quote), Rysk-style.
//
// The writer asks the desk for a price; several market makers each return a
// premium for the same option. They disagree slightly because each prices off
// its own implied vol and takes a different edge — so the writer gets a spread
// of quotes and picks the best (highest premium). Premiums are quoted and paid
// in BTC.
import { callPrice } from "./pricing";

export interface Maker {
  name: string;
  iv: number; // the maker's implied-vol view
  edge: number; // the maker's margin (fraction of fair value it keeps)
  tone: "lime" | "cyan" | "violet" | "amber";
}

// A small desk of recognizable-style names. Cosmetic — the on-ledger
// counterparty is a single pooled maker wallet.
export const MAKERS: Maker[] = [
  { name: "Galaxy", iv: 0.58, edge: 0.07, tone: "lime" },
  { name: "Wintermute", iv: 0.63, edge: 0.05, tone: "cyan" },
  { name: "B2C2", iv: 0.60, edge: 0.08, tone: "violet" },
  { name: "Cumberland", iv: 0.65, edge: 0.045, tone: "amber" },
];

export interface Quote {
  maker: string;
  tone: Maker["tone"];
  iv: number;
  premiumUsd: number;
  premiumSats: number;
  apyPct: number;
}

export interface RfqParams {
  spot: number;
  strikeUsd: number;
  depositBtc: number;
  days: number;
}

export function quoteFromMaker(m: Maker, p: RfqParams): Quote {
  const t = p.days / 365;
  const fairUsd = callPrice({ spot: p.spot, strike: p.strikeUsd, t, vol: m.iv }) * p.depositBtc;
  const jitter = 1 + (Math.random() - 0.5) * 0.05;
  const premiumUsd = Math.max(0, fairUsd * (1 - m.edge) * jitter);
  const premiumSats = Math.round((premiumUsd / p.spot) * 1e8);
  const apyPct =
    p.depositBtc > 0 ? (premiumUsd / (p.depositBtc * p.spot)) * (365 / p.days) * 100 : 0;
  return { maker: m.name, tone: m.tone, iv: m.iv, premiumUsd, premiumSats, apyPct };
}

/** Quotes from every maker for one strike, best first. */
export function runRfq(p: RfqParams): Quote[] {
  return MAKERS.map((m) => quoteFromMaker(m, p)).sort((a, b) => b.premiumSats - a.premiumSats);
}

export function bestQuote(quotes: Quote[]): Quote {
  return quotes.reduce((a, b) => (b.premiumSats > a.premiumSats ? b : a));
}
