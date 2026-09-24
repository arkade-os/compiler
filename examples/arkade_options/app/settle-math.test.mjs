import assert from "node:assert/strict";
import test from "node:test";
import { bestQuote, bsCall, deskQuotes } from "./quote.js";
import {
  holderPayoff,
  median3,
  oraclePreimage,
  settle,
  settlementOutputs,
  sliceError,
  twap,
  windows,
} from "./settle-math.js";

test("median matches the six orderings and ties", () => {
  assert.equal(median3(1n, 2n, 3n), 2n);
  assert.equal(median3(1n, 3n, 2n), 2n);
  assert.equal(median3(2n, 1n, 3n), 2n);
  assert.equal(median3(3n, 1n, 2n), 2n);
  assert.equal(median3(2n, 3n, 1n), 2n);
  assert.equal(median3(3n, 2n, 1n), 2n);
  assert.equal(median3(5n, 5n, 1n), 5n);
  assert.equal(median3(9n, 1n, 9n), 9n);
});

test("twap weights the settlement minute at 60 seconds", () => {
  assert.equal(twap(100n, 200n, 160n), 150n);
  assert.equal(twap(20_000n, 20_000n, 20_000n), 20_000n);
});

test("covered call and limited put payoffs", () => {
  const q = 100_000n;
  assert.equal(holderPayoff(0, 20_000n, 10_000n, q), 50_000n);
  assert.equal(holderPayoff(0, 10_000n, 10_000n, q), 0n);
  assert.equal(holderPayoff(1, 8_000n, 10_000n, q), 25_000n);
  assert.equal(holderPayoff(1, 4_000n, 10_000n, q), q);
  assert.equal(holderPayoff(1, 10_000n, 10_000n, q), 0n);
});

test("dust folds the small leg into the other output", () => {
  assert.deepEqual(settlementOutputs(50_000n, 100_000n), { mode: "split", holder: 50_000n, writer: 50_000n });
  assert.deepEqual(settlementOutputs(200n, 100_000n), { mode: "writer", holder: 0n, writer: 100_000n });
  assert.deepEqual(settlementOutputs(100_000n, 100_000n), { mode: "holder", holder: 100_000n, writer: 0n });
  assert.deepEqual(settlementOutputs(200n, 400n), { mode: "writer", holder: 0n, writer: 400n });
});

test("sample times used by the desk sit inside each slice", () => {
  const expiry = 10_000n;
  for (const [lo, hi] of Object.values(windows(expiry))) {
    assert.equal(sliceError([lo + 20n, lo + 30n, lo + 40n], lo, hi), null);
  }
  assert.equal(sliceError([10n, 20n, 70n], 0n, 100n), null);
  assert.equal(sliceError([10n, 20n, 71n], 0n, 100n), "oracle spread");
  assert.equal(sliceError([10n, 20n, 30n], 40n, 100n), "slice early");
});

test("oracle preimage is ticker plus two little-endian int64s", () => {
  const bytes = oraclePreimage(1n, 2n);
  assert.equal(bytes.length, 22);
  assert.equal(Buffer.from(bytes.subarray(0, 6)).toString("ascii"), "BTCUSD");
  assert.equal(bytes[6], 1);
  assert.equal(bytes[14], 2);
  assert.equal(bytes[21], 0);
});

test("settle drops one dishonest print and pays the call", () => {
  const expiry = 10_000n;
  const position = { kind: 0, strike: 10_000n, collateral: 100_000n, expiry };
  const honest = (base, who, times) => ({
    price: [base - 5n, base, base + 5n],
    time: times,
    who,
  });
  const slices = [
    honest(20_000n, [0n, 1n, 2n], [expiry - 1780n, expiry - 1770n, expiry - 1760n]),
    honest(20_000n, [1n, 2n, 3n], [expiry - 940n, expiry - 930n, expiry - 920n]),
    honest(20_000n, [2n, 3n, 4n], [expiry + 10n, expiry + 20n, expiry + 30n]),
  ];
  slices[1].price[2] = 80_000n;
  const result = settle(position, slices);
  assert.equal(result.medians[1], 20_000n);
  assert.equal(result.settlement, 20_000n);
  assert.equal(result.outputs.holder, 50_000n);
  assert.equal(result.outputs.writer, 50_000n);
});

test("black-scholes call is near the known one-year value", () => {
  const px = bsCall(100, 100, 1, 0.2);
  assert.ok(Math.abs(px - 7.9656) < 0.02, px);
});

test("the highest vol desk wins a covered-call auction", () => {
  const rows = deskQuotes({
    kind: 0,
    spotCents: 10_000_000,
    strikeCents: 11_000_000,
    years: 30 / 365,
    collateralSats: 10_000_000n,
  });
  assert.equal(bestQuote(rows, 0).name, "Kestrel");
  assert.equal(bestQuote(rows, 1).name, "Northbridge");
  assert.ok(rows.every((row) => row.sats > 331n));
});
