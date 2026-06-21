import "./polyfill";
import { useStore } from "../src/state/store";
import { btcToSats, satsToBtc } from "../src/lib/pricing";

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) failures++;
  console.log(`[${cond ? "PASS" : "FAIL"}] ${name}${extra !== undefined ? ` :: ${JSON.stringify(extra)}` : ""}`);
}
const S = () => useStore.getState();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // ----- RFQ + open -----
  S().setDeposit(0.1);
  S().setExpiry(14);
  S().requestQuotes();
  await sleep(1000);
  const ladder = S().ladder;
  check("RFQ returned 5 strikes", !!ladder && ladder.length === 5, ladder?.length);
  check("each strike has 4 maker quotes", !!ladder && ladder.every((r) => r.quotes.length === 4));
  check("a strike is auto-selected", S().selectedStrike !== null);
  check("best quote has positive premium", !!ladder && ladder[0].best.premiumSats > 0, ladder?.[0].best.premiumSats);

  const userPk = S().user.pubkey;
  const balBefore = S().emu.balance(userPk).virtual.sats;
  const row = ladder!.find((r) => r.strikeUsd === S().selectedStrike)!;
  S().accept(row);
  check("position opened", S().positions.length === 1, S().toast);
  const pos = S().positions[0];
  check("status active + premium > 0", pos.status === "active" && pos.premiumSats > 0);
  const balAfterOpen = S().emu.balance(userPk).virtual.sats;
  check(
    "deposit locked, premium received (net = premium - deposit)",
    balAfterOpen - balBefore === pos.premiumSats - pos.depositSats,
    { delta: balAfterOpen - balBefore },
  );

  // ----- settle KEPT (spot below strike) -----
  S().setSpot(pos.strikeUsd - 10_000);
  S().mine(pos.expiryHeight - S().emu.height + 1);
  const balPreSettle = S().emu.balance(userPk).virtual.sats;
  S().settle(pos.id);
  const settled = S().positions[0];
  check("settled kept branch", settled.outcome?.branch === "kept", settled.outcome);
  check("kept payout = full deposit", settled.outcome?.payoutSats === pos.depositSats);
  const balPostSettle = S().emu.balance(userPk).virtual.sats;
  check("deposit returned in full", balPostSettle - balPreSettle === pos.depositSats, {
    delta: balPostSettle - balPreSettle,
  });

  // ----- settle CALLED (spot above strike) -----
  S().setSpot(100_000);
  S().requestQuotes();
  await sleep(1000);
  const row2 = S().ladder!.find((r) => r.strikeUsd === S().selectedStrike)!;
  S().accept(row2);
  const pos2 = S().positions[0];
  const spotAbove = pos2.strikeUsd + 40_000;
  S().setSpot(spotAbove);
  S().mine(pos2.expiryHeight - S().emu.height + 1);
  const makerPk = S().maker.pubkey;
  const makerBefore = S().emu.balance(makerPk).virtual.sats;
  S().settle(pos2.id);
  const s2 = S().positions[0];
  const expectedCalled = Math.floor((pos2.depositSats * pos2.strikeUsd) / spotAbove);
  check("settled called branch", s2.outcome?.branch === "called", s2.outcome);
  check("called payout = deposit*strike/spot (capped)", s2.outcome?.payoutSats === expectedCalled, {
    payout: s2.outcome?.payoutSats,
    expectedCalled,
  });
  check("called payout < deposit", (s2.outcome?.payoutSats ?? 0) < pos2.depositSats);
  const makerAfter = S().emu.balance(makerPk).virtual.sats;
  check(
    "BTC conserved: writer share + maker remainder = deposit",
    expectedCalled + (makerAfter - makerBefore) === pos2.depositSats,
    { writer: expectedCalled, maker: makerAfter - makerBefore, deposit: pos2.depositSats },
  );

  console.log(`\nuser balance now ${satsToBtc(S().emu.balance(userPk).virtual.sats).toFixed(6)} BTC`);
  void btcToSats;
  console.log(failures === 0 ? "ALL GREEN" : `${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
