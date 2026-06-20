import "./polyfill";
import { useStore } from "../src/state/store";
import { STABLE } from "../src/lib/coveredCall";
import { usdToStableUnits, btcToSats } from "../src/lib/pricing";

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  const tag = cond ? "PASS" : "FAIL";
  if (!cond) failures++;
  console.log(`[${tag}] ${name}${extra !== undefined ? ` :: ${JSON.stringify(extra)}` : ""}`);
}

const S = () => useStore.getState();

// ----- Scenario 1: write (user=seller) on virtual, MM exercises ITM -----
S().selectChain("virtual");
const userPk = S().user.pubkey;
const btcBefore = S().emu.balance(userPk, STABLE.id).virtual.sats;

S().openPosition({
  side: "seller",
  notionalBtc: 1,
  strikeUsd: 90_000,
  premiumUsd: 1500,
  volPct: 60,
  expiryInBlocks: 10,
  graceBlocks: 5,
  exitBlocks: 5,
  chain: "virtual",
});
check("position opened", S().positions.length === 1, S().toast);
const pos = S().positions[0];
check("status active", pos.status === "active");
check("vault id present", !!pos.vaultUtxoId);

const usdAfterPremium = S().emu.balance(userPk, STABLE.id).virtual.asset;
check("premium credited (>= 1500 aUSD)", usdAfterPremium >= usdToStableUnits(1500), {
  usdAfterPremium,
});
const btcLocked = S().emu.balance(userPk, STABLE.id).virtual.sats;
// Net = 1 BTC locked, minus the 330-sat dust carrier that rides on the premium
// stablecoin UTXO credited back to the seller.
check("seller BTC reduced by 1 BTC (less premium dust carrier)", btcBefore - btcLocked === btcToSats(1) - 330, {
  delta: btcBefore - btcLocked,
});

// advance past expiry, exercise cooperatively (MM is buyer)
S().mine(10);
check("at/after expiry", S().emu.height >= pos.terms.expiryHeight);
S().exercisePosition(pos.id, "cooperative");
check("exercised", S().positions[0].status === "exercised", S().toast);
const usdFinal = S().emu.balance(userPk, STABLE.id).virtual.asset;
check("seller received strike (premium + 90k aUSD)", usdFinal >= usdToStableUnits(90_000 + 1500), {
  usdFinal,
});

// ----- Scenario 2: write, no exercise, reclaim onchain via exit path -----
S().selectChain("onchain");
S().openPosition({
  side: "seller",
  notionalBtc: 0.5,
  strikeUsd: 120_000,
  premiumUsd: 800,
  volPct: 60,
  expiryInBlocks: 5,
  graceBlocks: 3,
  exitBlocks: 4,
  chain: "onchain",
});
const pos2 = S().positions[0];
check("pos2 opened onchain", pos2.chain === "onchain" && pos2.status === "active", S().toast);
S().mine(3); // confirm funding
const reclaimH = pos2.terms.expiryHeight + pos2.terms.graceBlocks;
S().mine(reclaimH - S().emu.height + 1); // cross reclaim height
const btcPreReclaim = S().emu.balance(userPk, STABLE.id).onchain.sats;
S().reclaimPosition(pos2.id, "exit");
check("reclaim broadcast", S().toast?.kind === "ok", S().toast);
S().mine(3); // confirm reclaim
const btcPostReclaim = S().emu.balance(userPk, STABLE.id).onchain.sats;
check("reclaimed BTC back to seller", btcPostReclaim - btcPreReclaim === btcToSats(0.5), {
  delta: btcPostReclaim - btcPreReclaim,
});
check("pos2 reclaimed", S().positions.find((p) => p.id === pos2.id)?.status === "reclaimed");

// ----- Scenario 3: transfer buyer leg cooperatively (pre-expiry) -----
S().selectChain("virtual");
S().faucet(); // top up virtual BTC consumed by scenario 1
S().openPosition({
  side: "seller",
  notionalBtc: 0.25,
  strikeUsd: 100_000,
  premiumUsd: 400,
  volPct: 60,
  expiryInBlocks: 50,
  graceBlocks: 10,
  exitBlocks: 10,
  chain: "virtual",
});
const pos3 = S().positions[0];
const oldBuyer = pos3.buyerPk;
S().transferPosition(pos3.id, "buyer");
const pos3b = S().positions.find((p) => p.id === pos3.id)!;
check("buyer leg transferred (pubkey changed)", pos3b.buyerPk !== oldBuyer, S().toast);
check("position still active after transfer", pos3b.status === "active");
check("new vault id set", !!pos3b.vaultUtxoId);

console.log(`\n${failures === 0 ? "ALL GREEN" : failures + " FAILURE(S)"}`);
process.exit(failures === 0 ? 0 : 1);
