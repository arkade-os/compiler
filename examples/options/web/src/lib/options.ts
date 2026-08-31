// BTC-only covered call — the simplified, Rysk-style product.
//
// You deposit BTC and sell a call against it. A market maker pays you a premium
// in BTC now. At expiry (a fixed 30 days) it settles in BTC, two ways:
//   • spot ≤ strike  → "kept":   you get your full deposit back (+ the premium).
//   • spot > strike   → "called": your BTC is sold at the strike, so you receive
//                        deposit × strike/spot BTC (the capped amount) + premium.
//
// Settlement is a cooperative Arkade close co-signed by you, the maker, and the
// Operator. Arkade settles a UTXO and a virtual UTXO the same way, so there is
// no chain to choose — this module never branches on it. The CoveredCall
// contract instance is still built (same compiler ABI) to give every position a
// real, deterministic Arkade vault address. This module is the seam where the
// Arkade SDK's tx builder would assemble the actual spend.
import { coveredCallAbi } from "../abi";
import { instantiate, ContractInstance } from "./contract";
import { Emulator, Owner, Utxo, SettledTx } from "./emulator";
import type { Wallet } from "./wallet";
import { satsToBtc, usdToStableUnits } from "./pricing";
import { sha256, concatBytes, utf8, fromHex, schnorrVerify } from "./crypto";

export const BLOCKS_PER_DAY = 144;
/** The only expiry offered — a fixed 30-day tenor. */
export const EXPIRY_DAYS = 30;
const GRACE_BLOCKS = 144;
const EXIT_BLOCKS = 144;
const STABLE_TXID = "a1b2c3d4e5f6071829303132333435363738393a3b3c3d3e3f40414243444546";
const STABLE_GIDX = 0;

/** Covered-call strikes sit above spot. Five rungs, rounded to clean numbers. */
export const STRIKE_OFFSETS = [0.03, 0.06, 0.1, 0.15, 0.2];

/** The five strike prices offered for a given spot. */
export function strikeLadder(spot: number): number[] {
  const round = spot >= 50_000 ? 1000 : 500;
  return STRIKE_OFFSETS.map((p) => Math.round((spot * (1 + p)) / round) * round);
}

export interface Position {
  id: string;
  instance: ContractInstance;
  depositSats: number;
  strikeUsd: number;
  premiumSats: number;
  makerName: string;
  apyPct: number;
  openedHeight: number;
  expiryHeight: number;
  expiryDate: number; // ms epoch
  spotAtOpen: number;
  vaultUtxoId: string | null;
  status: "active" | "settled";
  outcome?: { branch: "kept" | "called"; payoutSats: number; spotAtSettle: number; height: number };
  history: { height: number; text: string }[];
}

export interface Ctx {
  emu: Emulator;
  user: Wallet;
  maker: Wallet;
  operator: Wallet;
}

function userOwner(w: Wallet): Owner {
  return { kind: "key", pubkey: w.pubkey, label: w.label };
}
function vaultOwner(inst: ContractInstance): Owner {
  return { kind: "contract", scriptId: inst.scriptId, name: inst.name, address: inst.address };
}

/** Commit to a settlement and require real schnorr co-signatures over it. */
function coSign(parts: string[], signers: Wallet[]): void {
  const msg = sha256(concatBytes(...parts.map(utf8)));
  for (const w of signers) {
    const sig = fromHex(w.sign(msg));
    if (!schnorrVerify(sig, msg, fromHex(w.pubkey))) {
      throw new Error(`co-signature failed: ${w.label}`);
    }
  }
}

/** Greedily select spendable BTC-only UTXOs covering `need` sats. */
function selectBtc(emu: Emulator, pubkey: string, need: number): { inputs: Utxo[]; total: number } {
  const utxos = emu.utxosOf(pubkey, "virtual").filter((u) => u.sats > 0 && !u.asset);
  const inputs: Utxo[] = [];
  let total = 0;
  for (const u of utxos) {
    if (total >= need) break;
    inputs.push(u);
    total += u.sats;
  }
  return { inputs, total };
}

let pid = 0;

/** Build the CoveredCall contract instance (deterministic Arkade vault). */
export function buildInstance(
  ctx: Ctx,
  depositSats: number,
  strikeUsd: number,
  expiryHeight: number,
): ContractInstance {
  return instantiate(coveredCallAbi, {
    sellerPk: ctx.user.pubkey,
    buyerPk: ctx.maker.pubkey,
    stableAssetIdTxid: STABLE_TXID,
    stableAssetIdGidx: STABLE_GIDX,
    btcSats: depositSats,
    strikeAmount: usdToStableUnits(strikeUsd * satsToBtc(depositSats)),
    expiryHeight,
    graceBlocks: GRACE_BLOCKS,
    exit: EXIT_BLOCKS,
  });
}

export interface WriteArgs {
  depositSats: number;
  strikeUsd: number;
  premiumSats: number;
  makerName: string;
  apyPct: number;
  spot: number;
}

/** Open a position: lock the deposit in the vault, receive the premium now. */
export function writeCall(ctx: Ctx, a: WriteArgs): { position: Position; tx: SettledTx } {
  const { emu, user, maker } = ctx;

  // Validate inputs up front so we never settle a malformed position.
  if (!Number.isFinite(a.depositSats) || a.depositSats <= 0) {
    throw new Error("Enter a positive BTC amount");
  }
  if (!Number.isFinite(a.strikeUsd) || a.strikeUsd <= 0) throw new Error("Invalid strike");
  if (!Number.isFinite(a.premiumSats) || a.premiumSats < 0) throw new Error("Invalid premium");

  const depositSats = Math.floor(a.depositSats);
  const premiumSats = Math.floor(a.premiumSats);

  const { inputs, total } = selectBtc(emu, user.pubkey, depositSats);
  if (total < depositSats) {
    throw new Error(
      `Not enough BTC: need ${satsToBtc(depositSats).toFixed(4)}, have ${satsToBtc(total).toFixed(4)}`,
    );
  }

  const expiryHeight = emu.height + EXPIRY_DAYS * BLOCKS_PER_DAY;
  const inst = buildInstance(ctx, depositSats, a.strikeUsd, expiryHeight);

  coSign(["lock", inst.scriptId, String(depositSats)], [user]);

  const outputs = [{ owner: vaultOwner(inst), sats: depositSats, asset: undefined }];
  const change = total - depositSats;
  if (change > 0) outputs.push({ owner: userOwner(user), sats: change, asset: undefined });

  const tx = emu.settle({
    chain: "virtual",
    inputs: inputs.map((i) => i.id),
    outputs,
    kind: "open",
    note: `Locked ${satsToBtc(depositSats).toFixed(4)} BTC · sold $${a.strikeUsd.toLocaleString()} call to ${a.makerName}`,
  });

  // Premium paid maker → writer, in BTC, from the maker's own balance.
  const prem = selectBtc(emu, maker.pubkey, premiumSats);
  if (prem.total < premiumSats) throw new Error("Maker has insufficient BTC to pay premium");
  emu.settle({
    chain: "virtual",
    inputs: prem.inputs.map((i) => i.id),
    outputs: [
      { owner: userOwner(user), sats: premiumSats, asset: undefined },
      ...(prem.total > premiumSats
        ? [{ owner: userOwner(maker), sats: prem.total - premiumSats, asset: undefined }]
        : []),
    ],
    kind: "premium",
    note: `${a.makerName} paid ${satsToBtc(premiumSats).toFixed(6)} BTC premium`,
  });

  const position: Position = {
    id: `pos_${++pid}`,
    instance: inst,
    depositSats,
    strikeUsd: a.strikeUsd,
    premiumSats,
    makerName: a.makerName,
    apyPct: a.apyPct,
    openedHeight: emu.height,
    expiryHeight,
    expiryDate: Date.now() + EXPIRY_DAYS * 864e5,
    spotAtOpen: a.spot,
    vaultUtxoId: tx.outputs[0] ?? emu.contractUtxos(inst.scriptId)[0]?.id ?? null,
    status: "active",
    history: [{ height: emu.height, text: "Opened — BTC locked, premium received" }],
  };
  return { position, tx };
}

/** Projected BTC payout for each branch at a given spot (excludes premium). */
export function projectOutcome(pos: Position, spot: number) {
  const calledSats = Math.floor((pos.depositSats * pos.strikeUsd) / spot);
  return {
    keptSats: pos.depositSats,
    calledSats: Math.min(calledSats, pos.depositSats),
    live: spot > pos.strikeUsd ? ("called" as const) : ("kept" as const),
  };
}

/** Settle at/after expiry. Resolves by spot; cooperatively co-signed. */
export function settleCall(ctx: Ctx, pos: Position, spot: number): SettledTx {
  const { emu, user, maker, operator } = ctx;
  if (pos.status !== "active") throw new Error(`position already ${pos.status}`);
  if (emu.height < pos.expiryHeight) {
    throw new Error(`not at expiry yet: block ${emu.height} < ${pos.expiryHeight}`);
  }
  const vault =
    (pos.vaultUtxoId && emu.getUtxo(pos.vaultUtxoId)) || emu.contractUtxos(pos.instance.scriptId)[0];
  if (!vault) throw new Error("vault not found");

  const proj = projectOutcome(pos, spot);
  const called = spot > pos.strikeUsd;

  const outputs = called
    ? [
        { owner: userOwner(user), sats: proj.calledSats, asset: undefined },
        { owner: userOwner(maker), sats: pos.depositSats - proj.calledSats, asset: undefined },
      ]
    : [{ owner: userOwner(user), sats: pos.depositSats, asset: undefined }];

  // Cooperative Arkade close: writer + maker + Operator co-sign.
  coSign(["settle", pos.instance.scriptId, called ? "called" : "kept", String(spot)], [
    user,
    maker,
    operator,
  ]);

  const tx = emu.settle({
    chain: "virtual",
    inputs: [vault.id],
    outputs,
    kind: "settle",
    note: called
      ? `Called away: you received ${satsToBtc(proj.calledSats).toFixed(4)} BTC at $${pos.strikeUsd.toLocaleString()}`
      : `Expired worthless: ${satsToBtc(pos.depositSats).toFixed(4)} BTC returned`,
  });

  pos.status = "settled";
  pos.vaultUtxoId = null;
  pos.outcome = {
    branch: called ? "called" : "kept",
    payoutSats: called ? proj.calledSats : pos.depositSats,
    spotAtSettle: spot,
    height: emu.height,
  };
  pos.history.push({
    height: emu.height,
    text: called ? "Settled — called away" : "Settled — kept BTC",
  });
  return tx;
}
