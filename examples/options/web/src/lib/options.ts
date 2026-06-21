// BTC-only covered call — the simplified, Rysk-style product.
//
// You deposit BTC and sell a call against it. A market maker pays you a premium
// in BTC now. At expiry it settles in BTC, two ways:
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
const GRACE_BLOCKS = 144;
const EXIT_BLOCKS = 144;
const STABLE_TXID = "a1b2c3d4e5f6071829303132333435363738393a3b3c3d3e3f40414243444546";
const STABLE_GIDX = 0;

/** Covered-call strikes sit above spot. Five rungs, rounded to clean numbers. */
export const STRIKE_OFFSETS = [0.03, 0.06, 0.1, 0.15, 0.2];
export const EXPIRY_PRESETS = [7, 14, 30];

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
  expiryDays: number;
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

let pid = 0;

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
  expiryDays: number;
  premiumSats: number;
  makerName: string;
  apyPct: number;
  spot: number;
}

/** Open a position: lock the deposit in the vault, receive the premium now. */
export function writeCall(ctx: Ctx, a: WriteArgs): { position: Position; tx: SettledTx } {
  const { emu, user, maker } = ctx;

  const utxos = emu.utxosOf(user.pubkey, "virtual").filter((u) => u.sats > 0 && !u.asset);
  const total = utxos.reduce((n, u) => n + u.sats, 0);
  if (total < a.depositSats) {
    throw new Error(
      `Not enough BTC: need ${satsToBtc(a.depositSats).toFixed(4)}, have ${satsToBtc(total).toFixed(4)}`,
    );
  }
  const inputs: Utxo[] = [];
  let acc = 0;
  for (const u of utxos) {
    inputs.push(u);
    acc += u.sats;
    if (acc >= a.depositSats) break;
  }

  const expiryHeight = emu.height + a.expiryDays * BLOCKS_PER_DAY;
  const inst = buildInstance(ctx, a.depositSats, a.strikeUsd, expiryHeight);

  coSign(["lock", inst.scriptId, String(a.depositSats)], [user]);

  const outputs = [{ owner: vaultOwner(inst), sats: a.depositSats, asset: undefined }];
  const change = acc - a.depositSats;
  if (change > 0) outputs.push({ owner: userOwner(user), sats: change, asset: undefined });

  const tx = emu.settle({
    chain: "virtual",
    inputs: inputs.map((i) => i.id),
    outputs,
    kind: "open",
    note: `Locked ${satsToBtc(a.depositSats).toFixed(4)} BTC · sold $${a.strikeUsd.toLocaleString()} call to ${a.makerName}`,
  });

  // Premium paid maker → writer, in BTC, off-contract.
  emu.credit(
    "virtual",
    userOwner(user),
    a.premiumSats,
    undefined,
    `${a.makerName} paid ${satsToBtc(a.premiumSats).toFixed(6)} BTC premium`,
  );

  const position: Position = {
    id: `pos_${++pid}`,
    instance: inst,
    depositSats: a.depositSats,
    strikeUsd: a.strikeUsd,
    premiumSats: a.premiumSats,
    makerName: a.makerName,
    apyPct: a.apyPct,
    openedHeight: emu.height,
    expiryHeight,
    expiryDays: a.expiryDays,
    expiryDate: Date.now() + a.expiryDays * 864e5,
    spotAtOpen: a.spot,
    vaultUtxoId: tx.outputs[0] ?? emu.contractUtxos(inst.scriptId)[0]?.id ?? null,
    status: "active",
    history: [{ height: emu.height, text: "Opened — BTC locked, premium received" }],
  };
  void maker;
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
