// Covered-call lifecycle.
//
// Domain operations that drive the CoveredCall contract through its states using
// the Arkade Script builder over the dual-chain emulator. Single-locked,
// Rysk-faithful: the seller escrows BTC, the buyer brings the strike payment at
// exercise only if in-the-money. Premium flows MM→seller off-contract at
// funding.
import { coveredCallAbi } from "../abi";
import { instantiate, ContractInstance, scriptIdToAddress } from "./contract";
import { ArkadeScriptTx, TapleafPath } from "./arkadeScript";
import {
  Emulator,
  Owner,
  Utxo,
  AssetAmount,
  SettledTx,
} from "./emulator";
import type { Wallet } from "./wallet";
import { btcToSats, usdToStableUnits } from "./pricing";

// A single stablecoin feed for the demo (USDT/USDC-style asset).
const STABLE_TXID =
  "a1b2c3d4e5f6071829303132333435363738393a3b3c3d3e3f4041424344454647".slice(0, 64);
const STABLE_GIDX = 0;
export const STABLE = {
  id: `${STABLE_TXID}:${STABLE_GIDX}`,
  txid: STABLE_TXID,
  gidx: STABLE_GIDX,
  symbol: "aUSD",
  label: "Arkade USD",
};

const DUST = 330; // taproot dust carrier

export type Side = "seller" | "buyer";
export type Lifecycle =
  | "active"
  | "exercised"
  | "reclaimed"
  | "transferred"
  | "expired-otm";

export interface PositionTerms {
  notionalBtc: number;
  strikeUsd: number;
  premiumUsd: number;
  volPct: number;
  expiryHeight: number;
  graceBlocks: number;
  exit: number;
}

export interface Position {
  id: string;
  inst: ContractInstance;
  sellerPk: string;
  buyerPk: string;
  sellerLabel: string;
  buyerLabel: string;
  userSide: Side;
  btcSats: number;
  strikeUnits: number;
  terms: PositionTerms;
  vaultUtxoId: string | null;
  chain: "onchain" | "virtual";
  status: Lifecycle;
  createdHeight: number;
  history: { height: number; text: string }[];
}

export interface Ctx {
  emu: Emulator;
  operator: Wallet;
  /** Resolve a signing wallet for a known pubkey (user / maker). */
  resolve: (pubkey: string) => Wallet;
}

function keyOwner(w: { pubkey: string; label?: string }): Owner {
  return { kind: "key", pubkey: w.pubkey, label: w.label };
}

function contractOwner(inst: ContractInstance): Owner {
  return {
    kind: "contract",
    scriptId: inst.scriptId,
    name: inst.name,
    address: inst.address,
  };
}

let pid = 0;

/** Build the contract instance for a set of terms + parties. */
export function buildInstance(
  sellerPk: string,
  buyerPk: string,
  terms: PositionTerms,
): ContractInstance {
  return instantiate(coveredCallAbi, {
    sellerPk,
    buyerPk,
    stableAssetIdTxid: STABLE.txid,
    stableAssetIdGidx: STABLE.gidx,
    btcSats: btcToSats(terms.notionalBtc),
    strikeAmount: usdToStableUnits(terms.strikeUsd * terms.notionalBtc),
    expiryHeight: terms.expiryHeight,
    graceBlocks: terms.graceBlocks,
    exit: terms.exit,
  });
}

/**
 * Write (open) a covered call. The seller locks `btcSats` into the vault on the
 * chosen chain; the MM pays the premium to the seller off-contract in the same
 * funding flow. Returns the new position and the funding tx.
 */
export function writeCoveredCall(
  ctx: Ctx,
  args: {
    seller: { pubkey: string; label: string };
    buyer: { pubkey: string; label: string };
    userSide: Side;
    terms: PositionTerms;
    chain: "onchain" | "virtual";
  },
): { position: Position; fundingTx: SettledTx } {
  const { emu } = ctx;
  const inst = buildInstance(args.seller.pubkey, args.buyer.pubkey, args.terms);
  const btcSats = btcToSats(args.terms.notionalBtc);
  const strikeUnits = usdToStableUnits(args.terms.strikeUsd * args.terms.notionalBtc);

  // Seller's BTC collateral. Gather seller BTC utxos on the funding chain.
  const sellerUtxos = emu
    .utxosOf(args.seller.pubkey, args.chain)
    .filter((u) => u.sats > 0);
  const total = sellerUtxos.reduce((n, u) => n + u.sats, 0);
  if (total < btcSats) {
    throw new Error(
      `seller has insufficient BTC on ${args.chain}: need ${btcSats} sats, have ${total}`,
    );
  }
  // Greedy selection.
  const inputs: Utxo[] = [];
  let acc = 0;
  for (const u of sellerUtxos) {
    inputs.push(u);
    acc += u.sats;
    if (acc >= btcSats) break;
  }

  const outputs = [
    { owner: contractOwner(inst), sats: btcSats, asset: undefined as AssetAmount | undefined },
  ];
  const change = acc - btcSats;
  if (change > 0) {
    outputs.push({ owner: keyOwner(args.seller), sats: change, asset: undefined });
  }

  const fundingTx = emu.settle({
    chain: args.chain,
    inputs: inputs.map((i) => i.id),
    outputs,
    kind: "fund",
    note: `${args.seller.label} locked ${args.terms.notionalBtc} BTC into ${inst.name} vault`,
  });
  // The vault output is the first materialized output (virtual) — for onchain it
  // materializes on confirmation; we track by scanning contract utxos for this
  // scriptId once available. We record the scriptId-derived address now and
  // resolve the concrete utxo id lazily.
  const vaultUtxoId =
    fundingTx.outputs[0] ?? findVault(emu, inst.scriptId)?.id ?? null;

  // Premium: MM → seller, off-contract stablecoin payment.
  const premiumUnits = usdToStableUnits(args.terms.premiumUsd);
  emu.credit(
    args.chain,
    keyOwner(args.seller),
    DUST,
    { id: STABLE.id, amount: premiumUnits },
    `${args.buyer.label} paid ${args.terms.premiumUsd.toFixed(2)} ${STABLE.symbol} premium to ${args.seller.label}`,
  );

  const position: Position = {
    id: `pos_${++pid}`,
    inst,
    sellerPk: args.seller.pubkey,
    buyerPk: args.buyer.pubkey,
    sellerLabel: args.seller.label,
    buyerLabel: args.buyer.label,
    userSide: args.userSide,
    btcSats,
    strikeUnits,
    terms: args.terms,
    vaultUtxoId,
    chain: args.chain,
    status: "active",
    createdHeight: emu.height,
    history: [{ height: emu.height, text: "Opened — collateral locked, premium paid" }],
  };
  return { position, fundingTx };
}

/** Resolve the live vault utxo for a position (handles post-confirmation ids). */
export function findVault(emu: Emulator, scriptId: string): Utxo | undefined {
  return emu.contractUtxos(scriptId)[0];
}

function resolveVaultUtxo(ctx: Ctx, pos: Position): Utxo {
  const v =
    (pos.vaultUtxoId && ctx.emu.getUtxo(pos.vaultUtxoId)) ||
    findVault(ctx.emu, pos.inst.scriptId);
  if (!v) throw new Error("vault not yet confirmed — mine a block first");
  return v;
}

/**
 * Exercise: buyer pays the strike in stablecoin to the seller and takes the BTC.
 * Valid from `expiryHeight`. Cooperative (virtual, Operator co-sign) or exit
 * (onchain, seller+buyer N-of-N after the CSV `exit` delay).
 */
export function exercise(
  ctx: Ctx,
  pos: Position,
  path: TapleafPath,
): SettledTx {
  const { emu } = ctx;
  if (pos.status !== "active") throw new Error(`position is ${pos.status}`);
  if (emu.height < pos.terms.expiryHeight) {
    throw new Error(
      `before expiry: height ${emu.height} < ${pos.terms.expiryHeight}`,
    );
  }
  const vault = resolveVaultUtxo(ctx, pos);
  const chain = path === "cooperative" ? "virtual" : "onchain";
  if (path === "exit") {
    const age = emu.height - vault.createdAt;
    if (age < pos.terms.exit) {
      throw new Error(
        `exit timelock not met: vault age ${age} < exit ${pos.terms.exit} blocks`,
      );
    }
  }

  // Buyer's stablecoin inputs (must cover the strike) on the same chain.
  const buyerStable = emu
    .utxosOf(pos.buyerPk, chain)
    .filter((u) => u.asset?.id === STABLE.id);
  const stableTotal = buyerStable.reduce((n, u) => n + (u.asset?.amount ?? 0), 0);
  if (stableTotal < pos.strikeUnits) {
    throw new Error(
      `buyer has insufficient ${STABLE.symbol}: need ${pos.strikeUnits}, have ${stableTotal}`,
    );
  }
  // Buyer also needs a little BTC to seed dust carriers; pull any buyer BTC utxo.
  const buyerBtc = emu.utxosOf(pos.buyerPk, chain).filter((u) => u.sats >= DUST);
  if (buyerBtc.length === 0) {
    throw new Error(`buyer needs a small BTC input (>= ${DUST} sats) on ${chain}`);
  }

  const sellerOwner: Owner = { kind: "key", pubkey: pos.sellerPk, label: pos.sellerLabel };
  const buyerOwner: Owner = { kind: "key", pubkey: pos.buyerPk, label: pos.buyerLabel };

  const tx = new ArkadeScriptTx(pos.inst, "exercise", path).spendVault(vault);

  // Select buyer stablecoin inputs.
  let sAcc = 0;
  const usedStable: Utxo[] = [];
  for (const u of buyerStable) {
    tx.addInput(u);
    usedStable.push(u);
    sAcc += u.asset?.amount ?? 0;
    if (sAcc >= pos.strikeUnits) break;
  }
  const btcCarrier = buyerBtc[0];
  tx.addInput(btcCarrier);

  // output[0]: seller receives strike stablecoin (dust carrier from buyer BTC).
  tx.addOutput({ owner: sellerOwner, sats: DUST, asset: { id: STABLE.id, amount: pos.strikeUnits } });
  // output[1]: buyer receives the BTC collateral.
  tx.addOutput({ owner: buyerOwner, sats: pos.btcSats, asset: undefined });
  // output[2]: buyer stablecoin change.
  const stableChange = sAcc - pos.strikeUnits;
  if (stableChange > 0) {
    tx.addOutput({ owner: buyerOwner, sats: 0, asset: { id: STABLE.id, amount: stableChange } });
  }
  // output[3]: buyer BTC change (carrier minus dust spent).
  const btcChange = btcCarrier.sats - DUST;
  if (btcChange > 0) {
    tx.addOutput({ owner: buyerOwner, sats: btcChange, asset: undefined });
  }

  // Signatures.
  tx.sign("buyerSig", ctx.resolve(pos.buyerPk));
  if (path === "exit") {
    tx.sign("sellerPkSig", ctx.resolve(pos.sellerPk));
    tx.sign("buyerPkSig", ctx.resolve(pos.buyerPk));
  } else {
    tx.withOperator(ctx.operator);
  }

  const spend = tx.build();
  const settled = emu.settle({
    chain,
    inputs: spend.inputs,
    outputs: spend.outputs,
    kind: "exercise",
    note: `${pos.buyerLabel} exercised ${pos.inst.name} (${path}) — paid strike, took BTC`,
  });
  pos.status = "exercised";
  pos.vaultUtxoId = null;
  pos.history.push({ height: emu.height, text: `Exercised via ${path} path` });
  return settled;
}

/** Seller reclaims the BTC after the grace window closes. */
export function reclaim(ctx: Ctx, pos: Position, path: TapleafPath): SettledTx {
  const { emu } = ctx;
  if (pos.status !== "active") throw new Error(`position is ${pos.status}`);
  const reclaimHeight = pos.terms.expiryHeight + pos.terms.graceBlocks;
  if (emu.height < reclaimHeight) {
    throw new Error(`reclaim window not open: height ${emu.height} < ${reclaimHeight}`);
  }
  const vault = resolveVaultUtxo(ctx, pos);
  const chain = path === "cooperative" ? "virtual" : "onchain";
  if (path === "exit") {
    const age = emu.height - vault.createdAt;
    if (age < pos.terms.exit) {
      throw new Error(`exit timelock not met: vault age ${age} < ${pos.terms.exit}`);
    }
  }

  const sellerOwner: Owner = { kind: "key", pubkey: pos.sellerPk, label: pos.sellerLabel };
  const tx = new ArkadeScriptTx(pos.inst, "reclaim", path)
    .spendVault(vault)
    .addOutput({ owner: sellerOwner, sats: pos.btcSats, asset: undefined })
    .sign("sellerSig", ctx.resolve(pos.sellerPk));
  if (path === "cooperative") tx.withOperator(ctx.operator);

  const spend = tx.build();
  const settled = emu.settle({
    chain,
    inputs: spend.inputs,
    outputs: spend.outputs,
    kind: "reclaim",
    note: `${pos.sellerLabel} reclaimed ${pos.btcSats} sats (${path})`,
  });
  pos.status = "reclaimed";
  pos.vaultUtxoId = null;
  pos.history.push({ height: emu.height, text: `Reclaimed via ${path} path` });
  return settled;
}

/**
 * Transfer a leg to a new party (cooperative, pre-expiry). Produces a fresh vault
 * with the swapped pubkey, preserving the BTC collateral, and re-points the
 * position at the new instance.
 */
export function transferLeg(
  ctx: Ctx,
  pos: Position,
  leg: Side,
  newParty: { pubkey: string; label: string },
): SettledTx {
  const { emu } = ctx;
  if (pos.status !== "active") throw new Error(`position is ${pos.status}`);
  if (emu.height >= pos.terms.expiryHeight) {
    throw new Error("no transfers after expiry");
  }
  const vault = resolveVaultUtxo(ctx, pos);

  const newSellerPk = leg === "seller" ? newParty.pubkey : pos.sellerPk;
  const newBuyerPk = leg === "buyer" ? newParty.pubkey : pos.buyerPk;
  const newInst = buildInstance(newSellerPk, newBuyerPk, pos.terms);
  void scriptIdToAddress; // address already on instance

  const fnName = leg === "seller" ? "transferSeller" : "transferBuyer";
  const signerPk = leg === "seller" ? pos.sellerPk : pos.buyerPk;
  const witnessField = leg === "seller" ? "newSellerPk" : "newBuyerPk";
  const sigField = leg === "seller" ? "sellerSig" : "buyerSig";

  const tx = new ArkadeScriptTx(pos.inst, fnName, "cooperative")
    .spendVault(vault)
    .addOutput({ owner: contractOwner(newInst), sats: pos.btcSats, asset: undefined })
    .setWitness(witnessField, newParty.pubkey)
    .sign(sigField, ctx.resolve(signerPk))
    .withOperator(ctx.operator);

  const spend = tx.build();
  const settled = emu.settle({
    chain: "virtual",
    inputs: spend.inputs,
    outputs: spend.outputs,
    kind: fnName,
    note: `${leg} leg transferred to ${newParty.label}`,
  });

  // Re-point the position.
  pos.inst = newInst;
  if (leg === "seller") {
    pos.sellerPk = newSellerPk;
    pos.sellerLabel = newParty.label;
  } else {
    pos.buyerPk = newBuyerPk;
    pos.buyerLabel = newParty.label;
  }
  pos.vaultUtxoId = settled.outputs[0] ?? findVault(emu, newInst.scriptId)?.id ?? null;
  pos.history.push({ height: emu.height, text: `Transferred ${leg} leg to ${newParty.label}` });
  return settled;
}
