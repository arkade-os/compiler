// Dual-chain Bitcoin emulator.
//
// Two settlement layers share one block clock (Bitcoin block height — the basis
// for every CLTV/CSV timelock and for `tx.time`):
//
//   • onchain  — Bitcoin L1. Spends enter a mempool and confirm after
//                CONFIRMATIONS blocks. This is the unilateral "exit" world.
//   • virtual  — Arkade VTXOs. The Operator co-signs and the spend settles
//                instantly at the current height. This is the cooperative world.
//
// The emulator is a pure ledger: it tracks UTXO ownership, balances, the block
// clock, and confirmation latency. Contract *semantics* (signatures, output
// shape, asset amounts, timelock predicates) are enforced one layer up in
// coveredCall.ts before a spend is handed here to settle.

export type ChainId = "onchain" | "virtual";

export type Owner =
  | { kind: "key"; pubkey: string; label?: string }
  | { kind: "contract"; scriptId: string; name: string; address: string };

export interface AssetAmount {
  id: string; // "<txid>:<gidx>"
  amount: number; // base units
}

export interface Utxo {
  id: string;
  chain: ChainId;
  owner: Owner;
  sats: number;
  asset?: AssetAmount;
  createdAt: number; // block height at which it became spendable
}

export interface OutputSpec {
  owner: Owner;
  sats: number;
  asset?: AssetAmount;
}

export type TxStatus = "pending" | "confirmed";

export interface SettledTx {
  id: string;
  chain: ChainId;
  kind: string;
  height: number; // height at submission
  inputs: string[];
  outputs: string[];
  status: TxStatus;
  confirmAt?: number;
  note?: string;
}

export interface LogEvent {
  height: number;
  ts: number;
  level: "info" | "success" | "warn";
  message: string;
}

interface PendingTx {
  txId: string;
  outputs: OutputSpec[];
  inputs: string[];
  confirmAt: number;
}

export interface EmulatorSnapshot {
  height: number;
  utxos: Utxo[];
  txs: SettledTx[];
  events: LogEvent[];
}

const CONFIRMATIONS = 3;

let counter = 0;
function rid(prefix: string): string {
  counter += 1;
  const rnd = Math.floor(Math.random() * 0xffffff)
    .toString(16)
    .padStart(6, "0");
  return `${prefix}_${counter.toString(16)}${rnd}`;
}

export class Emulator {
  height = 100_000; // a plausible mainnet-ish starting height
  private utxos = new Map<string, Utxo>();
  private pending: PendingTx[] = [];
  txs: SettledTx[] = [];
  events: LogEvent[] = [];

  constructor(public readonly confirmations = CONFIRMATIONS) {}

  private log(level: LogEvent["level"], message: string) {
    this.events.unshift({ height: this.height, ts: Date.now(), level, message });
    if (this.events.length > 200) this.events.pop();
  }

  snapshot(): EmulatorSnapshot {
    return {
      height: this.height,
      utxos: [...this.utxos.values()],
      txs: this.txs,
      events: this.events,
    };
  }

  getUtxo(id: string): Utxo | undefined {
    return this.utxos.get(id);
  }

  utxosOf(pubkey: string, chain?: ChainId): Utxo[] {
    return [...this.utxos.values()].filter(
      (u) =>
        u.owner.kind === "key" &&
        u.owner.pubkey === pubkey &&
        (chain ? u.chain === chain : true),
    );
  }

  contractUtxos(scriptId?: string): Utxo[] {
    return [...this.utxos.values()].filter(
      (u) => u.owner.kind === "contract" && (!scriptId || u.owner.scriptId === scriptId),
    );
  }

  /** Confirmed balance for a key, split BTC vs. a given asset, per chain. */
  balance(pubkey: string, assetId?: string) {
    const acc = {
      onchain: { sats: 0, asset: 0 },
      virtual: { sats: 0, asset: 0 },
    };
    for (const u of this.utxosOf(pubkey)) {
      acc[u.chain].sats += u.sats;
      if (assetId && u.asset && u.asset.id === assetId) {
        acc[u.chain].asset += u.asset.amount;
      }
    }
    return acc;
  }

  /** Mint funds to an owner (faucet / off-contract premium). Always confirmed. */
  credit(chain: ChainId, owner: Owner, sats: number, asset?: AssetAmount, note?: string): Utxo {
    const u: Utxo = {
      id: rid("utxo"),
      chain,
      owner,
      sats,
      asset,
      createdAt: this.height,
    };
    this.utxos.set(u.id, u);
    if (note) this.log("info", note);
    return u;
  }

  /**
   * Settle a spend. Inputs are consumed immediately (no double-spend); outputs
   * materialize instantly on the virtual chain or after `confirmations` blocks
   * on the onchain layer.
   */
  settle(params: {
    chain: ChainId;
    inputs: string[];
    outputs: OutputSpec[];
    kind: string;
    note?: string;
  }): SettledTx {
    const { chain, inputs, outputs, kind, note } = params;
    for (const id of inputs) {
      const u = this.utxos.get(id);
      if (!u) throw new Error(`input ${id} not found or already spent`);
    }
    // consume
    for (const id of inputs) this.utxos.delete(id);

    const txId = rid("tx");
    if (chain === "virtual") {
      const outIds = outputs.map((o) => this.materialize(chain, o, this.height));
      const tx: SettledTx = {
        id: txId,
        chain,
        kind,
        height: this.height,
        inputs,
        outputs: outIds,
        status: "confirmed",
        note,
      };
      this.txs.unshift(tx);
      this.log("success", note ?? `${kind} settled virtually`);
      return tx;
    }

    const confirmAt = this.height + this.confirmations;
    this.pending.push({ txId, outputs, inputs, confirmAt });
    const tx: SettledTx = {
      id: txId,
      chain,
      kind,
      height: this.height,
      inputs,
      outputs: [],
      status: "pending",
      confirmAt,
      note,
    };
    this.txs.unshift(tx);
    this.log("info", note ?? `${kind} broadcast onchain (confirms at ${confirmAt})`);
    return tx;
  }

  private materialize(chain: ChainId, o: OutputSpec, at: number): string {
    const u: Utxo = {
      id: rid("utxo"),
      chain,
      owner: o.owner,
      sats: o.sats,
      asset: o.asset,
      createdAt: at,
    };
    this.utxos.set(u.id, u);
    return u.id;
  }

  /** Advance the block clock, confirming any matured onchain transactions. */
  mine(blocks = 1): void {
    for (let i = 0; i < blocks; i++) {
      this.height += 1;
      const stillPending: PendingTx[] = [];
      for (const p of this.pending) {
        if (p.confirmAt <= this.height) {
          const outIds = p.outputs.map((o) => this.materialize("onchain", o, p.confirmAt));
          const tx = this.txs.find((t) => t.id === p.txId);
          if (tx) {
            tx.status = "confirmed";
            tx.outputs = outIds;
          }
          this.log("success", `onchain tx confirmed at height ${this.height}`);
        } else {
          stillPending.push(p);
        }
      }
      this.pending = stillPending;
    }
  }
}
