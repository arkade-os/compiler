// High-level Arkade Script transaction builder.
//
// This mirrors the shape of the Arkade SDK's `arkade-script` tx builder: you
// select a contract input + function + tapleaf path, attach funding inputs and
// outputs, collect the required signatures, and `build()` a settlement-ready
// spend. It is deliberately the single seam where the real
// `@arkade-os/sdk` builder can be substituted — the lifecycle code and UI depend
// only on this interface, never on the emulator internals.
//
//   path "cooperative" → server-cosigned tapleaf  → settles on the virtual chain
//   path "exit"        → N-of-N + CSV tapleaf      → settles onchain after `exit`
import { ContractInstance, getVariant, renderAsm } from "./contract";
import { ChainId, OutputSpec, Utxo } from "./emulator";
import { sha256, concatBytes, utf8, fromHex, schnorrVerify } from "./crypto";
import type { Wallet } from "./wallet";

export type TapleafPath = "cooperative" | "exit";

export interface SignerSpec {
  /** witness field name this signature fills, e.g. "buyerSig". */
  field: string;
  wallet: Wallet;
}

export interface ArkadeSpend {
  chain: ChainId;
  inputs: string[];
  outputs: OutputSpec[];
  witness: Record<string, string>;
  asm: string[];
  fnName: string;
  path: TapleafPath;
  sighash: string;
}

function pathToChain(path: TapleafPath): ChainId {
  return path === "cooperative" ? "virtual" : "onchain";
}

export class ArkadeScriptTx {
  private inputs: Utxo[] = [];
  private outputs: OutputSpec[] = [];
  private witnessValues: Record<string, string> = {};
  private signers: SignerSpec[] = [];
  private operator?: Wallet;

  constructor(
    private readonly inst: ContractInstance,
    private readonly fnName: string,
    private readonly path: TapleafPath,
  ) {}

  /** The contract UTXO being spent (input[0]). */
  spendVault(utxo: Utxo): this {
    this.inputs.unshift(utxo);
    return this;
  }

  addInput(utxo: Utxo): this {
    this.inputs.push(utxo);
    return this;
  }

  addOutput(spec: OutputSpec): this {
    this.outputs.push(spec);
    return this;
  }

  /** Bind a non-signature witness value (e.g. newSellerPk). */
  setWitness(field: string, value: string): this {
    this.witnessValues[field] = value;
    return this;
  }

  sign(field: string, wallet: Wallet): this {
    this.signers.push({ field, wallet });
    return this;
  }

  /** Attach the Arkade Operator co-signer (required on the cooperative path). */
  withOperator(operator: Wallet): this {
    this.operator = operator;
    return this;
  }

  /**
   * Canonical sighash over the spend. Not consensus-exact Bitcoin sighash, but
   * a stable commitment to (vault, function, path, inputs, outputs) so the
   * emulator can verify every required signature actually covers this tx.
   */
  private computeSighash(): Uint8Array {
    const parts: Uint8Array[] = [
      fromHex(this.inst.scriptId),
      utf8(`${this.fnName}:${this.path}|`),
    ];
    for (const i of this.inputs) parts.push(utf8(`in:${i.id};`));
    for (const o of this.outputs) {
      const ownerTag =
        o.owner.kind === "key" ? `k:${o.owner.pubkey}` : `c:${o.owner.scriptId}`;
      const assetTag = o.asset ? `${o.asset.id}=${o.asset.amount}` : "-";
      parts.push(utf8(`out:${ownerTag}/${o.sats}/${assetTag};`));
    }
    return sha256(concatBytes(...parts));
  }

  build(): ArkadeSpend {
    if (this.inputs.length === 0) throw new Error("no inputs");
    const variant = getVariant(this.inst, this.fnName, this.path === "cooperative");
    const sighash = this.computeSighash();

    const witness: Record<string, string> = { ...this.witnessValues };

    // Collect and verify every party signature.
    for (const s of this.signers) {
      const sig = s.wallet.sign(sighash);
      if (!schnorrVerify(fromHex(sig), sighash, fromHex(s.wallet.pubkey))) {
        throw new Error(`signature for ${s.field} failed to verify`);
      }
      witness[s.field] = sig;
    }

    if (this.path === "cooperative") {
      if (!this.operator) throw new Error("cooperative path needs the Operator co-signature");
      const serverSig = this.operator.sign(sighash);
      witness.serverSig = serverSig;
    }

    // Ensure every signature field the ABI demands is present.
    for (const field of variant.witnessSchema) {
      if (field.type === "signature" && witness[field.name] === undefined) {
        throw new Error(`missing required signature: ${field.name}`);
      }
    }

    const asm = renderAsm(this.inst, variant, witness);

    return {
      chain: pathToChain(this.path),
      inputs: this.inputs.map((i) => i.id),
      outputs: this.outputs,
      witness,
      asm,
      fnName: this.fnName,
      path: this.path,
      sighash: this.inst.scriptId,
    };
  }
}
