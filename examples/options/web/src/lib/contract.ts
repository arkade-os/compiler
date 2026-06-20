// Contract instantiation: bind a compiler ABI + concrete constructor arguments
// into a deployable instance with a deterministic vault identity (a stand-in for
// the Taproot output key / VTXO script address) and per-function tapleaf
// rendering. This is the boundary the real Arkade SDK's contract artifact would
// occupy; the emulator and tx-builder consume this shape, not the raw ABI.
import {
  ContractAbi,
  AbiFunctionVariant,
  pickVariant,
} from "../abi";
import { concatBytes, sha256, toHex, u64le, utf8, fromHex } from "./crypto";

export type ParamValue = string | number | bigint;

export interface ContractInstance {
  abi: ContractAbi;
  name: string;
  /** Constructor argument values keyed by parameter name. */
  params: Record<string, ParamValue>;
  /** 32-byte deterministic script commitment (hex). Plays the role of the
   *  Taproot tweaked output key for this exact parameterization. */
  scriptId: string;
  /** Human-facing bech32-style vault address derived from scriptId. */
  address: string;
}

/** Serialize one constructor parameter to bytes for the script commitment. */
function encodeParam(type: string, value: ParamValue): Uint8Array {
  switch (type) {
    case "pubkey":
      return fromHex(String(value));
    case "bytes32":
      return fromHex(String(value));
    case "bytes":
      return fromHex(String(value));
    case "int":
      return u64le(BigInt(value as number));
    default:
      return utf8(String(value));
  }
}

/**
 * Deterministic commitment to (contractName, ordered constructor args).
 * Two instances with identical parameters share an address — exactly the
 * property the `transferSeller` / `transferBuyer` continuation outputs rely on.
 */
export function computeScriptId(
  abi: ContractAbi,
  params: Record<string, ParamValue>,
): string {
  const parts: Uint8Array[] = [utf8(abi.contractName + "\0")];
  for (const input of abi.constructorInputs) {
    const v = params[input.name];
    if (v === undefined) {
      throw new Error(`missing constructor arg: ${input.name}`);
    }
    parts.push(encodeParam(input.type, v));
  }
  return toHex(sha256(concatBytes(...parts)));
}

/** Render a short bech32-flavored address from a script commitment. */
export function scriptIdToAddress(scriptId: string, hrp = "ark"): string {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const bytes = fromHex(scriptId);
  let out = "";
  for (let i = 0; i < 38; i++) {
    out += CHARSET[bytes[i % bytes.length] & 31];
  }
  return `${hrp}1${out}`;
}

export function instantiate(
  abi: ContractAbi,
  params: Record<string, ParamValue>,
): ContractInstance {
  const scriptId = computeScriptId(abi, params);
  return {
    abi,
    name: abi.contractName,
    params,
    scriptId,
    address: scriptIdToAddress(scriptId),
  };
}

/**
 * Render a function's tapleaf ASM with constructor params and witness values
 * substituted into `<placeholder>` tokens. `reclaimHeight` is computed per the
 * documented SDK substitution (expiryHeight + graceBlocks). The returned ASM is
 * the exact script a verifier would execute; the emulator does a structural
 * check of it rather than a full Bitcoin Script interpreter pass.
 */
export function renderAsm(
  inst: ContractInstance,
  fn: AbiFunctionVariant,
  witness: Record<string, ParamValue>,
): string[] {
  const bindings: Record<string, string> = {};
  for (const [k, v] of Object.entries(inst.params)) bindings[k] = String(v);
  for (const [k, v] of Object.entries(witness)) bindings[k] = String(v);

  // Documented compiler quirk: reclaimHeight is emitted as a bare placeholder.
  if (inst.params.expiryHeight !== undefined && inst.params.graceBlocks !== undefined) {
    bindings.reclaimHeight = String(
      BigInt(inst.params.expiryHeight as number) +
        BigInt(inst.params.graceBlocks as number),
    );
  }
  bindings.SERVER_KEY = "SERVER_KEY";

  return fn.asm.map((tok) => {
    if (tok.startsWith("<") && tok.endsWith(">")) {
      const inner = tok.slice(1, -1);
      if (bindings[inner] !== undefined) return bindings[inner];
      return tok; // structural placeholder (e.g. nested VTXO:..., tx.time)
    }
    return tok;
  });
}

export function getVariant(
  inst: ContractInstance,
  fnName: string,
  serverVariant: boolean,
): AbiFunctionVariant {
  const v = pickVariant(inst.abi, fnName, serverVariant);
  if (!v) {
    throw new Error(
      `no ${serverVariant ? "cooperative" : "exit"} variant for ${fnName}`,
    );
  }
  return v;
}
