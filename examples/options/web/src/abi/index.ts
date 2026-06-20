// Compiler-sourced contract ABIs.
//
// These JSON files are produced by the Arkade compiler (`arkadec`) from
// examples/options/*.ark and copied here verbatim. They are the single source
// of truth for constructor parameters, function witness schemas, and the two
// tapleaf variants (cooperative server-cosigned vs. unilateral exit) that the
// dual-chain emulator settles against. Do not hand-edit — regenerate upstream.
import coveredCallJson from "./covered_call.json";
import cashSecuredPutJson from "./cash_secured_put.json";

export type AbiType =
  | "pubkey"
  | "bytes32"
  | "bytes"
  | "int"
  | "signature"
  | "bool";

export interface AbiParam {
  name: string;
  type: AbiType;
}

export interface AbiWitnessField {
  name: string;
  type: AbiType;
  encoding?: string;
}

export interface AbiRequirement {
  type: string;
  message?: string;
}

export interface AbiFunctionVariant {
  name: string;
  functionInputs: AbiParam[];
  witnessSchema: AbiWitnessField[];
  serverVariant: boolean;
  require: AbiRequirement[];
  asm: string[];
}

export interface ContractAbi {
  contractName: string;
  constructorInputs: AbiParam[];
  functions: AbiFunctionVariant[];
  source: string;
  compiler: { name: string; version: string };
  updatedAt: string;
  warnings: string[];
}

export const coveredCallAbi = coveredCallJson as unknown as ContractAbi;
export const cashSecuredPutAbi = cashSecuredPutJson as unknown as ContractAbi;

/** All distinct function names in an ABI (variants collapsed). */
export function functionNames(abi: ContractAbi): string[] {
  return [...new Set(abi.functions.map((f) => f.name))];
}

/** Pick the cooperative (server-cosigned) or exit variant of a function. */
export function pickVariant(
  abi: ContractAbi,
  name: string,
  serverVariant: boolean,
): AbiFunctionVariant | undefined {
  return abi.functions.find(
    (f) => f.name === name && f.serverVariant === serverVariant,
  );
}
