// Compiler-sourced contract ABI.
//
// covered_call.json is produced by the Arkade compiler (`arkadec`) from
// examples/options/covered_call.ark and copied here verbatim. It is the single
// source of truth for constructor parameters, so every position in this app
// points at a real, deterministically-derived Arkade vault. Do not hand-edit —
// regenerate upstream.
import coveredCallJson from "./covered_call.json";

export type AbiType = "pubkey" | "bytes32" | "bytes" | "int" | "signature" | "bool";

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
