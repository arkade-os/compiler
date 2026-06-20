// Thin crypto layer over @noble + @scure. Everything Bitcoin/cryptographic in
// the app routes through here so the primitives are auditable in one place.
//
// Keys are x-only BIP340 Schnorr keys (the Arkade/Taproot convention). The
// embedded wallet signs with schnorr; the emulator verifies with schnorr.
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { hex } from "@scure/base";
import { randomBytes } from "@noble/hashes/utils";

export type Bytes = Uint8Array;

export function sha256(data: Bytes): Bytes {
  return nobleSha256(data);
}

/** Double-SHA256, as used for Bitcoin txids. */
export function hash256(data: Bytes): Bytes {
  return nobleSha256(nobleSha256(data));
}

export function toHex(b: Bytes): string {
  return hex.encode(b);
}

export function fromHex(s: string): Bytes {
  return hex.decode(s.startsWith("0x") ? s.slice(2) : s);
}

export function concatBytes(...arrays: Bytes[]): Bytes {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function utf8(s: string): Bytes {
  return new TextEncoder().encode(s);
}

/** 32-byte private key. */
export function randomPrivateKey(): Bytes {
  return schnorr.utils.randomPrivateKey();
}

/** x-only (32-byte) public key for a private key. */
export function xOnlyPubkey(priv: Bytes): Bytes {
  return schnorr.getPublicKey(priv);
}

export function schnorrSign(message: Bytes, priv: Bytes): Bytes {
  // Deterministic-ish: noble adds aux randomness; fine for an emulator.
  return schnorr.sign(message, priv);
}

export function schnorrVerify(sig: Bytes, message: Bytes, pubXOnly: Bytes): boolean {
  try {
    return schnorr.verify(sig, message, pubXOnly);
  } catch {
    return false;
  }
}

/** Encode a non-negative integer as 8-byte little-endian (uint64 LE). */
export function u64le(n: bigint | number): Bytes {
  let v = BigInt(n);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export { randomBytes };
