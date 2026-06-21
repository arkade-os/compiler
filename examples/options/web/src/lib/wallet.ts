// Embedded browser wallet.
//
// A self-custodial BIP340 Schnorr keypair generated in-browser and persisted to
// localStorage. No server, no extension — the private key never leaves the tab.
// The same module mints the simulated counterparties the emulator needs: a
// market-maker that writes/quotes options, and the Arkade Operator whose key
// co-signs every cooperative (virtual) settlement.
import {
  randomPrivateKey,
  xOnlyPubkey,
  schnorrSign,
  toHex,
  fromHex,
  type Bytes,
} from "./crypto";

export interface Wallet {
  label: string;
  pubkey: string; // x-only hex
  /** Signs a 32-byte sighash, returns 64-byte schnorr sig (hex). */
  sign(sighash: Bytes): string;
  /** Exposed only for the local emulator/persistence — never networked. */
  exportSecret(): string;
}

function makeWallet(label: string, priv: Bytes): Wallet {
  const pub = xOnlyPubkey(priv);
  return {
    label,
    pubkey: toHex(pub),
    sign: (sighash: Bytes) => toHex(schnorrSign(sighash, priv)),
    exportSecret: () => toHex(priv),
  };
}

const USER_KEY = "arkade.cc.user.secret";

/** Load the embedded user wallet, generating + persisting one on first run. */
/** A valid persisted secret is 64 lowercase hex chars (32 bytes). */
function parseSecret(secret: string | null): Uint8Array | null {
  if (!secret) return null;
  try {
    const priv = fromHex(secret.trim().replace(/^0x/, ""));
    return priv.length === 32 ? priv : null;
  } catch {
    return null;
  }
}

/** Load the embedded wallet, regenerating if storage is missing or corrupted. */
export function loadUserWallet(): Wallet {
  let priv = parseSecret(localStorage.getItem(USER_KEY));
  if (!priv) {
    priv = randomPrivateKey();
    localStorage.setItem(USER_KEY, toHex(priv));
  }
  return makeWallet("You", priv);
}

export function resetUserWallet(): Wallet {
  const secret = toHex(randomPrivateKey());
  localStorage.setItem(USER_KEY, secret);
  return makeWallet("You", fromHex(secret));
}

/** Import an existing secret (hex). */
export function importUserWallet(secretHex: string): Wallet {
  const clean = secretHex.trim().replace(/^0x/, "");
  const priv = fromHex(clean);
  if (priv.length !== 32) throw new Error("secret must be 32 bytes");
  localStorage.setItem(USER_KEY, clean);
  return makeWallet("You", priv);
}

/**
 * Deterministic counterparties seeded per-session. The market maker plays the
 * RFQ quoter that writes covered calls; the operator is the Arkade server.
 */
export function makeCounterparties(): { maker: Wallet; operator: Wallet } {
  const seedOnce = (k: string, label: string) => {
    let s = localStorage.getItem(k);
    if (!s) {
      s = toHex(randomPrivateKey());
      localStorage.setItem(k, s);
    }
    return makeWallet(label, fromHex(s));
  };
  return {
    maker: seedOnce("arkade.cc.maker.secret", "Arkade MM"),
    operator: seedOnce("arkade.cc.operator.secret", "Arkade Operator"),
  };
}
