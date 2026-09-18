# SwissLedger LVGA Pool — automated payout contract (Flavor A)

The destination-chain counterpart to `wlvga_payout.ark`. It receives reports
of Arkade wLVGA payouts and **automatically releases LVGA** to the committed
merchant — no human in the loop, and the pool operator cannot withhold or
redirect an individual payment. This is the **Flavor A** design: a *trusted
reporter* attests that the Arkade burn/transfer happened; the contract still
independently binds the destination, amount, and uniqueness so the reporter
is trusted for **liveness only**, not for correctness.

This contract is Solidity (it runs on SwissLedger, an EVM chain), so it lives
here as a spec, not as a compiled `.ark` artifact. The Arkade side
(`wlvga_payout.ark`) already emits everything below — no Arkade change is
needed.

## Roles

- **Reporter** — the party that tells the pool an Arkade payout occurred.
  Natural choice: the **pool operator / Arkade operator** itself, because the
  Arkade operator already knows the true VTXO state, and a *false* report
  releases LVGA from the operator's own pool with no BTC received in return —
  self-harm. So with reporter = pool operator the trust is aligned by
  incentive and reduces in practice to **"the operator stays online to
  report"** (censorship/liveness). A third-party reporter should be bonded.
- **Merchant** — the payee. Authorizes the exact payout with a signature over
  the payout message; holds a whitelisted LVGA address.
- **LP / pool operator** — funds the pool with LVGA. Solvency (keeping the
  pool funded) is theirs; per-payment discretion is removed by this contract.

## What the reporter submits

`release(merchantEvmAddr, amount, burnNonce, merchantSig)` — where
`merchantEvmAddr` and `amount` are read from the Arkade OP_RETURN commitment,
and `burnNonce` + `merchantSig` are read from the Arkade spend's witness. (If
the reporter is not implicitly authorized, add a reporter signature /
`onlyReporter` guard — the Flavor A trust anchor.)

## Byte layout — must match `wlvga_payout.ark` exactly

The merchant signs the **payout message**, verified on Arkade by
`checkSigFromStack` and re-derived here for `ecrecover`:

```
payoutPreimage = protocolTag              (P bytes, fixed)
              ‖ merchantEvmAddr           (20 bytes)
              ‖ amount                    (8 bytes, LITTLE-endian)
              ‖ burnNonce                 (8 bytes, LITTLE-endian)
payoutMsg      = sha256(payoutPreimage)   (32 bytes)
```

The Arkade OP_RETURN commitment carries `protocolTag ‖ merchantEvmAddr ‖
amount(8 LE)` (no `burnNonce`, no hash — it is the raw committed record); the
reporter supplies `burnNonce` and `merchantSig` alongside it.

Two integration details that will silently break `ecrecover` if missed:

1. **Little-endian ints.** `amount` and `burnNonce` are 8-byte *little-endian*
   in the preimage (that is how the Arkade `+` concat encodes them). EVM is
   big-endian natively, so the contract must byte-reverse before packing.
2. **Signature scheme.** `merchantSig` must be a *recoverable secp256k1 ECDSA*
   signature over the raw 32-byte `payoutMsg` — **not** an EIP-191
   (`\x19Ethereum Signed Message`) signature and **not** over a keccak hash.
   Solidity's `ecrecover` precompile takes an arbitrary 32-byte hash, so
   `ecrecover(payoutMsg, v, r, s)` recovers the merchant address directly, and
   the *same* signature is what Arkade's `checkSigFromStack` verifies over the
   sha256 digest — one key, two chains. (If Arkade's CSFS is Schnorr-only in a
   given deployment, the merchant instead provides two signatures over the
   same `payoutMsg`; the binding below is unchanged.)

## On-chain checks (in order)

```solidity
function release(
    bytes  calldata protocolTag,     // must equal the pool's configured tag
    address merchantEvmAddr,
    uint64  amount,                  // LVGA smallest unit == CHF cents
    uint64  burnNonce,
    uint8 v, bytes32 r, bytes32 s    // merchant's recoverable ECDSA sig
) external onlyReporter {            // (1) Flavor A: trusted reporter attests the Arkade burn
    require(keccak256(protocolTag) == keccak256(POOL_TAG), "wrong protocol");
    require(!paid[burnNonce], "already paid");            // (2) replay protection

    // (3) reconstruct the exact Arkade payout message (little-endian ints)
    bytes32 payoutMsg = sha256(abi.encodePacked(
        protocolTag,
        merchantEvmAddr,
        _le64(amount),
        _le64(burnNonce)
    ));

    // (4) the merchant authorized THIS destination + amount + nonce
    require(ecrecover(payoutMsg, v, r, s) == merchantEvmAddr, "bad merchant sig");

    // (5) LVGA transfer restriction: payee must be whitelisted
    require(LVGA.isWhitelisted(merchantEvmAddr), "merchant not whitelisted");

    paid[burnNonce] = true;                               // (6) mark + pay
    LVGA.transfer(merchantEvmAddr, amount);
}
```

`_le64` packs a `uint64` as 8 little-endian bytes to match the Arkade preimage.

## Trust model (honest)

| Concern | Who / what | Note |
|---|---|---|
| "Did an Arkade payout really happen?" | **Trusted reporter** (Flavor A) | The only real trust. With reporter = pool operator it is incentive-aligned (a false report drains the operator's own pool for no BTC) and reduces to liveness. Bond a third-party reporter. |
| Redirecting a payment | **Blocked** | `ecrecover` ties the payout to the merchant-signed `merchantEvmAddr`; the reporter cannot change the payee. |
| Forging amount / double-pay | **Blocked** | `amount`/`burnNonce` are inside the merchant-signed message; `paid[burnNonce]` stops replays. |
| Paying a non-compliant address | **Blocked** | LVGA whitelist check. |
| Censorship / withholding | **Residual** | A silent reporter can stall a payout (liveness). Mitigate with multiple/permissionless reporters — anyone, including the merchant, can submit if the guard allows. |
| Pool solvency | **LP** | The pool must hold LVGA; automation removes per-payment discretion, not the need to fund. |

**Versus Flavor B (SPV-verified).** Flavor A trusts the reporter to attest
the burn; Flavor B would replace `onlyReporter` with an on-EVM Bitcoin SPV
proof of the burn tx (a BTC-Relay-style light client), removing that trust at
the cost of a heavy verifier and Bitcoin-settlement latency. Because LVGA is
already a permissioned/regulated token with a known operator, Flavor A's
trusted-reporter model is consistent with the existing trust surface; the
`ecrecover`/whitelist/nonce checks keep the reporter contained to liveness.

## End-to-end recap

1. `wlvga_payout.ark` `payOut()` — merchant-authorized (CSFS), transfers the
   BTC-backed wLVGA claim to the LP, pins the OP_RETURN commitment.
2. Reporter observes the Arkade spend, calls `release(...)` here.
3. This contract binds destination/amount/uniqueness and transfers real LVGA
   to the whitelisted merchant — automatically.
