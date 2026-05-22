# Options — How It Works

**Status:** v1 design complete

---

## What it is

Two paired contracts for selling and buying volatility on Bitcoin, faithful to Rysk Finance v12's covered call and cash-secured put. Both contracts are:

- **European** — settleable only at `expiryHeight`.
- **Physically settled** — at expiry the actual underlying changes hands (BTC ↔ stablecoin), not a cash-equivalent.
- **Dual-collateralized** — both sides escrow their full obligation at trade execution. Counterparty risk is zero because both legs of the potential swap are already locked in the same vault.
- **Oracle-triggered** — settlement is a deterministic function of one Stork-style signed price. No party needs to act at expiry; any keeper can broadcast the settle.

| Contract | Seller locks | Buyer locks | ITM condition | ITM outcome |
|---|---|---|---|---|
| `CoveredCall` | `btcSats` BTC | `strikeAmount` stablecoin | `oraclePrice > strikePrice` | Swap: seller ← stablecoin, buyer ← BTC |
| `CashSecuredPut` | `stableAmount` stablecoin | `btcSats` BTC | `oraclePrice < strikePrice` | Swap: seller ← BTC, buyer ← stablecoin |

The premium is paid MM→seller upfront, off-contract, in the same atomic funding transaction. Just like Rysk pays premium in USD upfront; here it's in stablecoin (or BTC).

### Terminology

- **ITM** = *In The Money*. The option has intrinsic value — the buyer would profit by exercising. For a call, ITM means spot is above strike (the buyer wants to buy BTC at the cheaper strike price). For a put, ITM means spot is below strike (the buyer wants to sell BTC at the higher strike price).
- **OTM** = *Out of The Money*. The option has no intrinsic value at expiry — the buyer would lose by exercising vs. transacting at spot. For a call, OTM means spot ≤ strike. For a put, OTM means spot ≥ strike.
- **ATM** = *At The Money*. Spot equals strike. In this contract ATM is bundled into the OTM branch (`>=` / `<=` boundaries) because there's no economic reason to swap at parity.
- **Strike** = the agreed reference price. For a call, the price at which the buyer can buy BTC; for a put, the price at which the buyer can sell BTC.
- **Premium** = the price the buyer paid upfront for the option, kept by the seller regardless of outcome.
- **Notional** = the BTC quantity the option is written on (`btcSats` in both contracts).

---

## Economics

The quant's worked example: spot $77k at open, strike $90k, notional 1 BTC, expiry Jun 26.

| Spot at expiry | Branch | Seller receives | Buyer receives |
|---|---|---|---|
| $80k | OTM | 1 BTC back | strike (90,000 USDT) back |
| $90k | OTM (boundary) | 1 BTC back | strike back |
| $120k | ITM | strike (90,000 USDT) | 1 BTC |

Seller capped their upside at $90k for the premium. If BTC rallies to $120k, the seller would have made $43k holding spot; instead they keep $90k strike + the premium. The premium is the compensation for ceding the upside tail.

Symmetric story for the put: seller obligated to buy BTC at $90k strike if buyer wants to sell. Spot at $60k → put ITM → seller pays $90k strike, receives 1 BTC (now worth $60k). Seller's loss is offset (partially) by the premium they collected upfront.

---

## CoveredCall

Constructor: `sellerPk, buyerPk, oraclePk, ticker, stableAssetId, btcSats, strikeAmount, strikePrice, expiryHeight, exit`

The vault holds **both** `btcSats` BTC and `strikeAmount` of `stableAssetId`. `strikeAmount` and `strikePrice` MUST satisfy `strikeAmount × 1e8 == strikePrice × btcSats`.

The two are passed as separate constructor parameters and the contract does **not** verify the equality on-chain: the cross-multiplication `strikePrice × btcSats` reaches ~1e22 for routine USDT-6-decimal positions ($100k strike × 1 BTC = 1e11 × 1e8 = 1e19), which exceeds int64 (~9.2e18). The wallet must enforce consistency at funding; both parties sign the funding tx and therefore consent to the exact values baked into the tapscript. The contract uses `strikePrice` for the ITM branch decision and `strikeAmount` for the asset-balance payout; an inconsistent pair would produce a wrong economic outcome, not a vault drain — but the misconfigured side would still lose value, so wallet enforcement is the integrity boundary. Sanity checks (`strikePrice > 0`, `oraclePrice > 0`) are emitted by `settle()`.

### Functions

**`settle(oraclePrice, oracleTime, oracleSig)`** — permissionless. Anyone supplies a fresh oracle-signed price; the contract branches on `oraclePrice > strikePrice`. ITM → physical swap at strike (output 0 = stablecoin to seller, output 1 = BTC to buyer). OTM → unwind (output 0 = BTC back to seller, output 1 = stablecoin back to buyer).

### Funding buffer (don't skip this)

The vault must be funded with **`btcSats + 330` sats** of BTC, not just `btcSats`. The +330 covers the P2TR dust carrier on the asset-bearing output at settle (every settle branch has one BTC-only output and one stablecoin-carrying output). The contract checks `outputs[i].value >= btcSats` for the BTC-only output and assumes the 330-sat carrier is available. Fund with exactly `btcSats` and no buffer → vault is unspendable. Mining fees are handled out-of-band via direct miner submission (see the OTM unwind section), so they don't eat further into the vault. The same +330 buffer applies to `CashSecuredPut`.

**`transferSeller(sellerSig, newSellerPk)`** / **`transferBuyer(buyerSig, newBuyerPk)`** — pure key swap for either leg. The continuation output preserves both legs of collateral (BTC value *and* stablecoin asset balance).

---

## CashSecuredPut

Constructor: `sellerPk, buyerPk, oraclePk, ticker, stableAssetId, stableAmount, btcSats, strikePrice, expiryHeight, exit`

Same shape, sides reversed. Vault holds both `stableAmount` of `stableAssetId` and `btcSats` BTC.

### Functions

**`settle(oraclePrice, oracleTime, oracleSig)`** — branches on `oraclePrice < strikePrice`. ITM → output 0 = BTC to seller, output 1 = stablecoin to buyer. OTM → unwind.

**`transferSeller`** / **`transferBuyer`** — same as the call: both legs preserved on continuation.

---

## Oracle model

Identical to `StabilityVault`. The oracle signs `sha256(ticker || price || timestamp)` off-chain — `price` and `timestamp` as 8-byte little-endian unsigned ints. At settle, the caller provides `(oraclePrice, oracleTime, oracleSig)` as witness arguments. The contract:

1. Enforces freshness: `tx.time - oracleTime <= 144` blocks (~24h).
2. Rebuilds the message hash on stack with `+` (OP_CAT, with int sides auto-coerced via OP_SCRIPTNUMTOLE64 so on-chain and off-chain hashing agree).
3. Verifies the signature via `checkSigFromStack`.

Three layers of replay protection:

| Field | What it prevents |
|---|---|
| `ticker` | Reusing a signature meant for one feed (BTC/USD) on a different feed (ETH/USD). The vault binds `ticker` at creation. |
| `price` | The attested value itself. |
| `timestamp` | Stale signatures fail the 6-block freshness check (tightened from the 144-block default to bound the post-expiry oracle MEV race in volatile markets). |

---

## Cooperative vs exit paths

Every function compiles to two tapleaves:

| Path | How it unlocks | What it enforces |
|---|---|---|
| Cooperative | Arkade Operator co-signs | The full `require()` chain, including the oracle verification and the ITM/OTM branch |
| Exit | N-of-N (all involved keys) + CSV after `exit` blocks | Signatures and timelock only — **no introspection** |

Arkade-wide design constraint: introspection opcodes (`OP_INSPECTOUT*`, `OP_INSPECTOUTASSETLOOKUP`, …) only live in the cooperative layer where the Operator validates them. The exit path must settle as a pure Bitcoin script, so it falls back to N-of-N consent.

For `settle` the N is **seller + buyer**. The oracle key is *not* included in the exit-leaf N-of-N: the compiler distinguishes pubkeys used in `checkSig` (transaction signers) from those used only in `checkSigFromStack` (data signers — verifying off-chain oracle signatures over byte strings). The Stork-style oracle never co-signs individual L1 transactions; including it in the N-of-N would make the unilateral exit unreachable. Filtered out by `collect_data_only_pubkeys` in the compiler, so the exit leaf stays broadcastable by the two parties alone.

Total tapleaves: **6** (CoveredCall) + **6** (CashSecuredPut) = 12.

---

## L1 unilateral exit and the pre-signed OTM unwind

The cooperative path covers ~all normal settlement. The script-level N-of-N exit covers the case where the Operator is down but the oracle and counterparty are reachable. The remaining catastrophic case — Operator **and** oracle down past expiry — needs an additional layer, because without the oracle signature the script can't reach the settle branch and without the Operator the cooperative path is closed.

The compiler-level exclusion of the oracle key from the N-of-N (see "Cooperative vs exit paths" above) is what makes this layer feasible. With seller + buyer as the only N-of-N signers, a pre-signed template needs only their two signatures captured at funding time — no oracle co-signature, which would be impossible to obtain.

### Why pre-signed ITM templates don't work

A naive plan is: at funding, both parties pre-sign the two outcome transactions (OTM-unwind and ITM-swap) with `SIGHASH_ALL`. Each template is fully specified — both parties' collateral is in the vault, both parties' payouts are known, no buyer-side UTXO contribution is needed because both legs were locked at funding.

The trap: on L1 the script can't verify the oracle, so it can't gate which template is broadcastable. Either party could broadcast whichever template favors them, regardless of the actual oracle price. There's no on-chain referee.

### What does work: pre-sign OTM only

Pre-sign **only the OTM unwind template** at funding. The template:

```
input[0]:   vault outpoint              (both parties' collateral)
output[0]:  SingleSig(sellerPk)         (btcSats BTC)
output[1]:  SingleSig(buyerPk)          (strikeAmount of stableAssetId, via OP_RETURN packet)
nLockTime:  expiryHeight + STUCK_FUNDS_TIMELOCK   (long delay - see below)
```

Both parties sign with `SIGHASH_ALL`. Everything is fully known at funding time:
- input 0 is the vault outpoint
- output 0/1 layouts are fixed by contract terms (collateral amounts, party pubkeys)
- the OP_RETURN asset packet binding stablecoin to output 1 is part of the signed template — `SIGHASH_ALL` covers all outputs including the OP_RETURN, so the asset assignment is genuinely locked

Either party can broadcast this template once `nLockTime` matures. The outcome: each side gets back their original collateral. The premium stays with the seller (already paid out off-contract at funding). The trade is **canceled**, not settled.

### Why this is acceptable as a stuck-funds fallback

OTM-unwind is the seller-favoring outcome when the option is actually ITM (seller reclaims BTC instead of paying out the strike). So there's a real worst case: if Operator + oracle stay down long enough for the pre-sig timelock to mature **and** the option would have settled ITM, the seller can broadcast the OTM template and pocket the BTC the buyer should have received.

The mitigations are timelock and trust assumptions:

1. **Long `STUCK_FUNDS_TIMELOCK`.** Set it to, say, 1008 blocks (~1 week) past expiry. This gives the Operator + oracle ample time to come back online and trigger the correct settle. Pre-signed OTM activates only as a *last resort* when the protocol has been catastrophically offline for a week.
2. **Oracle independence.** Stork and the Arkade Operator are independent third parties. Both failing simultaneously for >1 week is unlikely.
3. **Bounded loss.** Even in the worst case, the buyer loses only their *potential ITM gain*, not their principal. The strike cash they locked is returned in full. They paid the premium upfront knowing this; the OTM unwind is equivalent to the option expiring worthless from their side.

This is the standard "stuck funds protection" pattern from Lightning: a fallback state that's not always the *correct* outcome but ensures funds aren't permanently locked.

### What the SDK has to do at funding

1. Wait for the funding tx to confirm so the vault outpoint is fixed.
2. Construct the OTM unwind template with `nLockTime = expiryHeight + STUCK_FUNDS_TIMELOCK`.
3. Both parties sign with `SIGHASH_ALL`. The two-of-two N-of-N signatures (`<sellerPkSig>` + `<buyerPkSig>`) are exactly what the exit leaf consumes — no oracle key needed because the compiler filters checkSigFromStack-only pubkeys out of the N-of-N.
4. Both parties (and ideally Arkade backup infra) store the signed template.
5. After `nLockTime` matures, either party can broadcast.

### Fee handling for the pre-signed template

`SIGHASH_ALL` commits to every output, including any fee-bearing output, so on-chain fee bumping (CPFP via an anchor output, RBF) isn't available against the signed template. The mitigation is **out-of-band fee payment**: direct submission to a miner / accelerator service (e.g. Mempool.space accelerator, MARA Slipstream, Slipstream-style direct-to-miner endpoints). The static on-chain fee in the template can be set to zero or near-zero; the OOB payment covers the actual mining cost at broadcast time. This keeps the pre-signed template valid indefinitely regardless of how the on-chain fee market moves.

For the cooperative + N-of-N exit paths the SDK does its usual thing — no pre-signing required.

### Why not pre-sign transfers

Transfers are interactive secondary-market trades. The next-holder's pubkey doesn't exist at funding time, so there's nothing to pre-sign. Both parties have to be online for the trade anyway.

---

## Lifecycle

```
1. Pricing & match (off-chain): buyer and seller agree on premium,
   strike, expiry via RFQ or direct quote.
2. Funding tx (atomic, both parties online):
     - Seller's collateral  -> vault
     - Buyer's collateral   -> vault
     - Premium              -> seller's wallet (off-contract)
     - Both parties sign the OTM unwind template (SIGHASH_ALL,
       nLockTime = expiryHeight + STUCK_FUNDS_TIMELOCK), store the
       signed template.
3. Pre-expiry: vault sits. Either party may transfer their leg via the
   cooperative path (the next-holder is the variable, so transfers can't
   be pre-signed in advance).
4. At/after expiryHeight: anyone supplies an oracle-signed price and
   broadcasts settle() — cooperative if Operator is up, N-of-N exit
   otherwise.
5. Stuck-funds path: if expiryHeight + STUCK_FUNDS_TIMELOCK passes with
   no settlement, either party broadcasts the OTM unwind template. Each
   side gets back their original collateral.
```

---

## Risk disclosures (wallet UX)

1. **European exercise.** Settlement only happens at or after `expiryHeight`, triggered by the oracle. Before then the vault is locked.
2. **Premium is non-refundable.** Paid in the funding tx, off-contract. Seller keeps it regardless of how the option settles.
3. **Oracle dependency.** Settlement requires a fresh oracle signature. If the oracle is offline at expiry the cooperative and N-of-N exit paths are both blocked until it resumes.
4. **Stuck-funds fallback unwinds, not settles.** If both the Operator and the oracle stay offline for `STUCK_FUNDS_TIMELOCK` past expiry, the pre-signed OTM template can be broadcast by either party. This returns original collateral to each side regardless of what the actual settlement outcome should have been. The buyer can lose their ITM gain in this rare case; their principal (strike cash) is not at risk.
5. **Counterparty risk = zero (by design).** Both sides' obligations are escrowed in the vault from funding. There is no scenario where one side defaults on their delivery — the assets are already on-chain.
