# Options — How It Works

**Status:** v1 design complete

---

## What it is

Two paired contracts for selling and buying volatility on Bitcoin, inspired by Rysk Finance v12 and feasible on Arkade once wrapped USDT/USDC is live as a native asset:

| Contract | Seller locks | Buyer holds | Exercise direction |
|---|---|---|---|
| `CoveredCall` | BTC | the right to buy BTC at strike | Buyer pays USDT, receives BTC |
| `CashSecuredPut` | USDT (= strike × notional) | the right to sell BTC at strike | Buyer delivers BTC, receives USDT |

Both are **European-style** (only exercisable in a window opening at `expiryHeight`), **physically settled** (real on-chain BTC ↔ USDT swap), and **oracle-free** (the buyer's exercise decision *is* the settlement signal).

The premium is paid off-contract in the funding transaction — same model as Rysk pays premium upfront in USD, only here it's in BTC or USDT depending on which side you're on.

---

## Economics

The quant's worked example for the call (spot = $77k at open, strike = $90k, notional = 1 BTC, expiry = Jun 26):

| Spot at expiry | Buyer exercises? | Seller keeps | Buyer receives | Buyer's USD P&L vs. premium |
|---|---|---|---|---|
| $80k (OTM) | No | 1 BTC | nothing | −premium |
| $90k (ATM) | Indifferent | 1 BTC or USDT-equivalent | mirror | ~−premium |
| $120k (ITM) | Yes | 90k USDT | 1 BTC | +(120k − 90k) − premium |

The seller capped their upside at $90k in exchange for the premium. If BTC rallies to $120k, the seller would have made $43k holding spot (1 BTC × ($120k − $77k)) — instead they keep the $90k strike plus the premium. The premium is the compensation for ceding that tail.

Symmetric story for the put — seller has obligated themselves to buy BTC at strike if the buyer wants to sell, in exchange for the premium.

---

## CoveredCall

Constructor: `sellerPk, buyerPk, stableAssetId, btcSats, strikeAmount, expiryHeight, graceBlocks, exit`

Vault holds `btcSats` of BTC. `strikeAmount` is the total stablecoin payment due (strike × notional in base units of the stablecoin).

### Functions

**`exercise(buyerSig)`** — buyer pays `strikeAmount` of `stableAssetId` to seller and receives the BTC. Only valid inside `[expiryHeight, expiryHeight + graceBlocks)`. Atomic single-tx swap.

**`reclaim(sellerSig)`** — seller takes the BTC back after the exercise window closes. Pure unlock — no introspection.

**`transferSeller(sellerSig, newSellerPk)`** / **`transferBuyer(buyerSig, newBuyerPk)`** — pure key swap for either leg. Collateral and terms preserved.

### Exercise transaction layout

```
input[0]:   CoveredCall UTXO         (btcSats BTC)
input[1+]:  buyer's USDT inputs      (>= strikeAmount + fees)
output[0]:  SingleSig(sellerPk)      (strikeAmount of stableAssetId)
output[1]:  SingleSig(buyerPk)       (btcSats BTC)
output[2+]: buyer's USDT change      (unconstrained)
```

---

## CashSecuredPut

Constructor: `sellerPk, buyerPk, stableAssetId, stableAmount, btcSats, expiryHeight, graceBlocks, exit`

Vault holds `stableAmount` of `stableAssetId` (and dust BTC). `stableAmount = strike × notional`.

### Functions

Same four functions, sides reversed:

**`exercise(buyerSig)`** — buyer delivers `btcSats` BTC to seller and receives the locked `stableAmount`. Same exercise window.

**`reclaim(sellerSig)`** — seller takes the stablecoin back after the window. The exit path's seller-only sig + CSV reclaims the asset (no introspection needed — sole-signer + timelock suffices).

**`transferSeller`** / **`transferBuyer`** — pure key swaps. The continuation output's stablecoin balance is verified via `assets.lookup` (the put's collateral lives in the asset slot, not in BTC value — that's the key shape difference from the call).

### Exercise transaction layout

```
input[0]:   CashSecuredPut UTXO      (stableAmount of stableAssetId)
input[1+]:  buyer's BTC inputs       (>= btcSats + fees)
output[0]:  SingleSig(sellerPk)      (btcSats BTC)
output[1]:  SingleSig(buyerPk)       (stableAmount of stableAssetId)
output[2+]: buyer's BTC change       (unconstrained)
```

---

## Cooperative vs exit paths

Every function compiles to two tapleaves:

| Path | How it unlocks | What it enforces |
|---|---|---|
| Cooperative | party-sig + Arkade Operator co-sig | Full `require()` chain, including asset lookups and scriptPubKey checks |
| Exit | N-of-N party-sigs + CSV after `exit` blocks | Only the signatures and the timelock — **no introspection** |

This split is an Arkade-wide design constraint: introspection opcodes (`OP_INSPECTOUT*`, `OP_INSPECTOUTASSETLOOKUP`, …) live only in the cooperative layer, where the Operator validates them. The exit path has to settle as pure Bitcoin script, so it falls back to N-of-N consent + a relative timelock.

Total tapleaves: **8** (CoveredCall) + **8** (CashSecuredPut) = 16.

---

## The unilateral-exit problem

The exit path's N-of-N requirement creates a liveness issue. After the Operator goes offline:

| Scenario | Can it proceed unilaterally? |
|---|---|
| Seller reclaims after grace | **Yes** — `reclaim` has no introspection, so its exit leaf is just seller-sig + CSV. Single signer. |
| Buyer exercises during window | **No** — `exercise` exit leaf is seller + buyer + CSV. Seller's signature is required at exercise time, and the seller has no incentive to sign post-hoc (it costs them the strike-vs-spot difference). |
| Either party transfers | **No, and don't bother** — transfers are interactive trades; you'd renegotiate fresh. |

The seller-veto on `exercise` is the real problem. Left unaddressed, a hostile or simply unreachable seller can deny the buyer their exercise rights any time the Operator is down.

---

## Pre-signed exit transactions

The fix is the ARK-native pattern: **capture the seller's exercise signature at funding time**, when both parties are necessarily online. The buyer holds that pre-signed template and can broadcast it unilaterally when the exercise window opens.

The SIGHASH flag is the key. The seller signs the canonical exercise template with:

```
SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
```

What this commits to:

| Flag | Commits to | Free for the buyer to change |
|---|---|---|
| `SIGHASH_ANYONECANPAY` | **only** input 0 (the vault) | Add/remove other inputs (their USDT) |
| `SIGHASH_SINGLE` | **only** output 0 (the strike payment to seller) | Set output 1, 2, … freely (their BTC + change) |

Plain English: *"I authorize this vault to be spent, so long as output 0 pays me `strikeAmount` of `stableAssetId`."* The buyer can attach their USDT however they like and route the BTC wherever they want.

### What gets pre-signed for each function

| Function | Pre-signer | SIGHASH | Stored by | Broadcast by |
|---|---|---|---|---|
| `CoveredCall.exercise` | Seller | `SINGLE \| ANYONECANPAY` on output 0 (strike to seller) | Buyer | Buyer, during the window |
| `CoveredCall.reclaim` | n/a — only seller's runtime sig + CSV | n/a | n/a | Seller, after grace |
| `CashSecuredPut.exercise` | Seller | `SINGLE \| ANYONECANPAY` on output 1 (cash to buyer) — see note | Buyer | Buyer, during the window |
| `CashSecuredPut.reclaim` | n/a | n/a | n/a | Seller, after grace |

**Note on the put**: the seller's pre-sig must constrain the output that pays the buyer (output 1 — the stablecoin returning to the buyer). `SIGHASH_SINGLE` commits to the output at the *same index* as the signed input. Since the vault is input 0, the pre-sig naturally commits to output 0 (the seller's BTC payment). That's also the right thing — the seller binds *what they're paid*. The buyer pre-signs the symmetric template binding their own input (the BTC they're delivering) — together the two pre-sigs lock both legs of the swap.

### Concrete exercise flow (CoveredCall, server offline)

```
At funding (both parties online):
  1. Build the exercise template:
     input[0]  = vault outpoint (sighash will be ANYONECANPAY|SINGLE)
     output[0] = SingleSig(sellerPk), strikeAmount of stableAssetId
     (outputs 1+ left blank)
  2. nLockTime = expiryHeight       ← absolute lower-bound timelock
  3. Seller signs input[0] with ANYONECANPAY|SINGLE
  4. Buyer stores the signed template

At exercise (buyer alone, after expiryHeight):
  5. Buyer fills in:
     input[1+]  = their USDT inputs
     output[1]  = SingleSig(buyerPk), btcSats BTC
     output[2+] = USDT change
  6. Buyer signs their own inputs
  7. Broadcast
```

Both ends of the exercise window are enforced:
- **Lower bound** (`tx.time ≥ expiryHeight`): the `nLockTime` field on the template — the template cannot be mined any earlier.
- **Upper bound** (`tx.time < expiryHeight + graceBlocks`): implicit, via the seller's `reclaim` pre-sig becoming spendable at that height. Once `reclaim` is broadcast and confirmed, the vault is gone and the buyer's pre-sig is dead. Within the grace window the buyer holds the only valid pre-sig; outside it, it's a race the buyer should lose.

### What the wallet/SDK needs to do

At funding time, the wallet must:

1. Construct the canonical exercise template for each option position.
2. Collect the seller's `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` signature on input 0.
3. Set the template's `nLockTime = expiryHeight`.
4. Hand the template + signature to the buyer's wallet for storage (and ideally back it up via Arkade infrastructure).

At exercise time the buyer's wallet:

1. Loads the stored template.
2. Attaches their USDT input(s).
3. Sets the BTC payout output.
4. Signs their own inputs + input 0 (their N-of-N signature on the vault).
5. Broadcasts.

For `reclaim`, no pre-signing is needed — the seller's exit leaf already requires only their own signature after the CSV matures.

### Why we *don't* pre-sign transfers

Transfers (`transferSeller` / `transferBuyer`) are interactive secondary-market trades. There's no canonical "transfer this to X" template at funding time because X doesn't exist yet. Each transfer is a fresh negotiation between the holder and the next holder, and the new party's pubkey is the variable. Pre-signing offers no value — both parties have to be online for the trade anyway.

### Limitations

- **Output layout is fixed.** The seller's pre-sig pins output 0 to the strike payment. The buyer can't add internal splits or route the strike to a different index without a fresh seller sig. For an option this is fine — the buyer's only on-chain choice is "exercise or don't."
- **No partial exercise.** The pre-sig commits to the full notional. Supporting partial exercise would require pre-signing N fractional templates at funding time, which isn't worth it for an MVP.
- **Race after grace.** If the buyer doesn't exercise within the window, both pre-sigs (exercise and reclaim) are technically spendable. The seller should win the race by broadcasting reclaim immediately at `expiryHeight + graceBlocks`, but this depends on liveness rather than script. Setting a generous `graceBlocks` (say 144 blocks ≈ a day) is the practical mitigation.

---

## Lifecycle

```
1. Pricing & match (off-chain): buyer and seller agree on premium, strike, expiry.
2. Funding tx (both parties online):
     - Seller's collateral → CoveredCall or CashSecuredPut vault
     - Premium → seller's wallet
     - Both parties pre-sign exercise + reclaim templates
3. Pre-expiry: vault sits; either party may transfer their leg via the
   cooperative path (or via a fresh N-of-N if the Operator is down).
4. Exercise window opens at expiryHeight:
     - Buyer exercises (cooperative or unilateral with pre-sig)
     - Or buyer abstains → seller reclaims after grace
5. Vault consumed. Both parties hold their post-settlement UTXOs.
```

---

## Risk disclosures (wallet UX)

1. **European exercise only.** The option is worthless before `expiryHeight` and after `expiryHeight + graceBlocks`. The wallet must surface the window prominently.
2. **Buyer must show up in the window.** Even with pre-signed exit transactions, the buyer's wallet has to broadcast within the grace period. A wallet that's offline through expiry loses the option.
3. **Premium is non-refundable.** Paid in the funding tx, off-contract. If the option expires OTM, the buyer's premium is the seller's profit.
4. **No partial exercise.** All-or-nothing for the full notional.
5. **Operator-down liveness depends on the pre-sign protocol.** If your wallet didn't capture the seller's exercise pre-sig at funding time, you cannot exercise unilaterally — only cooperatively through the Operator.
