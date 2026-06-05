# Options — How It Works

**Status:** v2 — single-locked Rysk-faithful design (supersedes the earlier dual-locked variant in PR #33)

---

## What it is

Two paired contracts for selling and buying volatility on Bitcoin, faithful to Rysk Finance v12's covered call and cash-secured put. Both contracts are:

- **European** — settleable only at `expiryHeight`.
- **Physically settled** — at exercise the actual underlying changes hands (BTC ↔ stablecoin), not a cash-equivalent.
- **Single-collateralized** — *only the seller* escrows their full obligation. The buyer brings the strike payment at exercise time if and only if they choose to exercise. This is the capital-efficient MM model — Rysk's RFQ counterparties don't tie up the strike value of every option they write.
- **No oracle** — the buyer's voluntary exercise decision *is* the settlement signal. A rational buyer exercises iff in-the-money; if they don't show up, the seller reclaims after a grace window.

| Contract | Seller locks | Buyer brings at exercise | ITM condition |
|---|---|---|---|
| `CoveredCall` | `btcSats` BTC | `strikeAmount` stablecoin | spot > strike (buyer wants to buy BTC at the cheaper strike) |
| `CashSecuredPut` | `stableAmount` stablecoin | `btcSats` BTC | spot < strike (buyer wants to sell BTC at the higher strike) |

The premium is paid MM→seller upfront, off-contract, in the same atomic funding transaction. Same model as Rysk pays premium in USD upfront.

### Terminology

- **ITM** = *In The Money*. The option has intrinsic value — the buyer profits by exercising.
- **OTM** = *Out of The Money*. No intrinsic value. The buyer rationally walks away.
- **Strike** = the agreed reference price. The amount of stablecoin the buyer pays (call) or receives (put) per unit of BTC.
- **Premium** = the price the buyer paid upfront. Seller keeps it regardless of outcome.
- **Notional** = the BTC quantity the option is written on (`btcSats`).
- **Grace window** = `[expiryHeight, expiryHeight + graceBlocks)` — the buyer's exercise opportunity.

---

## Why this design vs. the previous dual-locked variant

The earlier `CoveredCall` / `CashSecuredPut` (PR #33, master commit `501193a`) had both parties pre-lock their full exposure: seller's BTC *and* buyer's strike payment, settled deterministically by an oracle. That was a misread of Rysk's mechanics — confirmed by the quant after merge.

Rysk's actual model has only the seller locked. The MM commits no capital until exercise (they only ever pay strike if the option is ITM and they choose to exercise). This is what makes the RFQ market work: MMs can write many options against the same float because most expire OTM and never need a payout.

The dual-locked variant has its own merits (zero counterparty risk, fully autonomous settlement, no buyer liveness required), but it's not Rysk and it's not capital-efficient enough for production MM use. This PR replaces it with the faithful design.

---

## Economics

Worked example: 1 BTC notional, $90k strike, expiry Jun 26. MM pays seller $1,500 premium upfront.

| Spot at expiry | Exercise? | Seller ends with | Buyer ends with |
|---|---|---|---|
| $80k (OTM) | No | 1 BTC + $1,500 premium | nothing besides their lost premium |
| $90k (ATM) | Indifferent | ~1 BTC + premium | $0 PnL net of premium |
| $120k (ITM, exercised) | Yes | $90,000 USDT + premium | 1 BTC (worth $120k now) for $90k strike — $28,500 PnL net of premium |
| $120k (ITM, **buyer ghosts**) | No | 1 BTC + premium (free upside) | −premium (gave up ITM gain) |

Last row is the seller's "Christmas morning" outcome from the quant's note: ITM + buyer fails to exercise = seller keeps the appreciated BTC plus the premium. The buyer's only protection against this is showing up at expiry.

Mirror story for the put. If buyer holds 1 BTC put at $90k strike and spot drops to $60k: rational buyer exercises (delivers BTC, takes $90k cash, net $30k gain less premium); if they don't exercise, seller keeps the cash plus the premium.

---

## CoveredCall

Constructor: `sellerPk, buyerPk, stableAssetId, btcSats, strikeAmount, expiryHeight, graceBlocks, exit`

Vault holds **only** `btcSats` BTC. `strikeAmount` is the total stablecoin payment due at exercise (strike × notional, in base units of the chosen stablecoin).

### Functions

**`exercise(buyerSig)`** — buyer pays `strikeAmount` of `stableAssetId` to seller and takes the BTC. Valid from `expiryHeight` onward. The buyer brings their stablecoin inputs at this point — no pre-lock.

**`reclaim(sellerSig)`** — seller takes the BTC back after `expiryHeight + graceBlocks`. Once this height is reached, seller and any pending buyer exercise are in a race; rational seller broadcasts immediately to capture the windfall if the buyer didn't show up.

**`transferSeller(sellerSig, newSellerPk)`** / **`transferBuyer(buyerSig, newBuyerPk)`** — pure key swap, pre-expiry only. BTC collateral preserved on the continuation output.

### Exercise transaction layout

```
input[0]:   CoveredCall UTXO         (btcSats BTC)
input[1+]:  buyer's stablecoin inputs (>= strikeAmount + buyer's BTC fee)
output[0]:  SingleSig(sellerPk)      (strikeAmount of stableAssetId)
output[1]:  SingleSig(buyerPk)       (btcSats BTC)
output[2+]: buyer's change           (unconstrained)
```

---

## CashSecuredPut

Constructor: `sellerPk, buyerPk, stableAssetId, stableAmount, btcSats, expiryHeight, graceBlocks, exit`

Vault holds **only** `stableAmount` of `stableAssetId` (and a dust BTC carrier for L1). Same shape as the call, sides reversed.

### Functions

Same four — `exercise`, `reclaim`, `transferSeller`, `transferBuyer`. In `exercise`, output 0 collects the buyer's BTC delivery and output 1 takes the locked stablecoin. Transfers preserve the **stablecoin asset balance** on the continuation (not BTC value — vault holds the asset).

### Exercise transaction layout

```
input[0]:   CashSecuredPut UTXO      (stableAmount of stableAssetId)
input[1+]:  buyer's BTC inputs       (>= btcSats + buyer's BTC fee)
output[0]:  SingleSig(sellerPk)      (btcSats BTC)
output[1]:  SingleSig(buyerPk)       (stableAmount of stableAssetId)
output[2+]: buyer's BTC change       (unconstrained)
```

---

## Funding buffer

The vault must hold the seller's collateral **plus a dust carrier for the L1 spend output that needs to carry the asset**:

- `CoveredCall`: fund the vault with `btcSats + 330` sats. At exercise, the BTC-only output to the buyer takes `btcSats`; the stablecoin payment output to the seller takes the 330-sat dust carrier from the vault.

  *Wait — that's not right for this design*. In the single-locked model, the buyer is providing the stablecoin **and** is constructing the tx. The buyer can fund the carrier from their own input. The vault only ever needs to provide `btcSats` to one output. So:

  **Fund the vault with exactly `btcSats`.** The buyer's tx construction handles all carriers and fees. The contract's `>= btcSats` check works against the vault-input amount directly.

- `CashSecuredPut`: vault holds `stableAmount` of `stableAssetId` plus a 330-sat dust carrier (the bare minimum BTC to make the asset-carrying UTXO non-dust). At exercise, the buyer brings BTC; the 330-sat carrier just rides along into one of the output dust carriers.

Mining fees: handled out-of-band via direct miner submission for pre-signed paths; the cooperative path is fee-subsidized by the Operator. Vault sizing doesn't have to absorb fees.

---

## Cooperative vs exit paths

Every function compiles to two tapleaves:

| Path | How it unlocks | What it enforces |
|---|---|---|
| Cooperative | party-sig + Arkade Operator co-sig | Full `require()` chain including time guards and asset lookups |
| Exit | N-of-N party-sigs + CSV after `exit` blocks | Signatures + relative timelock only — **no introspection** |

For `exercise` the exit-leaf N is **seller + buyer**. For `reclaim` it's **seller**. For transfers it's **seller + buyer + new party**. The compiler also emits CLTV (`OP_CHECKLOCKTIMEVERIFY`) in the exit variant of `reclaim` because that's pure Bitcoin script — `expiryHeight + graceBlocks` is checked on the exit path too.

Total tapleaves: **8** (CoveredCall) + **8** (CashSecuredPut) = 16.

### Known compiler limitations

Two minor codegen quirks surface in the compiled ASM:

1. **`tx.time < expiryHeight` on transfers compiles to non-functional placeholders** in the exit variant. The cooperative path Operator validates this off-chain, but the script doesn't enforce the upper bound on the exit path. Mitigation: the exit-path transfer requires N-of-N (seller + buyer + new party); a post-expiry transfer would need both parties' active consent, which removes the unilateral griefing vector.

2. **`reclaimHeight = expiryHeight + graceBlocks` is computed but pushed as a separate `<reclaimHeight>` placeholder for `OP_CHECKLOCKTIMEVERIFY`.** The SDK has to substitute `reclaimHeight = expiryHeight + graceBlocks` when building the witness. Documented for SDK authors; the OP_ADD64 + OP_VERIFY chain validates the arithmetic, the placeholder carries the value to CLTV.

Both are upstream compiler issues, not contract bugs. They don't affect security; the cooperative path remains fully validated and the exit path remains broadcastable.

---

## Why the buyer is incentivized to exercise (and the unilateral-exit question)

The buyer has paid the premium upfront. If the option is ITM at expiry, the buyer's expected profit from exercise is `(spot − strike) × notional − fees − premium`. If positive, they exercise. If the buyer doesn't broadcast within the grace window, the seller's reclaim path matures and the buyer loses both the premium and the ITM gain.

This makes the design self-policing in the happy case: economically rational buyers always exercise when ITM, regardless of which path is available. The Operator-down case is the only edge:

- **Operator down + option ITM + buyer wants to exercise**: the cooperative path is closed. The exit path requires seller + buyer + CSV — but the seller has every incentive NOT to sign, since they keep the BTC if exercise fails. The buyer cannot unilaterally exercise on L1.

The mitigations are off-contract:
- **Pre-signed exit-path exercise template**: at funding, both parties pre-sign a canonical exercise tx with `SIGHASH_ALL`. The seller's signature is captured while they're online; the buyer assembles their stablecoin inputs and broadcasts at exercise time. Requires the buyer to commit to specific stablecoin UTXOs at funding (or use `SIGHASH_ANYONECANPAY` to add inputs later — but then the asset packet binding output 0 to the seller is at risk if not at the same index as the signed input).
- **Operator commit**: trust the Operator to be live. Realistically, this is what Rysk does on Hyperliquid — protocol liveness is the integrity boundary.

The original dual-locked design avoided this by making settlement oracle-triggered and party-agnostic. It traded capital efficiency for liveness independence. Trade-off the user picks.

---

## Lifecycle

```
1. Off-chain pricing & match: buyer and seller agree on strike, expiry,
   graceBlocks, premium.
2. Funding tx (both parties online):
     - Seller's collateral  -> vault
     - Premium              -> seller's wallet (off-contract)
     - (Optional) Both parties pre-sign exit-path exercise template
3. Pre-expiry: vault sits. Either party may transfer their leg via the
   cooperative path; transfers locked at expiryHeight.
4. At expiryHeight: exercise window opens.
   - Buyer evaluates ITM/OTM at live spot.
   - If ITM: buyer constructs and broadcasts exercise tx, paying strike,
     taking the underlying. Cooperative (fast) or exit-path with pre-sig.
   - If OTM: buyer does nothing.
5. At expiryHeight + graceBlocks: reclaim window opens.
   - Seller broadcasts reclaim, taking back whatever's in the vault.
   - Race between seller's reclaim and any belated buyer exercise; seller
     wins by default (rational broadcast is at the first valid block).
```

---

## Risk disclosures (wallet UX)

1. **Buyer must show up at expiry.** Unlike fully-automated derivatives, the buyer has to actively exercise. A buyer who's offline during the grace window forfeits both their premium and any ITM gain. Wallets MUST surface this prominently and ideally automate the exercise broadcast.
2. **Premium is non-refundable.** Paid upfront, off-contract.
3. **No oracle dependency.** Pricing is the buyer's responsibility at exercise time. Wallets should integrate spot price feeds for the ITM/OTM decision but the contract itself doesn't need one.
4. **Seller liveness asymmetry on operator-down.** If the Operator is offline at expiry and the option is ITM, the buyer cannot force exercise via the exit path alone (it requires seller co-sig, which they have every reason to withhold). Pre-signed exit templates mitigate but don't fully solve. For high-value positions, prefer the dual-locked variant (PR #33) which has fully autonomous oracle-triggered settlement at the cost of capital efficiency.
5. **Counterparty risk is asymmetric.** Seller's BTC delivery is trustless (collateral is escrowed). Buyer's strike payment is a "soft" obligation — they only pay if they exercise. The seller's worst case is that the buyer fails to exercise when ITM, which is good for the seller, not bad.
