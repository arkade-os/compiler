# LVGA payout bridge (Arkade → SwissLedger) + stable-value option

A merchant-payment bridge-out for wrapped LVGA. Real **LVGA** sits in a
liquidity pool on **SwissLedger** (an EVM chain); wrapped **wLVGA** — a
BTC-backed bearer claim — is spent on Arkade to trigger an LVGA payout to a
merchant. This PR is the productization layer; the general bridging research
(attested / SPV deposits, HTLC swaps) lives separately.

Contracts:

- [`wlvga_payout.ark`](wlvga_payout.ark) — the Arkade payout leg.
- [`swissledger_pool.md`](swissledger_pool.md) — spec for the EVM pool
  contract that automatically releases LVGA (Flavor A).
- [`../stability/stability_lvga_payout.ark`](../stability/stability_lvga_payout.ark)
  — the stable-value variant, backing the spending balance with a
  Bitcoin-collateralized, oracle-marked CHF claim.

## Hard requirement: LVGA is transfer-restricted

Only whitelisted addresses hold LVGA, and it flows one way (pool → merchant):
**wLVGA can never be redeemed for LVGA.** So wLVGA is *not* a wrapper you
unwrap — it is a BTC-backed bearer instrument, liquidatable for BTC only. The
BTC side and the LVGA side are connected solely through the liquidity
provider's balance sheet, which is why the payout must compensate the LP in
BTC, not in LVGA.

## `wlvga_payout.ark` — two payout modes

The wLVGA is a claim on the BTC a user locked at mint time. Two roles may be
**separate parties**: the BTC side (issued wLVGA, holds the BTC backing) and
the **LVGA liquidity provider (LP)** who funds the pool. A naive burn
compensates no one, so:

- **`payOut()` — two parties (default).** The wLVGA claim is **transferred to
  the LP**, not destroyed. The LP releases LVGA on SwissLedger and receives
  the BTC-backed claim on Arkade (redeemable for BTC, never for LVGA), so the
  BTC side and the LP can be different entities and the LP stays solvent.
- **`burnOut()` — same party (option).** The wLVGA is **burned**. Only solvent
  when the LP is *also* the party that received the BTC at mint time (an
  integrated market maker). Kept for deployments that are one legal entity.

Both modes:

- **Authorize** the payee with the merchant's secp256k1 key via
  `checkSigFromStack` over
  `sha256(protocolTag ‖ merchantEvmAddr ‖ amount ‖ burnNonce)`;
- **Commit** an OP_RETURN output `protocolTag ‖ merchantEvmAddr ‖ num2bin(amount, 8)`
  that the SwissLedger pool reads;
- Bound replay with `burnNonce`.

`merchantPk`/`merchantSig` (pubkey/signature) appear **only** inside
`checkSigFromStack` — never in a `+` concat — so every hashed/committed field
is bytes/int and `+` lowers to `OP_CAT`, matching the merchant's off-chain
signing and the EVM reconstruction byte-for-byte.

**LP economics.** Because LVGA is one-way, the LP is a market maker: per
payout it gives up **LVGA** (a CHF-pegged position), receives **BTC** via the
wLVGA claim (hedgeable to USDT), and earns **fees** priced into its quote —
CHF/BTC exposure for fee income, with the covenant guaranteeing it is paid in
BTC for every LVGA payout it services.

## One key, two chains

EVM and Bitcoin/Arkade both use **secp256k1**, so a single merchant key is
verified two ways over the *same* message: `checkSigFromStack` on Arkade and
`ecrecover` on the SwissLedger pool. The 20-byte `merchantEvmAddr` is committed
in the OP_RETURN (explicit, auditable payee) and the signature rides the
witness for the EVM `ecrecover`. See `swissledger_pool.md`.

## Automated release (Flavor A)

The destination pool contract releases LVGA **automatically** on a valid
report — the operator cannot withhold or redirect a payment. A trusted
reporter attests the Arkade burn/transfer happened, but the contract's
`ecrecover` + whitelist + `paid[burnNonce]` checks keep the reporter contained
to **liveness**, not correctness; with reporter = pool operator it is
incentive-aligned (a false report drains the operator's own pool for no BTC).
Full spec, byte layout, and reference Solidity in `swissledger_pool.md`.

## Stable-value payouts (stability-vault fusion)

`wlvga_payout` spends a **BTC-backed** claim — its value floats with BTC
between mint and spend. For a peg-stable spending balance, fuse the payout
with a stability vault:
[`../stability/stability_lvga_payout.ark`](../stability/stability_lvga_payout.ark).

`stability_vault.ark` manufactures a BTC-collateralized, oracle-marked fiat
claim (seeker holds a fixed target; provider posts collateral and carries the
price risk; funding compensates them). Point the `ticker` at a **CHF/BTC**
feed and the claim is synthetic CHF. `StabilityPayout.seekerPayout()` settles
it *not* to BTC for the seeker but as a **CHF-denominated LVGA payment**:

- funding accrues, the exit fee applies → `payoutCHF`;
- the merchant invoice is verified (`checkSigFromStack`, mirrored by EVM
  `ecrecover`) and committed in the OP_RETURN as `payoutCHF`;
- the seeker's BTC entitlement at the oracle price (`seekerRaw`) goes to the
  **LP**; the collateral remainder returns to the **provider**.

The same oracle prices both sides, so the merchant receives exactly the
claim's CHF value regardless of BTC moves during the holding period.
Crucially this is **where the CHF/BTC exposure lives**: the vault provider
carries it as a funded, over-collateralized, oracle-marked position — not the
bridge LP and not the user. Set `lpPk = providerPk` to run both roles as one
**delta-neutral market maker**; keep them distinct for two independent
parties.

Net, the full launch flow is a single stable-value rail: **BTC → CHF
stability-vault claim → LVGA merchant payment**, one oracle, one settlement,
with price risk isolated in the vault and the destination release automated by
the SwissLedger pool.

## Trust model

| Property | Where the trust sits |
|---|---|
| Payout authorization | On-chain — a valid spend + merchant signature; no quorum signs the release |
| LP solvency (two-party) | `payOut` transfers the BTC-backed claim to the LP; the LP is paid **in BTC** (LVGA is one-way) — BTC side and LP may differ |
| Pool liquidity | The SwissLedger pool must hold enough LVGA to service payouts |
| Release automation | The pool contract releases automatically on a valid report; residual is a **trusted reporter** (Flavor A) — liveness only, contained by `ecrecover`/whitelist/nonce |
| Price risk (stable variant) | Carried by the **stability-vault provider** (funded, over-collateralized, oracle-marked), not the bridge |
| Correct payee | `ecrecover` on EVM + the committed `evmAddr`; the merchant key binds both chains |

## Local checks

```bash
cargo run -- examples/bridge/wlvga_payout.ark -o /tmp/wlvga_payout.json
cargo run -- examples/stability/stability_lvga_payout.ark -o /tmp/stability_lvga_payout.json
cargo test --test examples wlvga_payout
cargo test --test examples stability_lvga_payout
```
