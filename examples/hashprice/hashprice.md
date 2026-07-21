# Hashprice Options for Miners

Hashprice is a miner's revenue per unit of hashrate-time (e.g. per PH/s per
day). It is the single number a mining operation's top line depends on, and it
moves with BTC price, network difficulty and fees. These contracts let a miner
hedge that number directly on Arkade, with BTC collateral, using plain
European options — no perps, no margin accounts.

Two vaults implement the same primitive in the two quote currencies:

| File | Contract | Quote | Settlement |
|---|---|---|---|
| `hashprice_btc_vault.ark` | `HashpriceBtcVault` | sats per contract | single oracle fixing, exact split, fully collateralized |
| `hashprice_usd_vault.ark` | `HashpriceUsdVault` | USD cents per contract | hashprice + BTC/USD fixings, payout capped by escrow |

One vault exists per (oracle feed, price band, maturity) — a listed option
series. A "contract" is a fixed quantity of hashrate-time (e.g. 100 PH·days),
set off-chain for the series; prices are quoted per contract.

## The primitive: a two-token range vault

Each vault carries a price band `[lowPrice, highPrice]`. Depositing collateral
mints equal amounts of two fungible Arkade Assets and burning a matched pair
redeems it 1:1 — issuance can never be mispriced. At maturity the pot splits
by the oracle fixing S:

```
UP   (call spread):  clamp(S − lowPrice,  0, width)   per pair
DOWN (put  spread):  clamp(highPrice − S, 0, width)   per pair
```

UP + DOWN always equals the escrowed width, so the vault holds exactly the
right BTC at every price: no margin calls, no liquidations, no keeper bots.
With `lowPrice = 0`, UP is the full underlying exposure and DOWN a plain put
struck at `highPrice`.

The premium never touches the contract. Option legs are ordinary Arkade
Assets, so they trade on the order book: miners and market makers place
standing orders on UP/DOWN tokens with **Arkade intents**, and the market
price of a leg *is* its premium.

## Miner strategies

Everything the desk needs reduces to holding or selling the two legs:

- **Long put on hashprice — insure the downside.** Buy DOWN tokens of a vault
  whose `highPrice` is the strike. If hashprice falls, DOWN pays out exactly
  the shortfall in mining revenue per contract of hashrate covered. The miner
  receives a payoff equal to the loss in mining revenues.

- **Short call on hashprice — sell the upside.** Mint pairs (escrowing the
  band width per pair), keep DOWN, sell UP via an intent. The sale proceeds
  are the premium received. If hashprice rises, the rig earns the increase
  while the sold UP leg pays it out — the miner pays a payoff equal to the
  increase in mining revenues, capped at `highPrice`.

- **Revenue lock — the collar.** Combine both across two vaults: buy DOWN in
  a series struck below spot, mint-and-sell UP in a series struck above.
  Premium received on the call offsets premium paid on the put; revenue is
  locked inside the band.

- **Any preferred ratio.** Because positions are fungible tokens, sizes are
  free: buy extra put coverage to profit from a hashrate increase, sell only
  part of the upside, or trade out of a leg mid-life by selling it — no vault
  interaction, no counterparty negotiation.

## Collateral: why BTC, and where the cap sits

Collateral is BTC throughout — for a miner it is the native working asset,
and it avoids the opportunity cost of parking stablecoins.

- **BTC-quoted vault**: payoffs are defined in sats, so the band width *is*
  the escrow and every payoff is exactly collateralized by construction.

- **USD-quoted vault**: a USD payoff backed by BTC can never be fully
  collateralized — the sats value of the band is unknown until maturity. Each
  pair therefore escrows a fixed `pairCollateral` sats and the UP payout is
  capped there. This is the on-chain form of capping the short-call writer's
  maximum loss (choose `highPrice` ≈ 2–3× spot hashprice, and size
  `pairCollateral` at the band width converted at a conservative BTC/USD
  floor). The cap only binds in a joint tail — hashprice far above the band
  *and* BTC sharply lower — which is the market maker's residual risk and is
  priced as a small discount on the call premium.

## Lifecycle

1. **Deploy** the series: genesis-issue the UP/DOWN assets and the vault
   identity singleton; both legs are mint-controlled by the identity, so
   supply can only change inside genuine vault spends, and only in equal
   amounts.
2. **Issue / burn** (pre-maturity, permissionless): deposit collateral for
   pairs, or return a matched pair for the deposit. Single-sided holders exit
   by selling the leg, not by burning.
3. **Trade**: legs move as plain asset transfers, priced by intents.
4. **Settle** (once, permissionless): any party submits the oracle
   fixing(s) — signed `sha256(feed || price || time)`, timestamps within
   `±settleWindow` of `maturity` — and the pot splits into `upPot`/`downPot`.
   No BTC leaves the vault.
5. **Redeem** (post-settlement, permissionless): burn a leg for a pro-rata
   slice of its pot. Numerator and denominator drain together, so every
   holder gets the same rate regardless of redemption order. Payouts at or
   below 330 sats (taproot dust) are absorbed rather than emitted.

## Exit model and oracle liveness

A pooled vault cannot express per-holder unilateral exit as a single CSV
tapscript leaf, so these references carry no exit leaf; the `exit` parameter
sizes the pre-signed recurrent exit tree maintained off-chain and refreshed
on every issue/burn. If the oracle never attests inside the settlement
window, the vault cannot settle — option holders bear that liveness risk, and
venues should treat the settlement window as an SLA on the oracle.

## Relation to the other examples

- `options/covered_call.ark`, `options/cash_secured_put.ark` — single-buyer,
  physically-settled options with no oracle; the buyer's exercise decision is
  the settlement signal. Good for bilateral trades, not for a listed market.
- `stability/stability_vault.ark` — the Fuji-style oracle attestation and
  clamped cash-settlement math these vaults reuse.
- `bonds/repayment_pool.ark` — the pro-rata pooled redemption shape
  (`amount × pot / shares` with both sides draining together).
