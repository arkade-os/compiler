# Mining Margin Vault

A liquid market for the economics of running a machine, so nobody has to run
the machine to hold them.

Bitcoin is over-provisioned: fleets of old-generation ASICs stay racked as a
bet on hashprice, and PPA / interconnect capacity is hoarded for its option
value while AI demand bids for the same electrons. All of that exposure is
held physically — by burning energy — because there is no financial
instrument to hold it instead. This contract is that instrument.

## The primitive

One series per `(oracle, hashTicker, powerTicker, cap, maturity)`. A contract
unit is a fixed quantity of hashrate-time at a reference efficiency (e.g.
1 PH·day at 20 J/TH), fixed off-chain. At maturity the oracle attests two
fixings, both denominated in sats per unit: `hashPrice` (what the unit
earned) and `powerCost` (what its electricity cost). The settled value is the
**mining margin**:

```
margin = clamp(hashPrice − powerCost, 0, cap)
```

Depositing `cap` sats mints a pair of fungible Arkade Assets:

| Leg | Pays at settlement | Financially is |
|---|---|---|
| RIG | `margin` | a machine on a PPA, without the machine |
| GRID | `cap − margin` | the same watts sold elsewhere instead |

The clamp at zero is the curtailment right — a rig is never forced to mine at
a loss. The two legs always sum to `cap`, so the vault is exactly
collateralized at every fixing: no margin calls, no liquidations. Legs trade
like any asset via Arkade intents; the premium never touches the contract.

## Positions

- **Sell fleet exposure** — a miner shorts RIG (mint pairs, keep GRID, sell
  RIG) sized to the fleet. The hedge replaces the machines: exposure stays,
  metal can be unplugged.
- **Fleet wind-down** — list a series at an old generation's efficiency. When
  its RIG trades near zero, the market has priced the zombie fleet's option
  value; the operator sells it and decommissions instead of idling rigs hot.
- **PPA carve-out** — an energy holder leasing capacity to an AI datacenter
  buys RIG to stay long mining economics while the electrons go to compute;
  GRID is the financial form of "send the power elsewhere".
- **Synthetic ASIC** — buy RIG across maturities: a strip of mining margin is
  a machine's revenue stream with no silicon, power draw, or e-waste.

## Lifecycle

Stateful two-token vault, following the hashprice option vault design: shares
and pots are constructor state, updated by dynamic recreation on every spend.

- `issue(amount)` — permissionless, pre-maturity: escrow `amount × cap`,
  mint paired RIG + GRID gated by the vault identity singleton.
- `burnPair(amount)` — permissionless, pre-maturity unwind: burn a matched
  pair, take the escrow back 1:1.
- `settle(fixings…)` — permissionless, once: two attestations timestamped
  within `±settleWindow` of maturity fix the margin and split the pot
  (`rigPot = shares × margin`, `gridPot` the exact remainder — no division).
- `redeemRig` / `redeemGrid(amount)` — after settlement: burn a leg for a
  pro-rata slice of its pot; pot and supply drain together, so the rate is
  invariant under redemption order.

> **Status**: state transitions need dynamic taproot reconstruction, which
> the compiler currently disables; the transition functions ship commented
> out (only a `disabled` placeholder compiles), matching the other stateful
> examples. Uncomment them when dynamic contract transitions are restored.

## Trust assumptions

- The oracle attests one price per ticker inside the settlement window;
  signing two different prices there is equivocation the market can observe.
- If the oracle never attests inside the window, the vault cannot settle —
  holders bear that liveness risk.
- Per-holder exit uses the off-chain recurrent exit tree parameterized by
  `exit`, as in the other pooled examples.
