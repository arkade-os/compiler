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
1 PH·day at 20 J/TH), fixed off-chain. At maturity the oracle signs two
fixings, both denominated in sats per unit: `hashPrice` (what the unit
earned) and `powerCost` (what its electricity cost). The settled value is the
**mining margin**:

```
margin = clamp(hashPrice − powerCost, 0, cap)
```

Depositing `cap` sats mints a pair of fungible Arkade Assets:

| Leg | Pays at maturity | Financially is |
|---|---|---|
| RIG | `margin` | a machine on a PPA, without the machine |
| GRID | `cap − margin` | the same watts sold elsewhere instead |

The clamp at zero is the curtailment right — a rig is never forced to mine at
a loss. The two legs always sum to `cap`, so the vault is exactly
collateralized at every fixing: no margin calls, no liquidations, no pro-rata
pots, no division. Legs trade like any asset via Arkade intents; the premium
never touches the contract.

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

- `issue(amount)` — permissionless: escrow `amount × cap`, mint paired
  RIG + GRID.
- `burnPair(amount)` — permissionless unwind: burn a matched pair, take the
  escrow back.
- `redeemRig` / `redeemGrid(amount, fixings…)` — burn a leg against the two
  oracle fixings for its exact side of the escrow, in any order.

The vault is stateless: supply lives in the asset groups, collateral in the
vault balance, and settlement is re-verified per redemption. Both fixings are
signed over exactly `maturity`, so the signature itself is the maturity gate —
no timelocks anywhere.

## Trust assumptions

- The oracle signs at most one price per `(ticker, maturity)`; two signatures
  over the same stamp are provable equivocation.
- If the oracle never publishes, legs cannot redeem (matched pairs can still
  `burnPair` out) — holders bear oracle liveness.
- Per-holder exit uses the off-chain recurrent exit tree parameterized by
  `exit`, as in the other pooled examples.
