# Mining Margin Vault

A market price for the economics of running a machine.

Bitcoin's capacity decisions are made through lumpy physical channels:
old-generation fleets stay racked as an unpriced bet on the margin, and PPA /
interconnect capacity is hoarded for option value while AI demand bids for
the same electrons. Hashprice alone trades (NDF markets exist); the **mining
margin** — hashprice minus power, the actual P&L line of a machine — has no
non-custodial, fully-collateralized, fungible instrument. This contract is
that instrument.

> **Status**: dynamic contract transitions are disabled in the compiler, so
> the five state-transition functions ship commented out and only a
> `disabled()` placeholder compiles — the artifact has no satisfiable spend
> path and must not be deployed. A CI guard test keeps the commented design
> compiling-modulo-the-gate and fires when transitions are restored.

## What this can and cannot do

Honest mechanism first. A cash-settled derivative cannot reduce Bitcoin's
aggregate energy burn: the difficulty adjustment re-pins mining spend to
protocol revenue whoever holds the paper, and hedging historically *lowers*
producers' cost of capital. What a margin price actually does:

- **Prices the keep-vs-scrap decision.** A racked old-gen fleet is a call
  option on the margin whose value is mostly time value — a number spot
  hashprice and a power bill cannot supply. Traded RIG at that fleet's
  efficiency *is* that number; when it stays below carrying cost across the
  strip, decommissioning is rational (the harvest is avoided carry plus
  salvage, not the sale proceeds).
- **Turns idle-hot fleets into price-responsive dispatch.** A miner who has
  locked the margin has no reason to mine through negative spreads: hedged
  metal runs in the spike hours and curtails otherwise.
- **Accelerates efficiency turnover.** Retiring high-J/TH hardware lets the
  same revenue-pinned security spend buy more hashes from fewer joules.
- **Keeps AI-pivoting power owners financially long mining.** A carve-out
  buyer holds margin exposure while the electrons go to compute — financial
  exposure, not hashrate; the network's security is physical.

## The primitive

One series per `(oracle, hashTicker, powerTicker, cap, maturity)`. A contract
unit is a fixed quantity of hashrate-time at a reference efficiency (e.g.
1 PH·day at 20 J/TH). Both fixings are **averaged (Asian) indices** over a
window stated in the oracle spec and ending at maturity — the settlement form
physical power markets use, because a point print on power is unrepresentative
and gameable. The ticker preimage must encode unit, reference efficiency,
averaging window, and hub, so a series is self-describing. The settled value:

```
margin = clamp(hashPrice − powerCost, 0, cap)
```

Both fixings are signed over exactly `maturity`: one message slot per
`(ticker, maturity)`, so a fixing cannot be replayed across series, there is
no timestamp window for a settler to shop in, and two prices for one slot are
provable oracle equivocation. Negative power fixings are admitted — routine
at volatile hubs.

Depositing `cap` sats mints a pair of fungible Arkade Assets:

| Leg | Pays at settlement | Financially is |
|---|---|---|
| RIG | `margin` | long a call spread on the margin |
| GRID | `cap − margin` | a cap-sat escrow claim, short the same spread |

RIG + GRID always equals cap, so the vault is exactly collateralized at every
fixing — no margin calls, no liquidations. Note what the legs are *not*: GRID
alone is not "the watts sold elsewhere" (that reading holds only as an
overlay — e.g. a running miner holding GRID has locked power-sale economics);
and RIG alone is not a machine — a machine is a strip of *hourly* curtailment
options, worth more than a single averaged fixing near breakeven (Jensen), so
machine replication takes a strip of maturities and keeps a known, one-sided,
priceable basis.

## Positions

- **Lock the margin (producer hedge).** Mint pairs, sell RIG, keep GRID,
  keep operating: the book is premium + locked margin in every state, and the
  rational dispatch is run-in-spikes, curtail otherwise. This — not
  unplugging — is the flagship trade; a seller who unplugs holds a naked
  short via GRID.
- **Wind-down signal.** Compare traded RIG at the fleet's efficiency against
  carrying cost across the strip. One near-zero series is not the test — a
  near-breakeven fleet's hourly curtailment value exceeds any single averaged
  fixing; the strip is the test.
- **PPA carve-out.** An energy holder leasing capacity to an AI datacenter
  buys RIG to stay long mining economics while the electrons go to compute.
- **Synthetic ASIC.** A strip of RIG across maturities converges to a
  machine's revenue stream up to intraday curtailment basis — and is short
  the tail above `cap`.

The natural short base is **merchant-power miners** (floating power cost).
Miners on fixed-price PPAs already own the power leg contractually; for them
a plain hashprice hedge composes more cleanly than a two-fixing margin
product.

## Lifecycle

- `issue(amount)` — permissionless, pre-maturity: escrow `amount × cap`,
  mint paired RIG + GRID gated by the vault identity singleton.
- `burnPair(amount)` — permissionless **any time before settlement**: a
  matched pair is worth exactly cap under every fixing, so the unwind stays
  open after maturity and is the recovery path if the oracle never publishes.
- `settle(fixings…)` — permissionless, once, at or after maturity (wall-clock
  gated): the two maturity-stamped fixings set the margin and split the pot
  exactly, no division.
- `redeemRig` / `redeemGrid(amount)` — after settlement: burn a leg for a
  pro-rata slice of its pot. Floor division shifts sub-share remainders to
  later redeemers (bounded; the final full-supply redemption sweeps exactly).

## Design trade-offs

- **Hard cap.** `cap` is both payoff cap and per-pair escrow: trust-minimal
  full collateralization, at the cost of truncating the tail above cap and
  locking dead capital if cap is set wide. The hashprice USD vault (#57)
  shows the decoupled alternative (`pairCollateral`) that trades tail credit
  risk for capital efficiency.
- **Sats numeraire.** Sats cancel BTC/USD out of the revenue leg, isolating
  difficulty-and-fee risk; the power leg then embeds BTC/USD (a fiat-sticky
  bill priced in sats). USD-account hedgers compose with BTC/USD instruments,
  or a USD-quoted variant can follow #57's.

## Trust assumptions

- The oracle signs at most one price per `(ticker, maturity)` slot; two
  signatures over one slot are provable equivocation.
- If the oracle never publishes, matched pairs recover escrow via
  `burnPair`; single-sided legs bear that liveness risk.
- The identity singleton's genesis mints exactly one token — mint control
  and the single-vault-UTXO model rest on it; every spend pins the vault at
  input 0.
- Per-holder exit uses the off-chain recurrent exit tree parameterized by
  `exit`, as in the other pooled examples.
