# Streaming Dividends — a dividend every second

A Bitcoin-native dividend rail for corporate issuers: the dividend accrues
continuously at one-second granularity, is fixed in USD cents per unit per
year, and pays out in sats at an oracle-attested BTC/USD price whenever the
holder chooses to settle. Two contracts implement the program:

| File | Contract | Role |
|---|---|---|
| `dividend_treasury.ark` | `DividendTreasury` | singleton BTC reserve; services claims, accepts top-ups, issuer recall |
| `streaming_share.ark` | `StreamingShare` | per-holder position carrying `(units, lastClaim)`; claim / transfer / split |

## The pilot: a listed Bitcoin treasury company (hypothetical)

Picture a listed Bitcoin treasury company preparing perpetual preferred
shares funded by its income-generation desk (covered calls, put premium —
see `options/` and `hashprice/`). Two frictions recur in that plan wherever
it is attempted:

- **The plumbing can't keep up with the ambition.** Paying dividends
  *monthly* is already exotic in most listed markets, where payouts are
  annual or semiannual; the issuer ends up building bespoke systems for
  shareholder verification, record-date management and recurring
  distribution runs.
- **The listing gate is cash-flow credibility.** Exchange review asks for
  evidence that recurring dividends are backed by sustainable recurring cash
  flows — hard to show with a short operating track record and batch
  quarterly disclosure.

Both frictions are artifacts of *batch* settlement. This program removes the
batch. On Arkade the dividend is not an event but a rate: every unit accrues
`annualDividendCents / 31,536,000` per second, continuously, and any holder
settles whenever they like. A monthly dividend makes 12 payments a year; this
makes the concept of "a payment" disappear — 31.5 million accrual ticks a
year, of which claims are just checkpoints.

The pilot shape that follows from this:

1. **Phase 0 — internal demo.** One treasury, a handful of positions on
   testnet. The income desk tops up the reserve on its real revenue cadence;
   a dashboard shows per-second accrual against reserve coverage.
2. **Phase 1 — closed pilot.** A small tranche of *dividend entitlement
   units* (not the listed security itself) is allotted to qualified
   investors; each allotment is deployed as a `StreamingShare`. The listed
   preferred, when it lists, stays on the traditional register — the pilot
   instrument is the payment rail, mirroring registry holdings.
3. **Phase 2 — the rail becomes the register.** Continuous on-chain top-ups
   from the income desk are themselves the auditable evidence of recurring
   cash flow that batch reporting struggles to demonstrate: reserve coverage
   is a public time series, not a quarterly disclosure.

Nothing here is legal advice; a real pilot needs securities counsel in the
issuer's jurisdiction. The contracts are jurisdiction-agnostic.

## Why streaming kills the record date

A record date exists because batch rails must snapshot ownership to know whom
to pay. Continuous accrual makes the snapshot meaningless:

- `transfer` is a key swap that carries `(units, lastClaim)` unchanged —
  accrued-but-unclaimed dividends travel with the position and are priced
  into the sale. Sell at 14:03:07 and you have earned exactly through
  14:03:07. There is no ex-dividend cliff, so no dividend-capture trade.
- `split` gives both children the parent's `lastClaim`; accrual is linear in
  units, so splits are exactly accrual-fair with no division.
- `claim` settles accrual and advances `lastClaim` to now, atomically with
  the payout. Claims are independent per holder — no distribution run.

## Mechanics

**Accrual.** Time is `tx.offchainTime` (TEE-attested wallclock, unix
seconds), giving one-second granularity:

```
elapsed      = now − lastClaim
accruedCents = units × annualDividendCents × elapsed / 31536000
payoutSats   = accruedCents × 1e8 / oraclePrice     // price in cents/BTC
```

The product `units × annualDividendCents × elapsed` must stay inside int64:
1e6 units at $6.00/yr unclaimed for ten years is 1.9e17 — comfortably safe.
Truncation loses under one cent per claim, and `accruedCents > 0` guards a
zero-payout claim from advancing `lastClaim`.

**Claim transaction.** A claim co-spends treasury and position; each covenant
independently recomputes the accrual and protects its own side:

```
input[srvIdx]:  DividendTreasury  (service — permissionless)
input[posIdx]:  StreamingShare    (claim — holder-signed)
output[0]: treasury re-created, reserveSats − payoutSats
output[1]: position re-created, lastClaim = now
output[2]: payoutSats → holder
```

The treasury verifies the co-spent input is a genuine `StreamingShare` with
the witness-declared `(holder, units, lastClaim)` (scriptPubKey equality
binds the declaration), and only releases reserve against a position whose
accrual basis simultaneously advances — the same second of dividend time can
never be paid twice. The position verifies the holder authorized, the
treasury is genuinely present, and the holder is paid. `service` itself is
permissionless, so wallets or watchtowers can co-sponsor claims.

**Funding.** `topUp` is permissionless and monotone — the reserve only
grows. The income desk streams revenue in on whatever cadence it earns it,
which is exactly the "recurring cash flow" evidence exchanges ask for, as a
public time series.

**Oracle.** Fuji-style signed feed, as in `stability/` and `hashprice/`:
`msg = sha256(ticker || price || time)` verified with `checkSigFromStack`,
freshness bounded to 600 seconds of `tx.offchainTime`. A claim needs a live
oracle; accrual itself never does — if the oracle stalls, dividends keep
accruing and claims resume with the feed.

**Dust.** Claims below 331 sats are rejected (`payoutSats > 330`), matching
the Taproot dust convention used across the examples. At $6.00/yr per unit
and $100k BTC, one unit crosses dust in about two days; a holder of N units
can claim N times as often. Accrual is per-second; claiming is whenever it's
worth a UTXO.

## Trust model — what the pilot does and doesn't enforce

- **Reserve coverage is visible, not mandatory.** `recall` lets the issuer
  withdraw reserve at will; claims fail when the reserve is exhausted. Every
  recall and every top-up is on-chain the moment it happens, so coverage is
  watchable in real time — but solvency is a legal obligation of the issuer,
  not a covenant. Hardening path (deliberately out of pilot scope): a
  timelocked recall notice, and the arrears clock + penalty-rate mechanics
  prototyped in the `VariableDividendPreferred` example (PR #40).
- **`totalUnits` is fixed at deployment.** The treasury sanity-checks
  positions against it, but issuance integrity (that allotted positions sum
  to `totalUnits`) is an off-chain deployment fact. An issuance-controlled
  asset gating position creation — the `hashprice/` identity-singleton
  pattern — is the natural upgrade.
- **Clock and oracle.** `tx.offchainTime` is TEE wallclock: not
  consensus-enforced, and guarded against regression but not against pause.
  Oracle liveness gates claims, never accrual.
- **Exit.** Both contracts carry CSV unilateral-exit leaves. The position
  UTXO's sat value is dust; what exits is the *instrument*, whose entitlement
  is then enforced against the issuer per program terms — same model as any
  registered security, with a better audit trail.

## Relation to the other examples

- `stability/` — the oracle witness, `tx.offchainTime` accrual and
  per-second rate idioms; this program is those idioms turned into a
  corporate-action rail.
- `bonds/` — the two-contract co-spend pattern (`repayment_pool` ⊗
  `bond_mint`) that `service` ⊗ `claim` follows.
- `hashprice/`, `options/` — the income side: covered calls and hashprice
  vaults are ways a treasury desk *earns* the BTC that `topUp` streams into
  this reserve.
- `VariableDividendPreferred` (PR #40) — the single-UTXO, per-holder
  preferred with arrears teeth; this program is its pooled, streaming,
  transfer-friendly successor.
