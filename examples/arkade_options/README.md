# Arkade Options desk

Cash-settled covered calls and limited puts. The writer locks BTC notional. At expiry the covenant reads three oracle slices, takes the median of each, and computes the settlement price with multiplies and a divide.

This is not `examples/options/`. Those contracts are physically settled and have no oracle. This folder is the cash-settled spec: the collateral is the notional, and the holder is paid in BTC out of that collateral.

## Run the desk

```bash
python3 -m http.server 8765 --directory examples/arkade_options
```

Open `http://127.0.0.1:8765/app/`.

Sell or buy, pick a covered call or a limited put, choose one of five strikes and an expiry, enter a BTC notional, and take the best of three simulated desk quotes. Locking starts a 30-second intent. If the desk funds, the position opens. If it does not, the lock refunds when the clock passes. An open position settles from three oracle slices. "Pyth spikes the midpoint" shows the median dropping the bad print.

The page keeps positions in `localStorage`. It does not broadcast to an operator. The numbers it shows are the same integer arithmetic as `option_vault.ark`. The script commitment is a SHA-256 of the terms, standing in for the vault's 32-byte witness program until an SDK session builds the real output script.

Quotes are Black-Scholes with zero rates. A covered call is priced as a call. A limited put is priced as a put spread struck at K and K/2. The spot comes from Coinbase, then Binance, and otherwise a labeled simulated price.

## Contracts

`contracts/option_intent.ark` is the RFQ lock, in the shape of `examples/non_interactive_swap/`: the user locks coins, `finalize` pays the other side before the deadline, and `cancel` refunds the user once `checkTime(deadline)` is true. Sats above the required amount are paid back. `unilateral` is the writer's CSV if the operator is gone.

`contracts/option_vault.ark` holds the notional.

- `settle` takes three slices. Five oracle keys are fixed in the constructor. Each slice needs three distinct keys. An oracle signs `sha256("BTCUSD" || num2bin(price, 8) || num2bin(time, 8))`.
- Slice windows, in unix seconds from expiry: open `[T-1800, T-1740]`, mid `[T-960, T-900]`, close `[T, T+60]`. Prints in a slice sit within 60 seconds of each other. The bucket time is the max timestamp.
- `ST = (mOpen * 900 + mMid * 900 + mClose * 60) / 1860`. The weights are the bucket lengths, so picking the edge of a slice cannot change a print's weight.
- Covered call: `ST <= K` pays the holder 0, otherwise `Q * (ST - K) / ST`.
- Limited put: `ST >= K` pays 0, otherwise `min(Q, Q * (K - ST) / ST)`. Below `K/2` that expression is at least `Q`, and the contract caps it.
- Prices are USD cents. `Q` and payoffs are sats. Division truncates. A leg of 330 sats or less is folded into the other output.
- `close` needs the writer and the holder. `unilateral` is the writer after CSV.

`Q` must be above 330 sats and at most 10 BTC. Prices must be at most $10,000,000.00. The desk uses 0.0001 BTC as its own minimum.

## Artifacts

`artifacts/*.json` are compiler output the page loads. Regenerate them from the repo root:

```bash
cargo run -- examples/arkade_options/contracts/option_vault.ark -o examples/arkade_options/artifacts/option_vault.json
cargo run -- examples/arkade_options/contracts/option_intent.ark -o examples/arkade_options/artifacts/option_intent.json
```

## Checks

```bash
cargo test --test examples arkade_options
node --test examples/arkade_options/app/settle-math.test.mjs
```
