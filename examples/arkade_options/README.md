# Cash-settled options

`option_vault.ark` pays a covered call (`kind` 0) or a limited put (`kind` 1) out of locked BTC. `examples/options/` is the physically settled pair and has no oracle.

Settlement price is three median prints, combined on the stack:

```
ST = (mOpen * 900 + mMid * 900 + mClose * 60) / 1860
```

Each print is the median of three distinct oracle signatures over `sha256("BTCUSD" || num2bin(price, 8) || num2bin(time, 8))`. Slice windows, in unix seconds from expiry: open `[T-1800, T-1740]`, mid `[T-960, T-900]`, close `[T, T+60]`. The weights are those bucket lengths.

A covered call pays the holder `Q * (ST - K) / ST` when `ST > K`, and 0 otherwise. A limited put pays `min(Q, Q * (K - ST) / ST)` when `ST < K`. Prices are USD cents. `Q` and payoffs are sats. A leg of 330 sats or less is folded into the other output.

`kind`, `strike`, `collateral`, and `expiry` are constructor parameters. Once coins are locked to the script those values are already agreed, so the spend paths do not check them again.

`option_intent.ark` is the RFQ lock, in the shape of `examples/non_interactive_swap/`. The user locks coins, `finalize` pays the other side before the deadline, and `cancel` refunds the user once `checkTime(deadline)` is true.

`settle`, `close`, and `unilateral` are on the vault. `close` needs the writer and the holder. `unilateral` is the writer's CSV.

The desk that quotes these contracts is [arkade-options](https://github.com/ArkLabsHQ/arkade-options).
