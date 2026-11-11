# Constant-product pool

One shared pool. External LPs deposit and exit. Traders fund a standing order and go offline. The operator settles each order as its own virtual transaction.

Base reserve is the pool output's value minus the 330-sat carrier. Quote, the LP-supply ledger, and one control unit are assets. The fee stays in the reserves, so the product rises by the LP fee. There is no fee-vault input on the hot path.

```
dy     = reserveOut * dxFee / (reserveIn + dxFee)
dxFee  = sold * (10000 - feeBps) / 10000
share  = supply * dx / base          when dy = dx * quote / base
```

Division rounds down. A sell that would pay 0, or the whole reserve, fails. A deposit whose quote does not match the floor price fails. An exit pays `reserve * burned / supply` of each side, and both amounts must be greater than 0.

With 1,000,000 sats and 2,000,000 quote, a 30 bps fee, and a sale of 10,000 sats: `dxFee` is 9,970 and the pool pays 19,743 quote. The pool then holds 1,010,000 sats and 1,980,257 quote. Selling 20,000 quote against that pool pays 10,068 sats. A deposit of 5,000 sats into a 1,000,000-share pool at the original reserves must bring 10,000 quote and mints 5,000 shares. Burning 250,000 of those shares returns 250,000 sats and 500,000 quote.

## Layout

Every settlement has the pool at input 0 and one standing order at input 1. Outputs are the next pool, the order's payout, the anchor, and the extension (`numOutputs == 4`).

| Order | Input 1 | Output 1 |
|---|---|---|
| `ConstantProductSwap.fill` | BTC above 330, no assets, or 330 sats plus quote | at least `minOut` of the other side, paid to `payScript` |
| `ConstantProductDeposit.fill` | BTC above 330 plus the matching quote | 330 sats and the minted LP tokens, paid to `payScript` |
| `ConstantProductExit.fill` | 330 sats and LP tokens | pro-rata BTC and quote, paid to `payScript` |

`refund` on an unfilled order is one input and pays `payScript` (`numOutputs == 3`). Each order has a CSV leaf for `ownerPk`, so the trader or LP can take that order back on L1. The pool itself is spent only through `swap`, `deposit`, and `withdraw`.

The pool prices the step and keeps its own output. The order checks the same numbers and pins `payScript`. A swap spends no LP tokens. A deposit mints LP and ledger by the same amount, and both groups must be controlled by the pool's control unit. A withdrawal burns the LP tokens and the same amount of ledger.

An empty pool (330 sats and the control unit) accepts the first deposit at the depositor's ratio, one share per sat of BTC. Burning the whole supply returns every sat and every quote unit and leaves that empty pool, which a later deposit can re-open. Partial exits leave both reserves and the ledger in place.

The covenant runs on spend. The funding transaction creates the first pool output; it is not checked by these scripts. Later deposits, swaps, and exits are.

This example puts one order in the transaction so the script is a single step. Several orders can share one transaction and one set of reserves. The pool walks those seats in order. Each standing order checks its own payout and `minOut`, and does not replay the other seats. Loops unroll, so the seat count is fixed in the source. The pool script grows by a few hundred bytes per seat and reaches the 10 KB script limit at about 30 swaps. The order scripts stay the same size.

That batch is still one spend of the one pool output, so those swaps happen in order and share one emulator execution. Separate pool outputs settle at the same time. Splitting one trading pair across those outputs also splits its reserves. An order whose `minOut` is already past the price has to be left out of the batch, because one failing input fails the whole transaction.
