# Arkade · BTC Covered Calls

A dead-simple, Rysk-style way to **earn yield on your Bitcoin** by selling covered
calls — BTC in, BTC out, no stablecoins and no oracle. It runs entirely in the
browser with an **embedded wallet** and a **local Arkade emulator**, so you can go
from quote to settlement without a node, a server, or real funds.

> Standalone web app under `examples/options/web`. No real money. For education
> and protocol demonstration.

`pnpm` · `vite` · `react` · `@noble` · `@scure`

---

## The flow

1. **Deposit BTC.** The call is a fixed 30-day tenor.
2. **Request quotes.** Five market makers price the same option off their own
   implied vol — an RFQ — and you’re shown **5 strikes**, each with the best
   premium and APY.
3. **Pick a strike.** You see every maker’s quote (best one tagged) and a
   plain-language outcome:
   - **If BTC < strike at expiry** → you keep all your BTC **+ the premium**.
   - **If BTC ≥ strike** → your BTC is sold at the strike (capped upside) **+ the
     premium**, paid out in BTC.
4. **Sell the call.** Your BTC locks in an Arkade vault; the premium hits your
   wallet immediately.
5. **Settle at expiry.** Drag the spot to simulate the market, mine to the expiry
   block, and settle — the position resolves in BTC based on where spot landed.

## One settlement model

Arkade settles an on-chain **UTXO** and a **virtual UTXO** the same way, so there
is no chain to bridge or choose and no path to pick — the app never exposes one.
Settlement is a cooperative Arkade close co-signed by you, the maker, and the
Operator. Value is conserved end-to-end: on a called-away outcome the vault’s BTC
is split between your capped proceeds (`deposit × strike / spot`) and the maker’s
share — the smoke test asserts this.

## Run it

```bash
cd examples/options/web
pnpm install
pnpm dev        # http://localhost:5180
```

```bash
pnpm build      # typecheck + production bundle to dist/
pnpm smoke      # headless test: RFQ → open → settle (kept) → settle (called)
```

### Deploy

On every push to `master` that touches `examples/options/web/**`, the
[`Deploy Covered-Call App`](../../../.github/workflows/deploy-options-app.yml)
workflow builds the app and publishes it to the `gh-pages` branch under
`/options`:

**https://arkade-os.github.io/compiler/options/**

Each PR that touches the app also gets a Vercel-style preview at
`/options-previews/pr-<N>/` via
[`pr-preview-options.yml`](../../../.github/workflows/pr-preview-options.yml).
Both live alongside the playground (site root) and its PR previews as independent
`gh-pages` subtrees. Vite `base` is `./` (relative assets), so the bundle works
under any subpath.

## Architecture

```text
src/
  abi/                 compiler-sourced ABI (covered_call.json)
  lib/
    crypto.ts          @noble schnorr + @scure/base — keys, sighash, hashing
    wallet.ts          embedded wallet + simulated maker / Operator
    contract.ts        ABI + args → deterministic Arkade vault identity
    emulator.ts        UTXO/vUTXO ledger + block clock
    pricing.ts         Black-Scholes premium math
    rfq.ts             market-maker quote simulation (the RFQ)
    options.ts         BTC-only covered call: strikes, write, settle
  state/store.ts       zustand store wiring it together
  ui/ + components/    Arkade-branded design system + screens
```

### Contract source

The contract logic is **not** reimplemented — it’s consumed from the compiler.
`src/abi/covered_call.json` is the compiler’s ABI for
[`examples/options/covered_call.ark`](../covered_call.ark); `contract.ts` binds
constructor arguments into a deterministic Arkade vault address, so every
position points at a real compiled vault. `options.ts` is the seam where the
Arkade SDK’s tx builder would assemble the actual settlement spend.

### Notes & limitations

- Self-custodial **BIP340 Schnorr** wallet generated and persisted in the browser
  (`localStorage`); the private key never leaves the tab. Every lock and
  settlement is co-signed with real schnorr signatures, verified by the emulator.
- This is an emulator: balances, blocks, and the spot feed are local. The spot
  slider is the settlement signal — the contract has no oracle.
- Premiums use a compact Black-Scholes; makers differ by implied vol and edge to
  produce a realistic RFQ spread.
