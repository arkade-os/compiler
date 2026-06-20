# Arkade · Covered Call

A Bitcoin-native **covered-call options dApp** in the spirit of Rysk Finance,
built on the Arkade `CoveredCall` contract. It runs entirely in the browser with
an **embedded wallet** and an **emulator that settles on two chains** — Bitcoin
L1 (onchain) and Arkade VTXOs (virtual) — so you can drive a covered call through
its whole lifecycle without a node, a server, or real funds.

> Standalone web app living under `examples/options/web`. No real money. For
> education and protocol demonstration.

![stack](https://img.shields.io/badge/vite-react-ts-informational) ·
`pnpm` · `@noble` · `@scure`

---

## What it does

- **Write or buy** a single-locked, physically-settled European covered call.
  The writer locks BTC; the holder brings the strike payment in stablecoin
  (`aUSD`) only if they exercise in the money. Premium flows MM→seller upfront,
  off-contract.
- **Quotes premiums** with a built-in Black-Scholes model (RFQ-style) and charts
  the **payoff** for the chosen side.
- **Embedded self-custodial wallet** — a BIP340 Schnorr key generated and
  persisted in the browser (`localStorage`); the private key never leaves the
  tab.
- **Dual-chain emulator** sharing one Bitcoin block clock (the basis for every
  `tx.time` / CLTV / CSV timelock):
  - **Virtual (Ark)** — the Arkade Operator co-signs and the spend settles
    instantly. Maps to the contract's **cooperative** tapleaf.
  - **Onchain (L1)** — spends enter a mempool and confirm after a few blocks.
    Maps to the contract's **exit** tapleaf (N-of-N + CSV `exit` delay).
- **Full lifecycle**: `write → exercise | reclaim | transfer`, with a live
  block clock, ITM/OTM moneyness driven by a spot slider, and a per-position
  **script inspector** that renders the two compiled tapleaves with your
  parameters substituted in.

## Run it

```bash
cd examples/options/web
pnpm install
pnpm dev        # http://localhost:5180
```

```bash
pnpm build      # typecheck + production bundle to dist/
pnpm smoke      # headless lifecycle test (write/exercise/reclaim/transfer)
```

### Try the happy path
1. Open the app — your embedded wallet is funded on both chains.
2. Keep **Virtual (Ark)** selected, set a strike below spot, and **Write covered
   call**. You receive the premium; your BTC is locked in the vault.
3. **Mine** blocks (⛏) until you cross the expiry height.
4. Hit **Exercise** — the buyer (Arkade MM) pays the strike `aUSD` to you and
   takes the BTC, settled instantly on the virtual chain.
5. Or don't exercise: mine past the reclaim height and **Reclaim** the BTC.
6. Switch to **Onchain (L1)** to watch the same flows go through a mempool and
   confirm via the unilateral **exit** path after the CSV delay.

## Architecture

```
src/
  abi/                 compiler-sourced ABIs (covered_call.json, cash_secured_put.json)
  lib/
    crypto.ts          @noble schnorr + @scure/base — keys, sighash, hashing
    wallet.ts          embedded wallet + simulated MM / Operator
    contract.ts        ABI + args → deterministic vault identity; tapleaf rendering
    arkadeScript.ts    high-level Arkade-Script tx builder (the SDK seam)
    emulator.ts        dual-chain UTXO ledger, block clock, confirmations
    coveredCall.ts     lifecycle: write / exercise / reclaim / transfer
    pricing.ts         Black-Scholes premium + payoff math
  state/store.ts       zustand store wiring it together
  ui/ + components/    Arkade-branded design system + screens
```

### Contract source

The contract logic is **not** reimplemented here — it is consumed from the
Arkade compiler output. `src/abi/covered_call.json` is the compiler's ABI for
[`examples/options/covered_call.ark`](../covered_call.ark), including the two
tapleaf variants per function (`serverVariant true/false`). `contract.ts` binds
constructor arguments to a deterministic vault commitment and renders each
tapleaf's ASM with parameters and witness values substituted — the same
substitution an SDK performs when building a witness (including the documented
`reclaimHeight = expiryHeight + graceBlocks` binding).

### The SDK boundary

The brief asked for the Arkade TypeScript SDK's high-level Arkade-Script tx
builder. That builder currently lives on an **unpublished branch**
(`arkade-os/ts-sdk@arkade-script`) and isn't installable from npm, and the
emulator requirement implies an in-browser settlement layer regardless. So
`lib/arkadeScript.ts` is a faithful, **narrow re-implementation of that builder's
shape** — `spendVault → addInput → addOutput → sign → withOperator → build` —
and is the *only* seam the app depends on. Swapping in the real
`@arkade-os/sdk` builder is a single-module change: nothing in the UI, store, or
lifecycle reaches past this interface into emulator internals.

### Notes & limitations

- Signatures are real BIP340 Schnorr over a canonical (not consensus-exact)
  sighash; the emulator verifies every required signature actually covers the
  spend. Script execution is checked structurally, not by a full Bitcoin Script
  interpreter.
- Mining fees are out of band (as in the contract design docs).
- This is an emulator: balances, blocks, and the spot feed are all local. The
  spot slider is the buyer's ITM/OTM signal — the contract itself has no oracle.
