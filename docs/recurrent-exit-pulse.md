# PULSE — Recurrent Unilateral Exit for Emulator-Enforced Pools

**Pooled Unilateral-exit via Lattice State Epochs.**

A protocol for giving open-membership pool contracts on Arkade a *standing* unilateral
exit, enforced by recurrent state updates between the transacting parties. This document
is a design specification: it defines the protocol lifecycle, the trust model, the
attack analysis — fifteen adversarial findings (A1–A15), detailed in §10 — that shaped
it, and the compiler surface that would standardize it. It proposes no code changes; the
compiler-facing sections are future work.

Cross-references: [`options.md`](./options.md) (two-tapleaf model, exit/renew options),
[`bonds.md`](./bonds.md) (pool covenants and today's exit asymmetry),
[`arkade-primitives-spec.md`](./arkade-primitives-spec.md) (recursive covenants,
emulated introspection).

## Table of contents

- [1. Plain-language explainers](#1-plain-language-explainers)
  - [1.1 The 30-second version](#11-the-30-second-version)
  - [1.2 The plain-language walkthrough (no math, no cryptography)](#12-the-plain-language-walkthrough-no-math-no-cryptography)
- [2. Motivation: the gap in today's exit compilation](#2-motivation-the-gap-in-todays-exit-compilation)
- [3. Design principles](#3-design-principles)
- [4. Vocabulary](#4-vocabulary)
- [5. Interactivity requirements](#5-interactivity-requirements)
- [6. The exit leaf](#6-the-exit-leaf)
- [7. Protocol lifecycle](#7-protocol-lifecycle)
  - [7.0 Genesis (D0)](#70-genesis-d0)
  - [7.1 Pulse ceremony (D1) — atomic; order is load-bearing](#71-pulse-ceremony-d1--atomic-order-is-load-bearing)
  - [7.1a Public finality predicate (conservation + consistency)](#71a-public-finality-predicate-conservation--consistency)
  - [7.2 Heartbeat (D2) — there is no cheap operator-only re-anchor](#72-heartbeat-d2--there-is-no-cheap-operator-only-re-anchor)
  - [7.3 Unilateral exit walk (D3)](#73-unilateral-exit-walk-d3)
  - [7.4 Expiry (D4) and the timelock ordering invariant](#74-expiry-d4-and-the-timelock-ordering-invariant)
- [8. Invalidation model](#8-invalidation-model)
- [8a. Recourse: when the count doesn't check out](#8a-recourse-when-the-count-doesnt-check-out)
  - [Failure modes and where each lands](#failure-modes-and-where-each-lands)
  - [The recourse ladder (strongest → weakest)](#the-recourse-ladder-strongest--weakest)
  - [Why the detect-before-consumed race favors the thief, not the victim](#why-the-detect-before-consumed-race-favors-the-thief-not-the-victim)
- [9. Bond and enforcement layers](#9-bond-and-enforcement-layers)
  - [Primary model: a FROST-in-TEE operator (no capital bond)](#primary-model-a-frost-in-tee-operator-no-capital-bond)
  - [Optional economic backstop: the bonded federation](#optional-economic-backstop-the-bonded-federation)
  - [9.1 Hardening the referees (TEE-constrained, bonded, conflict-free)](#91-hardening-the-referees-tee-constrained-bonded-conflict-free)
- [10. Attack analysis appendix](#10-attack-analysis-appendix)
- [11. Compiler surface (future work — gated zones)](#11-compiler-surface-future-work--gated-zones)
- [12. The no-fork endgame, and the GSR annex](#12-the-no-fork-endgame-and-the-gsr-annex)
  - [12.1 Baseline: permanent operating characteristics](#121-baseline-permanent-operating-characteristics)
  - [12.2 The GSR annex (the only fork contemplated)](#122-the-gsr-annex-the-only-fork-contemplated)
- [13. Security model and dialectical review](#13-security-model-and-dialectical-review)
  - [13.1 Two security models, not one](#131-two-security-models-not-one)
  - [13.2 The trilemma](#132-the-trilemma)
  - [13.3 Dialectical summary](#133-dialectical-summary)
  - [13.4 Can anyone halt epoch creation?](#134-can-anyone-halt-epoch-creation)
  - [13.5 Is the Operator always the exit-creator? (and the federation fix)](#135-is-the-operator-always-the-exit-creator-and-the-federation-fix)
  - [13.6 Feasibility: the lattice is an Arkade VTXO tree](#136-feasibility-the-lattice-is-an-arkade-vtxo-tree)
- [Trust statement](#trust-statement)

---

## 1. Plain-language explainers

### 1.1 The 30-second version

The pool is a **group piggy bank held at a bank** (the Arkade Operator).

- Every time anyone deposits, withdraws, or trades, the people doing *that* transaction
  sit down with the bank and **rewrite the fire-escape plan**: a stack of pre-signed
  cheques that says exactly who gets what if the bank ever disappears. Anyone can take
  those cheques to the blockchain and cash them — no bank needed.
- The pens used to sign the cheques are **destroyed immediately after signing**
  (ephemeral keys), so nobody can ever write a *different* set of cheques for that
  version of the piggy bank.
- The bank also publishes a **notarized balance snapshot of everyone** — not just the
  people transacting — every single time, and posts a **security deposit**. Getting
  caught signing two contradictory documents is mathematical proof of cheating and
  forfeits the deposit.
- You never have to show up when other people transact. Your escape cheque is kept
  current by whoever *is* in the room, and a **watchdog service** can cash it for you
  if the bank goes dark.
- Periodically (the **heartbeat**), the whole arrangement is refreshed on the actual
  blockchain, like renewing a lease. That is the "recurrent" rhythm: many off-chain
  **pulses** between on-chain heartbeats.

### 1.2 The plain-language walkthrough (no math, no cryptography)

Picture a **shared money jar** that a group uses together — to trade, lend, or pool
funds. Normally, putting money in a shared jar means trusting whoever holds it. PULSE is
a set of rules that lets you put money in the jar **and still take your own share out at
any time, by yourself, even if the jar-keeper vanishes or turns dishonest.** Here is how,
without any math.

- **The jar-keeper is a clerk, not a bank.** Someone (the Operator) runs the jar, but
  never holds your money in a way they could walk off with. Their job is to keep the
  books and coordinate — like the clerk in a shared safe-deposit room. They can refuse to
  *do new business*, but they cannot *take what is already yours*.

- **Every change comes with fresh "exit tickets."** Each time anyone makes a move — a
  deposit, a withdrawal, a trade — the few people involved in *that* move re-issue a
  complete set of **exit tickets**: one per member, each saying "this person is owed
  exactly this much." The tickets are already signed and final. Anyone can walk a ticket
  to the public ledger and cash it out — no permission, no clerk needed. If the clerk
  disappears tomorrow, everyone just cashes their latest ticket and goes home.

- **Old tickets can't be quietly rewritten.** The moment a new set of tickets is signed,
  the tools used to sign that batch are destroyed — so a *second, different* set for the
  same moment can't normally be made behind your back. In the one case it still could (the
  clerk teaming up with *everyone* who was in the room), doing it leaves a
  self-incriminating paper trail that triggers the cash deposit below. Either way, one set
  counts, and you hold your copy.

- **A public headcount protects the people not in the room.** You don't have to show up
  every time others transact. So how do you know *your* ticket still says the right number
  when you weren't watching? Each time, the clerk publishes a **signed headcount** — a
  public, stamped list of what *every* member is owed, not just the people doing the deal.
  Anyone in the world can check that the new tickets match that list and that the totals
  add up. If they don't, honest software everywhere refuses the change and the group falls
  back to the last good set of tickets. A mistake can't quietly slip through; it gets
  caught and rewound.

- **If the clerk lies, they lose a cash deposit.** Before running the jar, the Operator
  puts up a **security deposit** held by an independent referee group. If the Operator is
  ever caught doing the one forbidden thing — signing two contradictory documents about
  the same money — that is black-and-white proof of cheating, and the deposit is paid to
  the victim. Cheating isn't just hard; it's expensive and self-incriminating.

- **A watchdog can stand guard for you.** Because the tickets work without you lifting a
  finger, you can run (or hire) a **watchdog** that watches the ledger and cashes your
  ticket automatically the moment anything looks wrong — the clerk going silent, a
  deadline approaching, or two conflicting documents showing up.

- **The one honest catch.** When you are *not* in the room, the amount on *your* ticket is
  filled in by the people who are — checked by the public headcount and backed by the
  deposit, but not personally signed by you. So your ability to *leave* is rock-solid and
  needs nobody's permission; the *number* on your ticket is normally right (everyone can
  check the math) and, if someone manages to cheat it, the deposit pays you back. It is
  *"you can always get out, and you're financially covered if the amount is wrong"* — not
  *"the amount is impossible to get wrong."* That distinction is the whole trade-off.

- **Why "recurrent."** Tickets don't last forever. Every so often the whole arrangement is
  renewed on the public ledger, like resigning a lease, which keeps everyone's tickets
  fresh and cheap to cash. The practical upshot: don't go *completely* dark forever —
  check in now and then (or let your watchdog do it), and your money stays yours.

---

## 2. Motivation: the gap in today's exit compilation

Every non-internal Arkade function compiles to two tapleaves:

1. **Cooperative leaf** — user signatures plus introspection opcodes (`tx.outputs`,
   asset groups, recursive covenants via `new Self(...)`), terminating in
   `<SERVER_KEY> <serverSig> OP_CHECKSIG`. Introspection is *emulated*: the Operator
   validates the transition off-chain and refuses to co-sign invalid ones. On L1, the
   only thing consensus enforces on this path is the signature set.
2. **Exit leaf** — pure Bitcoin Script: an **N-of-N CHECKSIG chain over every pubkey
   named in the constructor and function parameters**, plus
   `<exit> OP_CHECKSEQUENCEVERIFY`.

This works for closed contracts with a fixed cast. It **collapses for open-membership
pools** — recursive covenants that anyone can spend cooperatively (AMMs, lending pools,
the repayment pool in `bonds.md`):

- Membership is dynamic and unbounded, so the N-of-N exit leaf names either the wrong
  parties or nobody.
- Today, pool exits are only *transient by construction*: a cooperative redemption
  phase drains funds to per-holder single-sig VTXOs, each of which has a clean exit.
  That guarantee exists only while the Operator cooperates.
- **A passive pool member — someone whose balance hasn't changed in weeks — has no
  standing unilateral exit at all.**

PULSE closes this gap.

## 3. Design principles

1. **Transactor-borne interactivity.** Exit enforcement is refreshed by *the
   transacting parties + the Operator only*. Whoever moves funds pays the coordination
   cost; passive members never sign anything after they join.
2. **State-aware data availability.** Every pool state and its exit artifacts are
   published and committed on-chain, so anyone — watchtowers, new depositors, third
   parties — can verify the latest state and act on it (including broadcasting someone
   else's exit).
3. **Finality on state updates, not on new on-chain outputs.** A pool transition is
   final when its pulse ceremony completes, decoupled from block production.
4. **Bounded lifetime.** The pool's `renew` expiry forces a recurrent on-chain refresh
   (the heartbeat), which resets exit cost and re-protects the full membership.

## 4. Vocabulary

| Term | Meaning |
|---|---|
| **Pool VTXO `U_k`** | The pool's virtual UTXO at epoch `k`, holding the aggregate funds |
| **State table `S_k`** | The full balance table at epoch `k`: every member's `(memberPk, balance)` |
| **Pulse** | One off-chain cooperative state transition `S_k → S_{k+1}`, consuming `U_k`, producing `U_{k+1}` |
| **Transacting parties `M_k`** | The parties whose balances change in pulse `k` — whoever is depositing, withdrawing, or trading (online by definition; typically 1–2) |
| **Transition tx `T_k`** | The plain, fully-signed, broadcastable transaction implementing pulse `k` |
| **Epoch key `P_k`** | MuSig2 aggregate of *ephemeral, sign-once* keys of `{Operator} ∪ M_k`. Passive members are **never** in the aggregate |
| **Exit lattice `L_k`** | Fully pre-signed splitting tree spending `U_k`'s exit leaf into one slot per member, per `S_k` |
| **Slot** | A lattice leaf output: `SingleSig(memberPk)` with the member's own exit CSV |
| **Continuity attestation `A_k`** | Operator-signed Schnorr over the Merkle root of the *full* table `S_k` |
| **Pulse commitment `h_k`** | `H(h_{k-1} ‖ S_k ‖ txid(T_k) ‖ root(L_k) ‖ A_k)`, co-signed by Operator + threshold of `M_k`, committed in the Operator's next on-chain batch |
| **Heartbeat** | A pulse whose transition tx lands on-chain, re-anchoring the pool tip with a freshly built full lattice |
| **Δ (`exit`)** | The exit leaf's relative timelock — the contest window |
| **`renew`** | The pool's absolute expiry, after which the Operator's sweep path eventually matures |
| **Bond** | The Operator's on-chain security deposit, held by a `k`-of-`n` federation of referees independent of the Operator; pays victims on objective equivocation evidence or returns to the Operator at expiry (§9) |
| **`requiredCoverage`** | The minimum bond size — an at-risk-*per-epoch* floor (the passive value a single collusion could short before the next heartbeat), not total TVL (§9) |

## 5. Interactivity requirements

| Role | Signs | Online when | Notes |
|---|---|---|---|
| **Passive member** | **Nothing after deposit** | Own deposit/withdraw only | Must *retain* exit artifacts (or delegate to a watchtower); interactivity is borne by transactors |
| **Transacting parties** | Lattice + transition + `h_k`, in **one ceremony** (two MuSig2 rounds, one network round-trip) | Their own transaction | Typically 1–2 parties |
| **Operator** | Every pulse + attestation + commitment | Always-on | Absence ⇒ freeze ⇒ everyone exits via lattices |
| **Watchtower** | Nothing (lattice is fully pre-signed) | Monitoring only | Can broadcast *anyone's* exit; non-custodial; delegable |
| **Heartbeat participants** | Operator + that pulse's transacting parties only | — | Passive members are **not** needed at heartbeats |
| **Genesis** | Operator only, if the pool starts empty and members join via deposit pulses | — | **No all-hands N-of-N ceremony ever exists** |

## 6. The exit leaf

The compiler-visible, standardized artifact. For a `recurrent` pool, the exit variant
emits — instead of the N-of-N CHECKSIG chain:

```
<PULSE_KEY> OP_CHECKSIG <exit> OP_CHECKSEQUENCEVERIFY OP_DROP
```

- `<PULSE_KEY>` is the epoch key `P_k` for the pool VTXO of that epoch. Constant size,
  regardless of membership.
- The **only possible spend** of this leaf is the pre-signed lattice root: the
  ephemeral keys behind `P_k` are deleted after signing, making the lattice a
  *de-facto covenant*.
- The CSV `Δ` is the **contest window**: transition transactions carry no delay, so
  anyone holding a newer signed transition can extend the chain on-chain, consuming
  `U_k` and voiding a stale lattice. This *chain-extension dominance* replaces
  revocation/punishment for the stale-state case. (It does **not** defend against a
  fresh colluding theft — see §9 and finding A5.)

## 7. Protocol lifecycle

### 7.0 Genesis (D0)

1. The Operator posts the per-pool **bond** (§9), sized to at least
   `requiredCoverage(initialTVL)` (TVL = the pool's total value locked).
2. The pool contract is deployed: an open-membership recursive covenant whose
   cooperative path the Operator emulates, with `recurrent` exit mode.
3. Preferred genesis: **start empty**. The first members join via ordinary deposit
   pulses, so no all-hands ceremony exists. (If a pre-seeded genesis is used instead,
   every genesis member must be online once to co-sign `L_0`.)
4. The Operator publishes `h_0` co-signed per §7.1 step 6 and anchors `U_0` in a batch
   transaction.

### 7.1 Pulse ceremony (D1) — atomic; order is load-bearing

A pulse either completes fully or is abandoned, leaving the pool on `U_k`, whose
lattice is already valid.

1. **Propose.** A transition `T_{k+1}` is proposed, changing only the transacting
   parties' balances. The Operator emulates the contract's introspection covenant
   against it. `S_{k+1} = S_k` with only `M_{k+1}` slots changed.
2. **Attest.** The Operator signs the continuity attestation `A_{k+1}` over the Merkle
   root of the *entire* `S_{k+1}` — every member, not just the transacting parties.
   One Schnorr
   signature; O(1) on-chain footprint; O(log N) inclusion proofs per member.
3. **Lattice first.** The parties build and MuSig2-sign `L_{k+1}` under
   `P_{k+1} = MuSig2(Operator, M_{k+1})`:
   - Root spends `U_{k+1}`'s exit leaf; the tree splits into per-member slots
     (`SingleSig(memberPk)` + the member's own exit CSV).
   - **Dedicated per-claimant anchor outputs** (pay-to-anchor, P2A) on every node;
     TRUC ("v3") transaction topology; lattice txs opt out of replace-by-fee — fee
     bumping is anchors + child-pays-for-parent (CPFP) only.
   - Balances below the 330-sat taproot dust floor are aggregated into a single
     **cooperative-only dust slot**.
   - If any signer aborts here, the **pulse is abandoned**; no keys are deleted; the
     pool stays on `U_k`.
   - *Honest cost note:* SIGHASH_ALL means a txid cascade — any change at the root
     re-invalidates every descendant, so the **whole O(N)-tx lattice is re-signed each
     pulse**. This is O(N) compute/bandwidth for the 2–3 signing parties (batchable in
     one network round) but **O(1) interactivity**. The scaling valve is two-tier
     sharding: frequent pulses update a small "hot band" sub-pool; the periodic
     heartbeat folds it back into the full lattice.
4. **Verification gate.** Each transacting party verifies, *before releasing anything*:
   - (a) its own slot value in `L_{k+1}`;
   - (b) **every passive slot equals the `S_k` carry-forward**, Merkle-checked against
     `A_{k+1}`;
   - (c) the Operator bond still covers the pool's passive TVL (§9);
   - (d) **its own lattice branch is in its hands** — *"no lattice in my hands, no
     pulse."* Publication to the relay mesh alone is never trusted.
5. **Transition signing.** Only now do the Operator + transacting parties sign
   `T_{k+1}` (SIGHASH_ALL, nSequence final).
6. **Commit.** `h_{k+1}` is **co-signed by the Operator + a threshold `t` of `M_{k+1}`**
   so the Operator cannot unilaterally author forks (`t ≥ 1`; a fork then requires `t`
   contradicting signatures, so higher `t` is more fork-resistant at the cost of more
   required online co-signers — `t = 1` minimal, `t = |M_{k+1}|` maximal). It is
   committed in the Operator's next on-chain batch transaction. Full artifacts `(S_{k+1}, T_{k+1}, L_{k+1},
   A_{k+1})` go to the relay mesh, content-addressed by `h_{k+1}`. **The next pulse is
   invalid until `h_k` is on-chain** — a chained dependency that turns commitment
   withholding into a *visible liveness fault* that trips auto-exit (§7.4).
7. **Delete ephemerals** — only after all parties confirm artifact storage. This is
   hygiene, *not* a trust anchor: deletion is unprovable; the real guarantee is
   equivocation detection (§9).

**Who signs what:**

| Artifact | Signers |
|---|---|
| `T_{k+1}` (transition) | Operator + `M_{k+1}` |
| `L_{k+1}` (lattice) | `P_{k+1} = MuSig2(Operator, M_{k+1})`, **before** `T` is signed |
| `A_{k+1}` (full-table attestation) | Operator alone (its honesty is bonded) |
| `h_{k+1}` (commitment) | Operator + threshold of `M_{k+1}` |

### 7.1a Public finality predicate (conservation + consistency)

The verification gate (step 4) is a *veto*, but only the transacting parties run it.
There is a second check that **anyone** can run — passive members, watchtowers, new
depositors, third parties — from data the on-chain commitment `h_k` already binds, with
no signing role required. It is the safety net for everyone the gate does not cover, and
it is what catches an *honest-but-buggy* pulse (one with no lie to slash on).

A pulse `k` is **final only if** both hold, recomputed from the published `S_k`,
`root(L_k)`, and the on-chain `value(U_k)`:

1. **Conservation** — `Σ(leaf values of L_k) + dust slot + Σ(path fees) == value(U_k)`.
2. **Consistency** — `root(L_k)` reproduces exactly the per-member slot set implied by
   `S_k`, and the `S_k` root matches the one attested in `A_k`.

If either fails — or the pre-image data needed to check them is withheld (which is
itself the §7.1 step 6 / A3 stall) — **conforming wallets and watchtowers MUST treat
pulse `k` as non-final and auto-exit on epoch `k−1`**, the last epoch that passed both
checks (genesis `h_0` is checked at deposit). This converts a malformed or
over-allocating lattice from a *silent loss* into a *liveness halt*, and it does so
without any covenant: the data is public and the arithmetic is objective. The only
residual is a counterparty who already treated pulse `k` as final off-chain before
checking — so external settlement must gate finality on this same predicate.

### 7.2 Heartbeat (D2) — there is no cheap operator-only re-anchor

A forced design finding: re-anchoring `U_k` under a new on-chain output changes its
outpoint, and every pre-signed signature (the transitions *and* the lattice) commits to
the old outpoint under SIGHASH_ALL. Re-signing would require the deleted ephemeral
keys. Therefore, **absent any consensus change that lets signatures float across
outpoints (§12.2), the heartbeat must itself be a cooperative on-chain pulse**:

- A full pulse ceremony whose `T` lands on-chain, with a **complete lattice rebuild
  over all of `S_k`** under a fresh epoch key.
- It resets virtual-chain depth (unilateral exit cost is bounded by *pulses since the
  last heartbeat* plus one lattice branch) and re-protects every current member.
- The Operator cannot heartbeat unilaterally; it can only propose one. Cadence is
  quorum- and economics-gated: required frequency rises with pool TVL so that
  **at-risk-per-epoch stays ≤ the Operator bond** (§9).

### 7.3 Unilateral exit walk (D3)

1. A watchtower (or the member) triggers on any of: a **missed `h_k` commitment**,
   `height ≥ renew − Δ − margin`, or a **conflicting published artifact**.
2. Broadcast the chain tip if needed (any unconfirmed transitions since the last
   heartbeat), then the **lattice root**, spending `U_k`'s exit leaf after the Δ
   contest window.
3. Broadcast the member's **branch path** (log N transactions), CPFP-bumping via the
   dedicated anchors.
4. After the slot's own CSV matures, sweep `SingleSig(memberPk)` to a wallet.

### 7.4 Expiry (D4) and the timelock ordering invariant

The Operator's renew-sweep must mature strictly after exits can complete:

```
sweepDelay ≥ Δ + margin        (compiler rejects violations)
```

making the window `[renew − Δ − margin, renew + sweepDelay)` **lattice-exclusive**: the
sweep can never consume `U_k` out from under an in-flight exit. `margin` scales with
lattice depth (log N confirmation time) plus a fee-spike buffer. Wallets and
watchtowers auto-exit if the pool has not heartbeat by `renew − Δ − margin`.

## 8. Invalidation model

| Threat | Mechanism | Nature |
|---|---|---|
| **Stale lattice broadcast** (old epoch's exit) | Chain-extension dominance: transitions have no CSV, exits wait Δ; any holder of a newer `T` extends the chain and voids the stale lattice | Trustless race the honest side structurally wins |
| **Commitment withholding / forks** | Chained `h_k` dependency + co-signed commitments: a skipped commitment stalls the pool visibly and trips auto-exit; a forked `h_k` carries a contradictory signature | Detection + liveness fallback |
| **Fresh colluding theft** (Operator + all of `M_k`, resurrected keys) | **Not a race** — the theft tx has no CSV and beats the Δ-delayed lattice. Defense is the equivocation proof: the victim holds `L_k` (a `P_k` signature) and the theft tx is a *second* `P_k` signature on a conflicting spend → bond slash (§9) | Economic deterrent |

Because the equivocation proof requires the victim to *hold* the lattice, **local
retention of `(lattice branch, root(L_k), A_k, h_k inclusion proof)` per epoch is a
security-critical protocol invariant**, not a convenience. A member (or their
watchtower) that discards these has no fraud proof — though because the lattice is
non-custodial, *any* surviving copy (the relay mesh, an archival watchtower) lets
anyone reconstruct and broadcast on the victim's behalf, so the data only needs to
exist *somewhere*, not necessarily with the victim.

**The contest window Δ is also a dispute window.** No published evidence can freeze
`U_k` on-chain — there is no covenant to freeze it. But a standardized, machine-checkable
evidence bundle (`A_j` plus the contradicting `L_k` or forked `h_k`) does two things
during Δ: it makes the federation *earmark* the bond (blocking its expiry-return while a
live contradiction stands), and it flips every conforming client's accept-policy to
*refuse new pulses* on that pool. Since the next pulse is invalid until `h_k` is on-chain
and honest co-signers will not co-sign a disputed tip, a credible dispute **halts state
progression** — the closest no-covenant analogue to a freeze. It stops the attacker
finding fresh victims; it does not, by itself, claw back the specific contested coins.

## 8a. Recourse: when the count doesn't check out

This is the user-facing companion to §8. The governing fact, stated sharply because
every line depends on it:

> A user can only ever broadcast a lattice that was **actually signed**. No honest
> "correct" lattice exists unless it was ceremonially produced. So *recovering your
> position* is possible only by falling back to a previously-signed, still-spendable
> lattice. If none exists, the ceiling is **economic compensation from the bond**, and
> the floor is **unbacked loss**.

### Failure modes and where each lands

| Failure | What it is | Tag (determining condition) |
|---|---|---|
| **Wrong amount** | your slot pays less than your balance | Active signer: **POSITION-RECOVERABLE** (veto at the gate). Passive: **COMPENSATION-ONLY** via `A_k` contradiction, unless you win the race below |
| **Missing slot** | you are in `A_k` but absent from `L_k` (= wrong amount, slot 0) | Same as wrong amount; the fraud proof is the cleanest (Merkle inclusion in `A_k` vs absence in `root(L_k)`); doubles as a conservation alarm |
| **Conservation failure — malicious** | `Σ(slots) > value(U_k)`, a theft structured as a race among victims | **LIVENESS-HALT** (§7.1a predicate; the inflated `A_k` also contradicts on-chain `value(U_k)`) → compensation residue |
| **Conservation failure — buggy-honest** | ceremony bug; `A_k` matches the buggy lattice, so *no lie, no conflicting signature* | Without §7.1a: **UNBACKED-LOSS** (no slashable evidence). With §7.1a: **LIVENESS-HALT** at `k−1`. This is why §7.1a is a first-class rule |
| **Missing / invalid branch** | signatures don't verify, or you never received a branch | Invalid sig, active: **POSITION-RECOVERABLE** (veto). Passive: **COMPENSATION-ONLY** if `A_k`+inclusion retained or mesh-recoverable; **UNBACKED** only if the data is *globally* lost |
| **Stale-but-correct** | your `L_k` is correct but `U_k` was already consumed by a newer (bad) transition | **COMPENSATION-ONLY** in the realistic case; POSITION-RECOVERABLE only inside the race below, which you usually lose |
| **Commitment fork** | Operator double-allocates `U_k` across two off-chain histories | **COMPENSATION-ONLY** (co-signed conflicting `h_k`) + **LIVENESS-HALT** for any observer of both |
| **Sub-dust** | balance below the 330-sat floor, aggregated into the cooperative-only dust slot | **UNBACKED-LOSS**, bounded ≤ dust floor — a *permanent* no-unilateral-exit gap (see §12.1) |

### The recourse ladder (strongest → weakest)

1. **Prevention — the gate is a veto.** If you are transacting in the pulse, you refuse
   to sign; because the lattice is signed before the transition, `U_k` is never consumed
   and the pool stays on the still-valid `L_k`. Full recourse — but only for the parties
   **online and signing that pulse**. Everyone else is downstream, and the rest of this
   ladder exists solely to serve them.
2. **Public conservation/consistency halt (§7.1a).** Anyone can recompute conservation
   and consistency from committed public data; on failure, pulse `k` is non-final and
   conforming software exits on `k−1`. Converts buggy-honest and over-allocating lattices
   from silent loss into a liveness halt, with no fork.
3. **Detect-before-consumed exit via the last-good epoch.** Hold a correct `L_{k−1}`,
   detect the bad pulse, broadcast `L_{k−1}` before the bad transition confirms. **Honest
   verdict: this loses the race to an active thief and works only against a dark or
   stalled Operator** (see below). It is a freeze remedy, not a theft defense.
4. **Equivocation fraud proof → bond compensation.** Two conflicting `P_k` signatures, or
   `A_j` contradicted by a later lattice with no member-signed debit. The federation pays
   victims — **money, not position**, capped at the bond.
5. **Residual unbacked loss.** What actually falls here: buggy-honest conservation *absent
   rule §7.1a*; a branch whose data is *globally* lost; sub-dust balances (structurally no
   exit); and the over-the-bond portion of any theft (`loss > bond`).

### Why the detect-before-consumed race favors the thief, not the victim

Your exit spends `<P_k> OP_CHECKSIG <Δ> OP_CSV`: the relative timelock means the lattice
root cannot be mined until **Δ blocks after `U_k` confirmed**. The attacker's consuming
transition carries **no CSV** (`nSequence` final, by design — §6, §8 row 3): it is
spendable immediately and confirms in the next block. So a colluding Operator consumes
`U_k` roughly Δ blocks before your exit is even valid, and your correct `L_k` becomes
un-broadcastable (its input is spent). Chain-extension dominance is a race the honest
side wins **only when the honest side holds the newer transition**; when the *thief*
holds the newer (bad) state, the same Δ that gives honest holders a contest window is a
head start handed to the attacker. The race therefore rescues only the **dark/stalled-
Operator** case (nobody broadcasts the consuming transition; your `L_k` matures
unopposed — this is the "freeze, not theft" case §9 is genuinely good at). Against active
theft it fails, and recourse falls to rung 4 — exactly the asymmetry the A5 finding
exists to prevent anyone from forgetting.

> **Bottom line.** For an active, online party the gate is a true veto. For a passive
> member shorted by an *actively-colluding* Operator, recourse terminates at **bonded
> compensation, not coin recovery** (this is the *amount* security model of §13.1) —
> because you cannot broadcast a correct lattice that
> was never signed. That is the structural price of pooling funds in one shared UTXO
> without a covenant; the protocol's job is to shrink the set of cases that reach it
> (rules §7.1a, the full-table attestation, mesh archival, TVL-tracking bond) and to make
> the compensation actually cover the loss.

## 9. Bond and enforcement layers

**Critical separation: the exit never touches the emulator.** The lattice is plain
pre-signed Bitcoin transactions. An emulator shutdown — including the Operator killing
its own attested execution environment — is a **freeze, not a theft**: watchtowers trip
on the missed heartbeat commitment and every member exits on L1 with zero Operator
involvement. What remains to defend is the *amount* a passive member is owed when an active set
colludes (§8, row 3). There are two ways to defend it; the simpler one is now primary.

### Primary model: a FROST-in-TEE operator (no capital bond)

Take the Operator to be a **permissionless FROST federation running in TEEs** — anyone can
peer in via threshold resharing, and each node's signing share lives in an attested
enclave. The enclave runs the pulse-validity policy (carry-forward, conservation, correct
passive balances) and **refuses to contribute its FROST share to an invalid pulse**. So a
lattice that shorts a passive member **cannot be signed at all** — strictly stronger than
"it can be signed but you are compensated," and it needs **no TVL-sized capital and no
separate referee quorum**. The protocol then reduces to what it should be: a **framework
that generates the recurrent exit lattices in the background**, as part of the
federation's normal per-pulse signing — members and watchtowers receive their branch
automatically, with no bond ceremony.

The honest cost: the amount guarantee now rests on "**≥ `t` enclaves hold**" — hardware-
attestation trust rather than economic trust. It is **defense-in-depth, not a sovereign
root** (enclaves get broken), so membership must be *diverse*, so that breaking the FROST
threshold means compromising `t` **independent** operators' hardware, not one entity's.
And with no bond, a successful threshold-break is an **uncompensated** loss rather than a
compensated one — though the exit stays TEE-independent (your last-good lattice is plain
pre-signed Bitcoin), so the freeze/dark case still gets everyone out. Fidelity bonds
survive here only as **cheap Sybil-resistance of the permissionless membership** (so
"anyone can peer" can't become one entity quietly holding `t` shares) — not as capital
sized to TVL. This **swaps the bond's economic trust for the enclave threshold's hardware
trust**; like everything else it does not escape the trilemma (§13.2), it relocates the
third corner.

### Optional economic backstop: the bonded federation

For deployments that prefer an economic guarantee over hardware trust — or that want a
*compensation* backstop against a TEE-threshold break — the original bonded model follows.
It is now **optional**, not load-bearing; its enforcement is independent of the Operator's
infrastructure:

- **A `checkSigFromStack` punishment leaf would be circular — rejected.**
  `checkSigFromStack` is an *emulated* Arkade opcode, not Bitcoin L1 consensus (it is
  consensus on Liquid, not on Bitcoin). An Arkade-native bond
  slashed via an emulated opcode dies with the emulator: the malicious Operator simply
  shuts the instance down.
- **Adopted design: judicial federation bond.** The bond is held by k-of-n entities
  *independent of the pool's Operator* (e.g. other Arkade Operators, watchtower
  networks). Their only powers are: *pay victims on objective evidence* or *return the
  bond to the Operator at expiry*. The evidence is objective and machine-checkable with
  no emulator involved:
  - two valid signatures under the same epoch key `P_k` on conflicting spends; or
  - a continuity attestation `A_j` contradicted by a later published lattice paying a
    member less, with no member-signed debit in between.
  Federation trust applies to the **deterrent layer only — never to exit**.
- **How the slashing actually executes — and why it is *not* pure Bitcoin Script.** The
  bond is an on-chain UTXO the **Operator funds** and locks into a `k`-of-`n` multisig
  with the referees. **Bitcoin Script enforces only that multisig — not the fraud logic.**
  No current opcode can evaluate the evidence on-chain: Script cannot test whether two
  Schnorr signatures share a key and conflict, nor verify a signature against a message
  placed on the stack (that needs `OP_CHECKSIGFROMSTACK`, which Bitcoin lacks), and the
  Lightning-style nonce-reuse key-leak cannot be forced without pinning the nonce (a
  covenant). So the referees check the *objective, public* evidence off-chain and co-sign
  the payout to the victim (or the return to the Operator at expiry). The trust added is
  precisely **≥1 honest referee in the `k`-of-`n` set** who honors objective evidence and
  does not collude to steal or deny — reputationally exposed (anyone can recompute the same
  evidence) but not Script-enforced. Pure-Script slashing — *"reveal two conflicting
  signatures, take the bond"* — becomes possible only with the new opcodes of §12.2
  (`OP_CHECKSIGFROMSTACK`, or `OP_CAT`-verifiable hash-based one-time signatures whose
  reuse leaks a preimage that sweeps the bond); until then, the multisig-plus-referees
  construction is the honest mechanism.
- **Rejected alternative, documented honestly:** forced-nonce-reuse key-leak punishment
  (make any second `P_k` signature leak the aggregate secret) does **not** work with
  plain CHECKSIG: a cheater simply signs with a fresh nonce, and Script cannot pin
  the nonce.
- **Sizing and client enforcement.** The bond is per-pool and TVL-tracking. Wallets
  refuse to participate in pulses of an under-bonded pool (`bond <
  requiredCoverage(...)`) — client-side policy informed by a bond-reference field in the
  ABI (§11). **`requiredCoverage` is an at-risk-*per-epoch* floor, not total TVL:** the
  most that can be stolen before the next heartbeat is the passive value a single
  collusion can short, so full deterrence needs `bond ≥` (passive value at risk between
  heartbeats). Heartbeat cadence is the lever that keeps this affordable — frequent
  heartbeats shrink the at-risk window, so the bond covers per-epoch exposure rather than
  the whole pool. Below full coverage, the residual is exactly the +EV-above-bond risk of
  §12.1 item 3: a capital-efficiency-vs-coverage policy choice, not a free parameter.
- **Permanence.** Under the working assumption that no covenant soft fork ever
  activates on Bitcoin, the federation is a permanent fixture of the deterrent layer —
  and is engineered to be acceptable as one: evidence-only powers, k-of-n diversity,
  never in the exit path. The only contemplated consensus change that would retire it
  is the Great Script Restoration (§12.2), whose restored opcodes make the
  equivocation proof verifiable in Script directly.

### 9.1 Hardening the referees (TEE-constrained, bonded, conflict-free)

The federation's job is *halt-or-pay-per-evidence*, never *spend freely* — but a
`k`-of-`n` multisig is free to send anywhere, so absent a covenant the "only halt, not
steal" property must be supplied off-chain. Three hardenings, stackable, none of which
escapes the trilemma:

- **Attested execution (TEE) constrains the referee key.** If each referee's signing key
  lives in a TEE running *attested* adjudication code, the key will only co-sign a payout
  that matches the objective public evidence and is addressed to `{victim, operator}` —
  so a referee **cannot use its key to steal the bond, only to follow the rules or
  refuse**. This reduces the trust from "the referee is honest" to "the enclave is unbroken
  *and* the attested code is correct." Caveats stated plainly: TEEs are *defense-in-depth,
  not a sovereign root of trust* — enclaves have a long history of microarchitectural
  breaks — so use `k`-of-`n` **across diverse TEE vendors** (an attacker must break `k`
  enclaves of mixed make), and accept the added hardware-vendor trust. The output
  constraint to `{victim, operator}` is enforced by the enclave, not by Script (Script
  cannot constrain a multisig's outputs without a covenant).
- **Referee fidelity bonds — Sybil resistance first, punishment second.** Each referee
  identity is gated by a *publicly verifiable* Bitcoin fidelity bond — time-locked (a CLTV
  UTXO whose weight grows with the amount locked and the lock duration) or burned. The bond
  does two distinct jobs that must not be conflated:
  - **Sybil resistance (the clean, Bitcoin-native win).** A fidelity bond makes forged
    independence *expensive*: standing up `k` referees costs `k` locked bonds, and each
    bond ties a persistent, costly identity to a referee so reputation accrues to it. This
    is exactly the economic backing the `k`-of-`n` independence assumption was missing (the
    node-collusion worry of §13.5) — and it needs **no slashing machinery**: the bond only
    has to *exist and be provable*. It also keeps the construction Bitcoin-native rather
    than importing an external staking network. **Sizing chains cleanly:** corrupting the
    quorum must cost more than the operator bond it guards, which is itself
    `requiredCoverage` (≥ at-risk-per-epoch), so `Σ(referee bonds to reach k) ≥
    operatorBond ≥ stealable value`. Like the pool's own bond, fidelity bonds are
    time-bounded and must be **renewed**; the client check that refuses an under-bonded
    pool (§9) should verify the *referee* bonds are live and sized, not only the
    Operator's.
  - **Punishment (honestly bounded).** Making a referee bond *slashable on misbehavior*
    hits the same wall as the operator bond — Bitcoin Script cannot verify "this payout was
    unbacked" or "this referee censored a valid claim." Three partial backstops, strongest
    first: (i) **equivocation self-slashing** — structure each referee's payout
    authorization so that co-signing two conflicting payouts for the same case leaks that
    referee's key and anyone sweeps its bond (the one-time/nonce-committed-signature
    construction; pure-ish Script for the double-sign case, GSR-gated in general, §12.2);
    (ii) **attestation-gated recovery** — a referee reclaims its time-locked bond only
    against a TEE attestation that it followed the protocol, so misbehavior forfeits
    recovery (the off-chain TEE trust of the bullet above); (iii) **reputation** — for known
    bonded entities a public, costly, persistent identity makes getting-caught
    business-ending, the suspenders to the on-chain belt. Keep the referee set
    **independent of the Operator / threshold-MPC set (§13.5)** so the two collusions do not
    correlate.
- **The Operator may sit in the `k`-of-`n` for the *return* path only, never the
  *slashing* path.** Split the bond into two spending conditions: **pay-victim** requires
  `k`-of-`n` referees with the **Operator excluded** (otherwise it could block its own
  punishment), while **return-to-Operator** at expiry may require the Operator plus a
  timelock (wanting one's own bond back is aligned). Putting the Operator in the slashing
  quorum is a conflict of interest and is forbidden.

**Blast radius.** Even if the *entire* referee/TEE layer is compromised, the worst case is
**the bond is stolen or a valid claim is denied — the deterrent evaporates** — but the
**pool funds are untouched**, because the exit lattices are pre-signed and independent of
the bond apparatus: members still sweep their last-good amount. Referee compromise degrades
the *amount-deterrent*, never the *exit*. As everywhere else, this hardens the trusted
layer; only a covenant (§12.2) converts amount-safety into cryptographic self-custody.

## 10. Attack analysis appendix

Fifteen adversarial findings shaped this spec — A1–A13 from the protocol red-team,
A14–A15 from the recourse analysis (§8a). Severity: **CRITICAL** (breaks the safety
claim), **HIGH** (loses funds or bricks exit under a realistic adversary), **MED**
(griefing/liveness/cost).

| # | Attack | Severity | Resolution in this spec |
|---|---|---|---|
| A1 | **Operator-only heartbeat re-anchor voids all pre-signed exits** — new outpoint ⇒ txid change ⇒ every SIGHASH_ALL signature dead; re-signing needs deleted keys | CRITICAL | Heartbeat is a full cooperative on-chain pulse with complete lattice rebuild (§7.2). No cheap re-anchor construct exists or may be exposed (floating claims under GSR would relax this — §12.2) |
| A2 | **Silent-majority gap** — lattice signers are only Operator + `M_k`; nothing structurally forces correct passive slots; for 1-party pulses this degrades to "trust the Operator" | CRITICAL | Continuity attestation `A_k` over the *full* table each epoch + carry-forward verification by every transacting party (§7.1 step 4b) + cross-epoch fraud proof slashable on the bond (§9) |
| A3 | **"Publish the lattice" is unenforceable** — Operator signs last, can withhold mesh publication or the on-chain commitment selectively | HIGH | "No lattice *in my hands*, no pulse" (local possession gate, §7.1 step 4d); chained `h_k` dependency turns withholding into a visible stall that trips auto-exit (§7.1 step 6, §7.3) |
| A4 | **MuSig2 N-of-N brittleness** — one signer aborts mid-ceremony ⇒ epoch key can never sign again ⇒ if the lattice were incomplete, the exit leaf is permanently unspendable | HIGH | Lattice signed *before* the transition (§7.1 order); abort ⇒ pulse abandoned on still-protected `U_k`; passive members excluded from the aggregate (minimal signer set) |
| A5 | **Theft beats the race** — a colluding theft tx has no CSV; the lattice waits Δ; the defender is structurally slower | HIGH | Stated honestly: chain-extension dominance only kills *stale* lattices; anti-theft is the equivocation proof + bond (§8, §9), not a race |
| A6 | **Anchor pinning on shared lattice nodes** — occupying a shared internal node's anchor grief-blocks every member exiting through it | HIGH | Dedicated per-claimant anchors; TRUC topology; minimized shared-anchor surface in the lattice template (§7.1 step 3); heartbeat-SLA compensation from the bond |
| A7 | **Partial-lattice broadcast griefing** — broadcasting the root but no branches forces the pool into exit mode | MED | Monotonically harmless: the tree is fully pre-signed; any member pushes their own branch with CPFP; delays only, priced to the griefer via fees |
| A8 | **"Deletion attestations" are unfalsifiable** — you cannot prove a key was deleted | HIGH | Deletion demoted to hygiene; the trust anchor is equivocation detection, which requires **mandatory artifact retention** (§8); a resurrected key that signs anything new creates the fraud proof |
| A9 | **Renew-sweep races in-flight exits** — sweep maturity near `renew` can consume `U_k` under a maturing lattice | HIGH | Compiler-enforced ordering invariant `sweepDelay ≥ Δ + margin` creating a lattice-exclusive window (§7.4) |
| A10 | **Bond circularity & sizing** — emulated slashing dies with the emulator; fixed bonds get out-run by TVL | HIGH | Judicial federation bond, evidence-based, emulator-independent (§9); TVL-tracking sizing with client-side refusal; heartbeat cadence caps at-risk-per-epoch ≤ bond |
| A11 | **O(N) lattice re-sign cascade** — SIGHASH_ALL invalidates all descendants on any root change; "incremental subtree reuse" does not survive the txid cascade | MED→HIGH | Costed honestly (§7.1 step 3): O(N) compute for 2–3 parties, O(1) interactivity; two-tier hot-band sharding as the scaling valve; GSR floating-claim constructions named as the real fix (§12.2) |
| A12 | **Depositor verification is not enough** — verifying your slot at deposit does not protect later epochs you never sign | MED | Deposit completes only with branch + attestation + bond-coverage check in hand; continued protection explicitly requires a watchtower (§5, §8) |
| A13 | **Off-chain `h_k` equivocation** — Operator shows different chains to different parties while committing one hash on-chain | MED | `h_k` must be co-signed by Operator + threshold of `M_k` (§7.1 step 6): a fork necessarily carries someone's contradictory signature |
| A14 | **Buggy-honest conservation failure** — a ceremony bug makes `Σ(slots) ≠ value(U_k)` while `A_k` matches the buggy lattice, so there is no lie and no slashable evidence → silent unbacked loss | HIGH | Public finality predicate (§7.1a): conservation + consistency are recomputable from committed data; failure makes pulse `k` non-final and forces auto-exit on `k−1`, converting silent loss into a liveness halt with no fork |
| A15 | **Sub-dust no-exit** — balances below the 330-sat floor sit in a cooperative-only dust slot with no unilateral exit | MED | Named as a permanent, bounded recourse gap (§8a, §12.1 item 6); mitigated by client below-floor warnings and attesting the dust aggregate so over-debit is compensation-provable |

## 11. Compiler surface (future work — gated zones)

Changes touch `src/parser/grammar.pest`, `src/models/mod.rs`, and
`src/compiler/mod.rs`, all of which are supervised zones; this section is a proposal
only.

- **Options grammar**: a new `recurrent` flag alongside the existing canonical form:

  ```
  options {
      server = server;
      exit = exit;        // Δ, the contest window (int constructor param)
      renew = renew;      // absolute refresh deadline (int constructor param)
      recurrent = true;   // pool exit mode: PULSE instead of N-of-N
  }
  ```

- **Exit variant emission**: for `recurrent` contracts, the `serverVariant=false`
  tapleaf emits

  ```
  <PULSE_KEY> OP_CHECKSIG <exit> OP_CHECKSEQUENCEVERIFY OP_DROP
  ```

  instead of the N-of-N CHECKSIG chain. `<PULSE_KEY>` is a placeholder in the emitted
  ASM (same convention as `<SERVER_KEY>`), bound per epoch by the SDK ceremony.

- **ABI**: a new requirement type `recurrentExit` on the exit variant, carrying the
  lattice template: slot script (`SingleSig(<memberPk>)` + exit CSV — the existing
  pattern), tree arity, dedicated-anchor policy, dust policy (330-sat floor,
  cooperative-only dust slot), continuity-attestation format, the dispute-evidence
  bundle format (§13.4 — fixing it here is what keeps conforming clients from splitting
  on what counts as a valid halt trigger), and a bond reference for client-side coverage
  checks.

- **Timelock invariant**: the compiler rejects configurations where the operator sweep
  could mature inside the exit window (`sweepDelay < exit + margin`), per §7.4.

- **Explicitly absent**: any "operator-only re-anchor" construct (A1).

Everything else — ceremony ordering, artifact retention, watchtower triggers, TRUC
packaging, bond-coverage refusal — is SDK/ceremony policy, not compiler surface.

## 12. The no-fork endgame, and the GSR annex

Working assumption: **no covenant soft fork ever activates on Bitcoin.** PULSE is
designed to be the terminal construction under that assumption, not a stopgap. The
only consensus change this document contemplates at all is the **Great Script
Restoration (GSR)** — re-enabling the Script opcodes disabled in 2010 — treated here
as an annex, not a dependency.

### 12.1 Baseline: permanent operating characteristics

These are not "open problems awaiting a fork"; they are the operating envelope, each
with its compensating discipline:

1. **Passive carry-forward stays attestation-bonded.** A passive, watchtower-less
   member who retains nothing degrades to bonded-Operator trust. Discipline: the
   watchtower market (non-custodial; anyone can run one) plus mandatory artifact
   retention (§8). Hardening available today, no fork required: **k-of-n
   multi-Operator co-signing of the continuity attestation `A_k`** — lying about a
   passive balance then requires collusion across independent Operators, not just
   one.
2. **Heartbeats stay quorum-gated ceremonies.** Re-anchoring invalidates SIGHASH_ALL
   signatures, so every heartbeat is a full pulse. Discipline: heartbeat cadence is a
   protocol parameter enforced client-side; pools that cannot sustain their cadence
   should not grow.
3. **The defender stays slower than the thief.** The theft path has no CSV; the
   lattice waits Δ. Only the bond deters collusion: if `theft value > bond`, collusion
   of the Operator + all transacting parties of an epoch is profitable. Discipline:
   heartbeat cadence and client-side bond checks cap at-risk-per-epoch ≤ bond —
   wallets refuse pulses that would breach it (§9).
4. **Bond slashing stays federated.** Evidence-only powers, k-of-n diversity, never in
   the exit path (§9). This is the deterrent layer's permanent shape.
5. **Key deletion stays unprovable** — inherent; no consensus change fixes it. The
   design therefore never relies on it (§8, A8).
6. **Sub-dust balances have no unilateral exit.** Balances below the 330-sat floor are
   aggregated into a cooperative-only dust slot (§7.1 step 3), which by construction needs
   Operator cooperation to spend. Discipline: clients warn a member when their balance
   crosses below the unilateral-exit floor so they can consolidate while the Operator is
   live; the dust aggregate is attested in `A_k` so over-debiting it is at least
   compensation-provable. The structural floor itself is permanent absent a fork.

Worst-case for a passive member shorted by an actively-colluding Operator, recourse is
the bond (compensation), not coin recovery (§8a) — the bond is therefore a *cap on
compensable loss*, which is what items 3 and 6 are disciplined around.

### 12.2 The GSR annex (the only fork contemplated)

The Great Script Restoration proposes re-enabling the opcodes disabled in 2010 —
concatenation, substrings, bit operations, multiplication/division — under a *varops
budget* that bounds worst-case validation cost the way the existing sigops budget
bounds signature checks. It is not a "covenant soft fork" by name. But restored
concatenation **is a covenant in effect**, through two well-understood constructions:

- **Sighash reconstruction.** Script assembles the spending transaction's signature
  hash from stack elements (concatenation + SHA256) and verifies it with a fixed-key
  `OP_CHECKSIG` — constraining the spending transaction field by field. Transaction-id
  reflection extends this to introspecting the current outpoint.
- **Hash-based one-time signatures.** Their verification is pure hashing and
  concatenation, so Script can verify signatures over *arbitrary data* with no new
  signature-check opcode.

Under GSR, each baseline characteristic upgrades:

1. **Carry-forward becomes consensus-enforced** (closes A2 cryptographically). The
   exit leaf becomes a real covenant: "this output may only be spent to the
   distribution Merkle-committed by `h_k`," with each member's slot proven by a log-N
   Merkle path verified in Script. The pre-signed lattice becomes an optimization for
   cheap exits — no longer the safety net.
2. **Heartbeats no longer need the quorum** (closes A1 and A11). Exit claims built on
   sighash reconstruction can choose *not* to commit to the prevout transaction id, so
   they float across re-anchors without re-signing. The Operator can re-anchor
   unilaterally; incremental O(log N) state updates follow.
3. **The theft path disappears structurally** (closes the A5 asymmetry). A covenant
   exit leaf has no epoch key to collude with: there is nothing the Operator and the
   transacting parties can co-sign that pays anywhere other than the committed
   distribution.
4. **Slashing becomes L1-native and the federation evaporates** (closes the §9
   residue). Epoch authorizations double as hash-based one-time signatures; producing
   two conflicting one-time signatures under one epoch authorization is verifiable in
   the bond's punishment leaf with nothing but hashing. The equivocation proof stops
   needing judges.

All four verifications are hash-dominated (Merkle paths, one-time-signature chains)
and sized for a budgeted Script model.

## 13. Security model and dialectical review

This section answers the three questions the design is most often pressed on — *is this
1-of-N? can anyone halt epoch creation? is the Operator always the exit-creator?* — and
states the one thing the rest of the document must not overclaim.

### 13.1 Two security models, not one

PULSE has **two distinct security properties with two distinct trust models**, and
conflating them is the central error to avoid:

| Property | Model | Honest assumption |
|---|---|---|
| **Exit mechanism** (can I get *out*?) | **1-of-N** — the strongest tier | The lattice is fully pre-signed and non-custodial; *any one* honest data-holder in `{you, your watchtowers, mesh archivers}` can broadcast it. You yourself suffice (1-of-1). Against a non-racing Operator, exit always completes. |
| **Exit amount** (is the *number* in my slot right?) | **Bonded — not a clean 1-of-N** | The set whose honesty protects a passive member's balance in a pulse is `{Operator ∪ M_k}` — the Operator plus whoever is transacting. One honest member of that set refuses the bad pulse at the gate (§7.1 step 4b). But that set **excludes the victim** and can be **as small as two** (Operator + one transacting party — and if both collude, the honest count in it is zero). Below "1 honest in that set," safety degrades to *bonded compensation* (§9), an economic layer, not a cryptographic one. |

**Why the amount model is weaker than the systems PULSE resembles.** In a statechain or
a coinpool, every signer is checking *their own* balance and updates are N-of-N, so any
one refusal blocks — a true 1-of-N where the honest party is *defending their own funds*.
In Arkade, a VTXO owner is 1-of-1 over *their own* coins. In PULSE, **the victim is not a
required signer of the transition that can rob them**: the honest party who could save a
passive member is a *disinterested third party* (some other transacting party running
the §7.1 step 4b carry-forward check), not the victim. That carry-forward check is
therefore **policy-enforced, not incentive-compatible** — a transacting party has no
economic stake in a stranger's passive slot, so the check holds only because conforming
software performs it, and it is not a Nash equilibrium. This is the honest game-theoretic
floor, and it is why "1-of-N" must always be qualified as *"1-of-N for the mechanism,
bonded for the amount."*

### 13.2 The trilemma

The amount model is not weak by oversight; it is the corner the design chose. You cannot
have all three of:

- **(a) non-interactive passive members** — they sign nothing while idle (the entire
  open-membership selling point);
- **(b) no covenant** — the working assumption (§12);
- **(c) trustless safety of a passive member's *amount*** — cryptographic, not bonded.

PULSE takes **(a) + (b)** and pays by relaxing **(c)** to bonded compensation. A real
covenant (the GSR annex, §12.2) buys **(a) + (c)** by dropping (b). Forcing the victim to
co-sign every pulse that touches the pool buys **(b) + (c)** by dropping (a) — but that is
just a coinpool, and it destroys the passive/open-membership property. The trilemma *is*
the design, stated honestly; it is not a defect to be patched.

### 13.3 Dialectical summary

| Thesis | Antithesis | Synthesis |
|---|---|---|
| Pre-signed lattices give passive members a standing unilateral exit with no covenant | The lattice is signed only by `{Operator + transacting parties}`, never the victim — a unilateral exit to an amount *someone else wrote* | **Self-custody of the exit mechanism, delegated (bonded) custody of the exit amount** |
| Recurrent pulses keep the exit fresh | Recurrence puts the Operator in every pulse — perpetual operator dependency | Liveness of *progress* is operator-gated; liveness of *exit* is operator-free (you hold the last lattice) |
| Bond + equivocation proof deters theft | Economic security ≠ cryptographic; above the bond theft is +EV; and the preventing check has no incentive behind it | A cryptographically-enforced *mechanism* around an economically-enforced *amount* — a hybrid, not trustless |

### 13.4 Can anyone halt epoch creation?

Three vectors — two bounded, one intentional:

1. **The Operator can halt *all* epoch creation unilaterally** (it is a mandatory signer
   of every pulse). This is a real censorship/liveness power, but it is **bounded to
   "freeze + force mass exit," not theft**: a frozen pool just means everyone leaves on
   the last lattice. It is the same shape as Arkade's normal operator-liveness assumption, with a
   wider blast radius (one Operator freezes the whole pool's progress at once).
2. **Any single transacting party can halt *their own* pulse** by aborting the MuSig2
   round (N-of-N: one missing nonce or partial stalls it — A4). This blocks only pulses
   that party is in; it cannot censor others transacting with the Operator. Bounded
   griefing.
3. **Anyone with *objective* fraud evidence can halt epoch creation via the dispute
   artifact** (§8a) — this is intentional (the social freeze). Critical caveat: conforming
   clients must halt only on **machine-checkable** evidence; halting on unverified
   disputes turns "cry wolf" into a free pool-wide DoS. The admissible evidence is the
   two types defined in §9 (two conflicting `P_k` signatures, or an `A_j` contradicted by
   a later lattice) packaged as the §8a bundle; their exact wire serialization is an open
   item for the SDK/ABI (§11) — two implementations that disagree on the format would
   split the social layer, so the format must be fixed there, not left to convention.

### 13.5 Is the Operator always the exit-creator? (and the federation fix)

**Yes.** `P_k` always includes the Operator, so **no valid exit lattice can be produced
without it** — the Operator is a mandatory co-signer *of the safety net itself*. This does
not brick exit of *existing* funds (you still hold the last lattice), but it means there
is **no operator-free way to mint a new exit distribution**, the Operator is the **sole
liveness bottleneck** for progress, and its collusion with a small `M_k` is the only theft
path.

The highest-leverage no-fork improvement is to make **"the Operator" a k-of-n
federation** rather than a single party. This simultaneously (i) removes the single
liveness bottleneck (§13.4 #1), (ii) raises the theft-collusion threshold from
"Operator + M_k" to "k operators + M_k," and (iii) strengthens the continuity attestation
(§12.1 item 1). **Honest ceiling:** federation does *not* make the victim a signer, so it
widens and diversifies the trusted set but does **not** convert §13.1's amount model into
a clean 1-of-N over the membership, and does not escape the trilemma (§13.2). It is the
best available no-fork hardening, recommended as the baseline operator construction — not
a way out of the corner. Threshold guidance: pick `k` and `n` so that compromising `k`
independently-run operators is strictly harder than compromising one (`k ≥ 2`), and set
`n ≥ 2k − 1` so that even after `k − 1` compromises (safety margin intact) the remaining
`n − k + 1` honest operators still meet the `k`-of-`n` threshold needed to advance and
attest. A `1-of-n` federation is *weaker* than a single Operator (any one node enables
collusion); `n-of-n` is maximally safe but liveness-fragile. The bond and attestation
parameters (§9, §12.1 item 1) are sized against the same `k`.

**Realizing the federation as a threshold-MPC operator.** The strongest instantiation of
this federation is not a hand-rolled multisig but a **threshold-MPC signing network** that
acts as the Operator's side of every signature. A non-collusive scheme (the kind where the
network can sign *only* together with the user, and the network side is itself an MPC
across hundreds–thousands of nodes with identifiable abort — e.g. 2PC-MPC) is a clean
drop-in: because such schemes now produce **Schnorr/Taproot-compatible** signatures, the
network simply produces the Operator's share of `P_k`, `A_k`, and `h_k`, while the
transacting parties `M_k` remain the always-required co-signers — no change to the Bitcoin
side of the design. This upgrades three named weaknesses at once: operator-collusion theft
now requires breaking the MPC threshold rather than bribing one party; the network can
**enforce the verification-gate policy *before* it co-signs** — refusing its share for any
pulse that violates passive carry-forward or conservation — which turns A2's
policy-but-not-incentive-compatible client check into something an honest threshold
actually enforces; and key-resurrection (A8) now needs threshold collusion. Identifiable
abort also lets the network's own staking punish misbehavior, partly subsuming the §9
referee federation for the operator-collusion case. **The same honest ceiling still
binds, and two limits are specific to this realization:** the MPC sits on the
**cooperative path only** — the exit must stay pre-signed and MPC-independent, so that the
lattice broadcasts even if the MPC network is gone (never put MPC liveness in the custody
path); and it does **not** make the victim a signer, so amount-safety merely moves from
"trust one Operator" to "trust the MPC threshold" — quantitatively far stronger, but still
committee trust, not cryptographic self-custody, and so it does not escape the trilemma
(§13.2). It also imports that network's own liveness, security, and economic assumptions —
a real external dependency weighed against PULSE's "buildable on Arkade" baseline.

**The threshold benefit is only as real as the network's Sybil resistance.** "Collusion
now requires breaking the MPC threshold" holds *only if the nodes are genuinely
independent* — and node independence **cannot be proven cryptographically**; it is the
same unprovable real-world property as key deletion (A8) and federation non-collusion
(§9). It rests entirely on economics and social structure: per-node staking with slashing
sized **above the stealable value** (the MPC analogue of `requiredCoverage`, §12.1 item 3),
identifiable abort (which punishes a *defector* but not a *colluding majority*), and
genuine stake distribution. If those fail — the "nodes" are one entity behind a façade, or
a staked majority colludes — the threshold collapses back to the single-Operator-collusion
case of §8 (row 3), **but no worse**: exit stays MPC-independent and the bonded-amount
model already assumes that collusion is possible, so a fake threshold degrades PULSE to its
existing floor, never beneath it. Wallets should therefore gate the "MPC-secured" label on
a measured stake-distribution bound (e.g. a Nakamoto-coefficient floor), the same way they
refuse an under-bonded pool (§9) — the benefit is quantitative and economic, never a
cryptographic guarantee of independence.

### 13.6 Feasibility: the lattice is an Arkade VTXO tree

The "exit lattice" is **structurally an Arkade VTXO tree**, which is deployed and
covenant-free — so the construction is buildable on Bitcoin today with no soft fork:

- **The tree:** a Taproot root spending the shared UTXO, internal branches splitting
  value, `SingleSig + CSV` leaves — signed N-of-N via MuSig2 with the Operator included.
  Arkade is itself covenant-free — its VTXO trees are pre-signed and operator-cosigned
  with no covenant opcode — establishing that all-of-all pre-signing emulates a covenant
  with **no introspection opcode and no fork**. PULSE's epoch-key-then-delete is the same
  sign-once-then-delete key technique (with the unprovable-deletion caveat, A8).
- **The fee plumbing:** dedicated per-leaf anchors via **P2A** (standard relay since
  Bitcoin Core 28.0), **TRUC/v3** relay, and ephemeral anchors — all merged. §7.1 step
  3's "dedicated anchors + TRUC" is real, not aspirational. Implementer caveat: a
  P2A-bearing lattice transaction only propagates across peers on Core ≥28.0 (or
  equivalent relay policy), and a lattice that does not propagate is a failed exit — so
  wallets should broadcast through P2A-aware relay rather than assume universal support.
- **The binding constraint:** the SIGHASH_ALL txid cascade (A11) forces re-signing the
  **whole O(N) tree every pulse**, versus Arkade's once-per-*batch*. This is realistic for
  low-to-moderate pulse frequency; a high-throughput pool needs the two-tier hot-band
  sharding (§7.1 step 3). MuSig2 for the epoch key is a two-round ceremony over the small
  online `M_k` — passive members are correctly excluded from it.

**Verdict:** no Bitcoin-Script or transaction-structure reason the lattice cannot be
built as described. Feasibility is bounded by *signing throughput*, not consensus rules.
("Lattice" is the splitting-tree nomenclature here — a radix/Merkle tree — unrelated to
lattice *cryptography*.)

## Trust statement

> PULSE has **two security models, not one.** The **exit mechanism is 1-of-N** and
> emulator-independent — pure pre-signed L1 transactions, any one honest data-holder can
> broadcast, Operator or emulator shutdown means *freeze, never theft*. The **exit amount
> is enforced, not trustless**: a passive member's balance is protected only by the
> honesty of `{Operator ∪ the transacting parties}` of a pulse — a set that excludes the
> victim and can be as small as two. The **primary model** closes that set with a
> **FROST-in-TEE Operator** (§9) whose attested enclaves refuse to sign an invalid pulse,
> so the bad lattice cannot be produced — hardware-attestation trust, no capital; an
> **optional bond** adds an economic *compensation* backstop for those who prefer it to
> hardware trust. Either way the amount rests on enclave-threshold or committee trust, not
> cryptographic self-custody — the **trilemma** (§13.2): with non-interactive passive
> members and no covenant, amount-safety *must* be enforced by a trusted layer rather than
> by consensus. Covenant-grade trustlessness of the amount is reachable only through the
> GSR annex (§12.2); absent any fork, this **trustless-mechanism / enforced-amount** model
> is the end state, and the design is engineered to be livable as exactly that.
