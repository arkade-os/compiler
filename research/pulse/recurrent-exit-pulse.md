# PULSE — Recurrent Unilateral Exit for Emulator-Enforced Pools

**Pooled Unilateral-exit via Lattice State Epochs. Revision 2 (amended).**

A protocol for giving open-membership pool contracts on Arkade a *standing* unilateral
exit, enforced by recurrent state updates between the transacting parties. This document
is a design specification: it defines the protocol lifecycle, the trust model, the
attack analysis — seventeen adversarial findings (A1–A17), detailed in §10 — that shaped
it, and the compiler surface that would standardize it. It proposes no code changes; the
compiler-facing sections are future work.

Cross-references: [`options.md`](../../examples/options/options.md) (the two-tapleaf
model this design generalizes), [`bonds.md`](../../examples/bonds/bonds.md) (pool
covenants and today's exit asymmetry).

## Table of contents

- [0. Amendment log (revision 2)](#0-amendment-log-revision-2)
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
  - [7.5 Exit notice and eviction-with-payout (D5)](#75-exit-notice-and-eviction-with-payout-d5)
- [8. Invalidation model](#8-invalidation-model)
- [8a. Recourse: when the count doesn't check out](#8a-recourse-when-the-count-doesnt-check-out)
  - [Failure modes and where each lands](#failure-modes-and-where-each-lands)
  - [The recourse ladder (strongest → weakest)](#the-recourse-ladder-strongest--weakest)
  - [The mechanical race, analyzed honestly](#the-mechanical-race-analyzed-honestly)
- [9. Bond and enforcement layers](#9-bond-and-enforcement-layers)
  - [Primary model: a FROST-in-TEE operator (no capital bond)](#primary-model-a-frost-in-tee-operator-no-capital-bond)
  - [The seal set](#the-seal-set)
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

## 0. Amendment log (revision 2)

Changes relative to the revision-1 draft (PR #45, `docs/recurrent-exit-pulse.md`):

1. **Relocated to `research/pulse/`.** The repository restructure removed the `docs/`
   tree; research-grade protocol documents now live under `research/`. Cross-references
   updated to the new `examples/<domain>/` doc locations.
2. **The current-state exit race is now analyzed** — the one case revision 1 left
   unexamined. Two new findings: **A16 (live-Operator exit denial)**, which revision 1
   permitted *without leaving any slashable evidence*, and **A17 (current-root broadcast
   griefing)**, which supersedes the full-root case of A7.
3. **New mechanism, §7.5: exit notices + eviction-with-payout.** The only conforming way
   to displace an in-flight exit of the current state is to pay the exiting member in
   full, on-chain, in the displacing transition. This upgrades the exit guarantee from
   *"exit completes against a dark Operator"* to **exit-or-payout against any Operator**,
   and reprices exit griefing into a self-limiting nuisance.
4. **Per-pulse finality decoupled from block production.** Revision 1 required `h_k`
   on-chain before the next pulse, silently capping pulse throughput at batch cadence.
   Finality is now gated by an off-chain **epoch seal** (a k-of-n data-availability
   receipt); the on-chain batch commits the seal-chain head, preserving the
   visible-liveness-fault property.
5. **Terminology.** *Checkpoint* is deliberately not used for the seal: Arkade already
   uses **checkpoint transactions** for the intermediate pre-signed transactions users
   co-sign when spending VTXOs offchain — themselves an anti-griefing device. See the
   note in §4.
6. **Threshold continuity attestation promoted.** k-of-n co-signing of `A_k` moves from a
   §12.1 optional hardening to the default in the primary (FROST-in-TEE) model.
7. **Anchor topology revised (A6).** Per-claimant anchors on every node were an
   O(N log N)-output blowup; replaced by one keyless P2A anchor per node (TRUC sibling
   eviction defeats occupation) with per-claimant anchors at slot level only. Claimant
   attribution now comes from sealed exit notices, not anchor provenance.
8. **§2 and §11 rewritten for the current compiler surface.** The `options { ... }`
   block and the `serverVariant` ABI shape no longer exist; exits are author-written
   `tapscript` leaves and the ABI is grouped (`functions[]` with `arkade` + `leaves[]`).
9. **Timelock margins tightened (§7.4).** `margin` now explicitly includes virtual-chain
   depth and a stampede fee buffer; clients cap pulses-between-heartbeats. The
   slot-level CSV's rationale is stated (§7.1 step 3).

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
  people transacting — every single time, and an **independent panel stamps a receipt**
  confirming it holds the full paperwork before the next move can happen.
- **The bank cannot quietly stop your cheque.** If a cheque is in motion and the bank
  wants to keep the piggy bank together, the rules allow exactly one way to intervene:
  **pay that person their full balance on the spot**. A cheque in motion ends only two
  ways — it clears, or you are paid. (A prankster who cashes someone else's cheque just
  pays the fees to hand them their money early.)
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
  self-incriminating paper trail. Either way, one set counts, and you hold your copy.

- **A public headcount protects the people not in the room.** You don't have to show up
  every time others transact. So how do you know *your* ticket still says the right number
  when you weren't watching? Each time, the clerk publishes a **signed headcount** — a
  public, stamped list of what *every* member is owed, not just the people doing the deal.
  Anyone in the world can check that the new tickets match that list and that the totals
  add up. If they don't, honest software everywhere refuses the change and the group falls
  back to the last good set of tickets. A mistake can't quietly slip through; it gets
  caught and rewound.

- **Leaving can't be stalled.** Want out while the clerk is still around but stonewalling
  you? You hand in a written **exit notice** — like giving notice on a lease. From that
  moment, the only lawful "eviction" is one that **pays you your full balance
  immediately**. The clerk can't keep tearing up your ticket and dealing you a new one
  forever; either your ticket cashes, or you're paid out on the spot. Both are exits.

- **If the clerk lies, they lose a cash deposit** (optional backstop). Before running the
  jar, the Operator can put up a **security deposit** held by an independent referee
  group. If the Operator is ever caught doing a forbidden thing — signing two
  contradictory documents about the same money, or evicting someone without paying them —
  that is black-and-white proof of cheating, and the deposit is paid to the victim.

- **A watchdog can stand guard for you.** Because the tickets work without you lifting a
  finger, you can run (or hire) a **watchdog** that watches the ledger and cashes your
  ticket automatically the moment anything looks wrong — the clerk going silent, a
  deadline approaching, or two conflicting documents showing up.

- **The one honest catch.** When you are *not* in the room, the amount on *your* ticket is
  filled in by the people who are — checked by the public headcount, stamped by the
  independent panel, and (optionally) backed by the deposit, but not personally signed by
  you. So your ability to *leave* is rock-solid and needs nobody's permission; the
  *number* on your ticket is normally right (everyone can check the math) and, if someone
  manages to cheat it, the deposit pays you back. It is *"you can always get out, and
  you're financially covered if the amount is wrong"* — not *"the amount is impossible to
  get wrong."* That distinction is the whole trade-off.

- **Why "recurrent."** Tickets don't last forever. Every so often the whole arrangement is
  renewed on the public ledger, like resigning a lease, which keeps everyone's tickets
  fresh and cheap to cash. The practical upshot: don't go *completely* dark forever —
  check in now and then (or let your watchdog do it), and your money stays yours.

---

## 2. Motivation: the gap in today's exit compilation

On the current compiler surface, a contract compiles into **function groups**: each
covenant function gets

1. **A synthesized cooperative leaf** — the `arkade` covenant (introspection over
   `tx.outputs`, asset groups, recursive covenants via `new Self(...)`), terminating in
   the injected `<SERVER_KEY>`/emulator signatures. Introspection is *emulated*: the
   Operator validates the transition off-chain and refuses to co-sign invalid ones. On
   L1, the only thing consensus enforces on this path is the signature set.
2. **Author-written `tapscript` leaves** — pure Bitcoin Script, require-only: signatures,
   hashlocks, CLTV/CSV. The unilateral exit is such a leaf, naming keys fixed at
   instantiation:

   ```solidity
   function unilateral(signature userSig) tapscript {
       require(older(exit));
       require(checkSig(userSig, user));
   }
   ```

This works for closed contracts with a fixed cast. It **collapses for open-membership
pools** — recursive covenants that anyone can spend cooperatively (AMMs, lending pools,
the repayment pool in `bonds.md`):

- A tapscript leaf can only name keys known at instantiation. Membership is dynamic and
  unbounded, so an exit leaf names either the wrong parties or nobody — the pool contract
  either ships with **no unilateral leaf at all**, or with a curator/operator-gated leaf
  that is custodial by construction.
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
   final when its pulse ceremony completes and is sealed, decoupled from block
   production.
4. **Bounded lifetime.** The pool's `renew` expiry forces a recurrent on-chain refresh
   (the heartbeat), which resets exit cost and re-protects the full membership.
5. **Exit-or-payout.** The only conforming way to displace an in-flight exit of the
   current state is to pay the exiting member in full, on-chain, in the displacing
   transition (§7.5). Nothing else may void a current-state exit.

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
| **Continuity attestation `A_k`** | Schnorr attestation over the Merkle root of the *full* state table `S_k` — Operator-signed; threshold-signed in the primary model (§9) |
| **Pulse commitment `h_k`** | `H(h_{k-1} ‖ S_k ‖ txid(T_k) ‖ root(L_k) ‖ A_k)`, co-signed by Operator + threshold of `M_k` |
| **Epoch seal `σ_k`** | k-of-n countersignature over `h_k` by the seal set, issued only after the §7.1a predicate passes **and** the sealers hold the full artifact bundle. The per-pulse finality gate (§7.1 step 6) |
| **Seal set** | The k-of-n entities issuing epoch seals — independent of the Operator; defaults to the referee federation of §9. Never in the exit path |
| **Exit notice `X_k(m)`** | Member `m`'s signed declaration invoking unilateral exit at epoch `k`; sealed notices are objective, timestamped evidence (§7.5) |
| **Eviction pulse** | A transition consuming `U_k` while an exit is in flight; conforming **only if** it pays the noticed/claiming member(s) in full on-chain (§7.5) |
| **Heartbeat** | A pulse whose transition tx lands on-chain, re-anchoring the pool tip with a freshly built full lattice |
| **Δ (`exit`)** | The exit leaf's relative timelock — the contest window |
| **`renew`** | The pool's absolute expiry, after which the Operator's sweep path eventually matures |
| **Bond** | The Operator's optional on-chain security deposit, held by a `k`-of-`n` federation of referees independent of the Operator; pays victims on objective evidence or returns to the Operator at expiry (§9) |
| **`requiredCoverage`** | The minimum bond size — an at-risk-*per-epoch* floor (the passive value a single collusion could short before the next heartbeat), not total TVL (§9) |

> **A note on "checkpoint."** Arkade already uses **checkpoint transactions** for
> something specific: the intermediate pre-signed transactions a user co-signs when
> spending VTXOs offchain, which close a griefing window during transfers. PULSE
> deliberately does **not** reuse the word for its federation receipt — that is the
> **epoch seal** — and the pool-scope anti-griefing role that checkpoint transactions
> play for individual VTXO transfers is played here by **exit notices + eviction
> pulses** (§7.5). ("Seal" is used in the plain sense of a stamped receipt; it has no
> relation to single-use seals.)

## 5. Interactivity requirements

| Role | Signs | Online when | Notes |
|---|---|---|---|
| **Passive member** | **Nothing after deposit** | Own deposit/withdraw only | Must *retain* exit artifacts (or delegate to a watchtower); interactivity is borne by transactors |
| **Transacting parties** | Lattice + transition + `h_k`, in **one ceremony** (two MuSig2 rounds, one network round-trip) | Their own transaction | Typically 1–2 parties |
| **Operator** | Every pulse + attestation + commitment | Always-on | Absence ⇒ freeze ⇒ everyone exits via lattices |
| **Seal set** | Epoch seals only | Per pulse (k-of-n threshold) | Data-availability custodian; never in the exit path; a stalled seal set is a visible liveness fault (§7.1 step 6) |
| **Watchtower** | Nothing (lattice is fully pre-signed) | Monitoring only | Can broadcast *anyone's* exit and file the owner's exit notice if delegated; non-custodial |
| **Heartbeat participants** | Operator + that pulse's transacting parties only | — | Passive members are **not** needed at heartbeats |
| **Genesis** | Operator only, if the pool starts empty and members join via deposit pulses | — | **No all-hands N-of-N ceremony ever exists** |

## 6. The exit leaf

The compiler-visible, standardized artifact. For a `recurrent` pool, the exit leaf
emits — instead of a fixed-key CHECKSIG:

```
<exit> OP_CHECKSEQUENCEVERIFY OP_DROP <PULSE_KEY> OP_CHECKSIG
```

- `<PULSE_KEY>` is the epoch key `P_k` for the pool VTXO of that epoch. Constant size,
  regardless of membership.
- The **only possible spend** of this leaf is the pre-signed lattice root: the
  ephemeral keys behind `P_k` are deleted after signing, making the lattice a
  *de-facto covenant*.
- The CSV `Δ` is the **contest window**: transition transactions carry no delay, so
  anyone holding a newer signed transition can extend the chain on-chain, consuming
  `U_k` and voiding a stale lattice. This *chain-extension dominance* replaces
  revocation/punishment for the stale-state case.
- **Chain-extension is symmetric, and revision 2 constrains the other direction.** The
  same no-CSV property that lets honest holders kill a *stale* lattice also lets a
  *live* Operator displace an exit of the **current** state. That displacement is
  conforming only as an **eviction pulse** — one that pays the exiting member in full
  (§7.5). Chain extension does **not** defend against a fresh colluding theft — see §9
  and finding A5.

## 7. Protocol lifecycle

### 7.0 Genesis (D0)

1. If the deployment uses the optional bond (§9), the Operator posts it, sized to at
   least `requiredCoverage(initialTVL)` (TVL = the pool's total value locked).
2. The pool contract is deployed: an open-membership recursive covenant whose
   cooperative path the Operator emulates, with a `recurrent` exit leaf.
3. Preferred genesis: **start empty**. The first members join via ordinary deposit
   pulses, so no all-hands ceremony exists. (If a pre-seeded genesis is used instead,
   every genesis member must be online once to co-sign `L_0`.)
4. The Operator publishes `h_0`, obtains the seal `σ_0` per §7.1 step 6, and anchors
   `U_0` in a batch transaction.

### 7.1 Pulse ceremony (D1) — atomic; order is load-bearing

A pulse either completes fully or is abandoned, leaving the pool on `U_k`, whose
lattice is already valid.

1. **Propose.** A transition `T_{k+1}` is proposed, changing only the transacting
   parties' balances. The Operator emulates the contract's introspection covenant
   against it. `S_{k+1} = S_k` with only `M_{k+1}` slots changed. If any exit notice
   is outstanding against `U_k` (§7.5), the proposal **must** include the noticed
   members' full payouts, or it is non-conforming from the start.
2. **Attest.** The continuity attestation `A_{k+1}` is signed over the Merkle root of
   the *entire* `S_{k+1}` — every member, not just the transacting parties. One Schnorr
   signature (threshold-signed in the primary model, §9); O(1) on-chain footprint;
   O(log N) inclusion proofs per member.
3. **Lattice first.** The parties build and MuSig2-sign `L_{k+1}` under
   `P_{k+1} = MuSig2(Operator, M_{k+1})`:
   - Root spends `U_{k+1}`'s exit leaf; the tree splits into per-member slots
     (`SingleSig(memberPk)` + the member's own exit CSV — slots are ordinary Arkade
     VTXOs, so they keep standard VTXO exit semantics and can be re-onboarded; the
     total worst-case exit latency is therefore chain-broadcast + Δ + log N
     confirmations + the slot CSV, and §7.4's margins are sized against it).
   - **One keyless pay-to-anchor (P2A) output per lattice node** — anyone can fee-bump
     any node; TRUC ("v3") transaction topology, whose sibling-eviction rule makes an
     occupying low-fee child replaceable, defeating anchor-occupation griefing (A6).
     Per-claimant anchors exist at **slot level only**. Lattice txs opt out of
     replace-by-fee — fee bumping is anchors + child-pays-for-parent (CPFP) only.
     (Claimant attribution comes from sealed exit notices (§7.5), never from anchor
     provenance, so internal nodes do not need per-claimant anchors — which would be
     O(N log N) outputs.)
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
   - (c) any outstanding exit notice is honored with a full payout (§7.5);
   - (d) if the deployment is bonded, the bond still covers the pool's at-risk value
     (§9);
   - (e) **its own lattice branch is in its hands** — *"no lattice in my hands, no
     pulse."* Publication to the relay mesh alone is never trusted.
5. **Transition signing.** Only now do the Operator + transacting parties sign
   `T_{k+1}` (SIGHASH_ALL, nSequence final).
6. **Commit and seal.** `h_{k+1}` is **co-signed by the Operator + a threshold `t` of
   `M_{k+1}`** so the Operator cannot unilaterally author forks (`t ≥ 1`; a fork then
   requires `t` contradicting signatures, so higher `t` is more fork-resistant at the
   cost of more required online co-signers — `t = 1` minimal, `t = |M_{k+1}|`
   maximal). Full artifacts `(S_{k+1}, T_{k+1}, L_{k+1}, A_{k+1})` go to the relay
   mesh, content-addressed by `h_{k+1}`, **and to the seal set**, which issues the
   epoch seal `σ_{k+1}` only after (i) recomputing the §7.1a predicate and (ii)
   confirming the full bundle is *in its hands* — the seal is a **data-availability
   receipt**, not a mere countersignature. **The next pulse is invalid until `σ_k` is
   issued.** Sealing is off-chain and per-pulse, so pulse rate is decoupled from block
   production (principle 3); the Operator's next on-chain batch commits the current
   **seal-chain head**, so a withheld seal or a withheld batch commitment is a
   *visible liveness fault* within one batch interval that trips auto-exit (§7.3).
   (Revision 1 required `h_k` itself on-chain before the next pulse, which serialized
   pulses at batch cadence; the seal restores throughput while keeping withholding
   visible. A deployment unwilling to depend on a third-party seal set for liveness
   may run **self-sealed** — the Operator threshold seals — accepting
   same-trust-domain data availability; see §9.)
7. **Delete ephemerals** — only after all parties confirm artifact storage. This is
   hygiene, *not* a trust anchor: deletion is unprovable; the real guarantee is
   equivocation detection (§9).

**Who signs what:**

| Artifact | Signers |
|---|---|
| `T_{k+1}` (transition) | Operator + `M_{k+1}` |
| `L_{k+1}` (lattice) | `P_{k+1} = MuSig2(Operator, M_{k+1})`, **before** `T` is signed |
| `A_{k+1}` (full-table attestation) | Operator (threshold-signed in the primary model, §9) |
| `h_{k+1}` (commitment) | Operator + threshold of `M_{k+1}` |
| `σ_{k+1}` (epoch seal) | k-of-n seal set — predicate check + data-availability receipt |

### 7.1a Public finality predicate (conservation + consistency)

The verification gate (step 4) is a *veto*, but only the transacting parties run it.
There is a second check that **anyone** can run — passive members, watchtowers, new
depositors, third parties — from data the commitment `h_k` binds, with no signing role
required. It is the safety net for everyone the gate does not cover, it is what the
seal set **must** recompute before sealing, and it is what catches an
*honest-but-buggy* pulse (one with no lie to slash on).

A pulse `k` is **final only if** both hold, recomputed from the published `S_k`,
`root(L_k)`, and `value(U_k)` — read directly on-chain when `U_k` is anchored, and
derived from the last on-chain anchor plus the published transition chain when `U_k`
is virtual (both objective from committed data):

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
checking — so external settlement must gate finality on this same predicate (in
practice: on the epoch seal, which implies it).

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
  **at-risk-per-epoch stays ≤ the Operator bond** (§9) — and, independently, so the
  virtual-chain-depth cap of §7.4 holds.
- **Eviction pulses land on-chain by definition** (§7.5). A well-run Operator folds
  them into the heartbeat schedule — an eviction is simply a heartbeat that also pays
  the leavers — so the cost of defending against exit griefing amortizes into
  scheduled maintenance rather than being a separate loss.

### 7.3 Unilateral exit walk (D3)

1. A trigger fires — **voluntary**: the member (or their watchtower) files an exit
   notice `X_k(m)` (§7.5) and proceeds regardless of Operator health; or
   **defensive**: a missed epoch seal or batch commitment, `height ≥ renew − Δ −
   margin`, or a **conflicting published artifact**.
2. Broadcast the chain tip if needed (any unconfirmed transitions since the last
   heartbeat), then the **lattice root**, spending `U_k`'s exit leaf after the Δ
   contest window.
3. Broadcast the member's **branch path** (log N transactions), CPFP-bumping via the
   node anchors.
4. After the slot's own CSV matures, sweep `SingleSig(memberPk)` to a wallet.

**Outcome guarantee.** The walk ends in the slot sweep — or, if a conforming eviction
pulse displaces it, in an immediate on-chain payout of the member's full balance
(§7.5). Both are exits; neither requires the Operator's goodwill.

### 7.4 Expiry (D4) and the timelock ordering invariant

The Operator's renew-sweep must mature strictly after exits can complete:

```
sweepDelay ≥ Δ + margin        (compiler rejects violations)
```

making the window `[renew − Δ − margin, renew + sweepDelay)` **lattice-exclusive**: the
sweep can never consume `U_k` out from under an in-flight exit. `margin` scales with:

- **lattice depth** (log N confirmation time),
- **virtual-chain depth `D`** — the exit must first broadcast up to `D` pending
  transitions (§7.3 step 2), each needing confirmation, and
- a **fee-spike buffer sized for the pool's own stampede**: a deadline exit is
  correlated — N members may walk at once, and the pool's exit is itself the
  congestion event.

Clients therefore also enforce a **cap on `D`** (pulses since the last heartbeat) —
the same cap that keeps at-risk-per-epoch ≤ bond (§9). Wallets and watchtowers
auto-exit if the pool has not heartbeat by `renew − Δ − margin`.

### 7.5 Exit notice and eviction-with-payout (D5)

Revision 1 analyzed stale-lattice broadcasts, commitment withholding, and fresh
colluding theft (§8) — but left a fourth case unexamined: **an exit of the correct,
current state, broadcast while the Operator is alive.** Chain-extension dominance cuts
both ways, and both directions were unhandled:

- **Griefing (A17).** The current lattice root is fully pre-signed and mesh-published
  *by design* — anyone can broadcast it. An unbumped root is inert (a TRUC zero-fee
  parent cannot confirm without a CPFP child), but a **bumped** root forces a choice:
  let it mature — a forced mass exit in which the griefer pays for one root and one
  branch while every other member pays their own branch walk (≈N× damage leverage) —
  or displace it, which costs the Operator an on-chain transaction **plus a full O(N)
  lattice re-sign**. Retries cost the attacker nothing until one confirms.
- **Exit denial (A16) — the worse direction.** The only defense (displace within Δ via
  a no-CSV transition) is equally available to a *malicious live* Operator against a
  *legitimate* exit — repeatably, forever, at one on-chain transaction per attempt.
  Each displacement carries the member's balance forward *correctly*, so under
  revision 1 **denial produced no slashable evidence whatsoever**: no equivocation, a
  clean attestation, a passing §7.1a predicate. And denial composes with expiry: deny
  until `renew`, and the sweep path matures — evidence-free stalling becomes
  theft-at-expiry. Revision 1's standing-exit guarantee therefore held only against a
  *dark* Operator; §13.1's "against a non-racing Operator" qualifier was carrying far
  more weight than six words should.

Both directions are closed by one normative rule.

> **Exit notice.** A member `m` (or their delegated watchtower) files
> `X_k(m)`: a message signed by `m`'s slot key, referencing the sealed tip `h_k`,
> invoking unilateral exit of slot `m`. Notices go to the relay mesh **and the seal
> set**; a **sealed notice is objective, timestamped evidence**. (Mempool observation
> deliberately confers no obligations — mempool state is not consensus and cannot be
> proven after the fact. The notice exists precisely to make "an exit was in flight"
> objective.)
>
> **Eviction-with-payout.** From the moment `X_k(m)` is sealed, any transition
> consuming `U_k` — and any subsequent transition, until the notice is discharged — is
> **conforming only if it pays `m`'s full `S_k` balance to an on-chain output under
> `m`'s slot key.** A displacing transition without that payout is an **unlawful
> eviction**: non-final under §7.1a-extended client policy, refused by the seal set,
> unsignable under the primary model's enclave policy (§9), and — where the optional
> bond exists — slashable on the objective evidence pair (sealed `X_k(m)`, sealed or
> broadcast displacement lacking the payout).

Consequences:

- **Exit-or-payout.** After a notice, one of exactly two things happens within the
  contest window: the lattice matures (exit), or a conforming eviction pulse pays the
  member immediately (a *faster* exit). A live adversarial Operator can no longer
  stall an exit; a dark one never could. Refusing to pulse at all is the remaining
  option, and it is a **visible stall** — missed seal, missed batch commitment — that
  trips pool-wide auto-exit (§7.3).
- **Griefing is repriced into a self-service exit.** Broadcasting the current root now
  *is* requesting eviction: the "griefer" is paid out in full and removed from the
  pool (re-entry costs an ordinary deposit pulse). A third party bumping someone
  else's root is paying fees to hand that member a fast exit. A flood of simultaneous
  notices degenerates into a cooperative unwind — which is the correct limit for a
  pool most of whose members want out.
- **The honest Operator's defense playbook is now legitimate and cheap.** Ignore
  unbumped roots (they cannot confirm). On a bumped root or sealed notice, evict with
  payout — folded into the next heartbeat (§7.2), so the defense cost amortizes into
  scheduled maintenance. Never displace without paying: that is the one forbidden
  move, and it is the one that creates evidence.
- **Denial now leaves a trail.** The Operator's options against a noticed exit are:
  honor it (payout), let it mature (exit), or stall visibly (mass auto-exit). The
  evidence-free denial loop of revision 1 no longer exists.

**Honest bounds.** The *payout leg* of exit-or-payout is enforced by the same trusted
layer as the amount model — enclave policy, seal refusal, client conformance, optional
bond (§13.1) — not by Bitcoin consensus. Against a fully compromised enforcement stack
the revision-1 racing gap reopens; that is why notices are sealed (the evidence
outlives the stack), why clients must treat *any* displacement of a noticed exit
without payout as a §8 dispute (halt + auto-exit on the last good epoch), and why the
`renew`-adjacent auto-exit margin (§7.4) exists. §7.5 closes the **mechanism-denial**
gap; it does not change the **amount** model of §13.1, and it cannot help sub-dust
slots (§12.1 item 6). Under GSR (§12.2 item 3) the displacement path disappears
structurally and this rule becomes moot.

## 8. Invalidation model

| Threat | Mechanism | Nature |
|---|---|---|
| **Stale lattice broadcast** (old epoch's exit) | Chain-extension dominance: transitions have no CSV, exits wait Δ; any holder of a newer `T` extends the chain and voids the stale lattice | Trustless race the honest side structurally wins |
| **Commitment withholding / forks** | Chained seal dependency + co-signed commitments: a missing seal stalls the pool visibly and trips auto-exit; a forked `h_k` carries a contradictory signature | Detection + liveness fallback |
| **Spurious current-state exit broadcast** (griefing — A17) | Unbumped roots cannot confirm (TRUC); a bumped root is met with a conforming eviction pulse: the broadcaster's slot is paid out in full and the pool continues (§7.5) | Priced, self-limiting; defense folds into heartbeat cadence |
| **Live-Operator exit denial** (A16) | Displacing a *noticed* exit without the payout is an unlawful eviction — non-final, unsealable, enclave-unsignable, bond-slashable; stalling instead is a visible liveness fault → auto-exit | Exit-or-payout guarantee (§7.5) |
| **Fresh colluding theft** (Operator + all of `M_k`, resurrected keys) | **Not a race** — the theft tx has no CSV and beats the Δ-delayed lattice. Defense is the equivocation proof: the victim holds `L_k` (a `P_k` signature) and the theft tx is a *second* `P_k` signature on a conflicting spend → dispute halt + bond slash where bonded (§9) | Economic deterrent |

Because the equivocation proof requires the victim to *hold* the lattice, **local
retention of `(lattice branch, root(L_k), A_k, h_k, σ_k, and any filed exit notices)`
per epoch is a security-critical protocol invariant**, not a convenience. A member (or
their watchtower) that discards these has no fraud proof — though because the lattice
is non-custodial, *any* surviving copy (the relay mesh, the seal set, an archival
watchtower) lets anyone reconstruct and broadcast on the victim's behalf, so the data
only needs to exist *somewhere*, not necessarily with the victim. The seal set's
data-availability receipt (§7.1 step 6) makes it the custodian of last resort.

**The contest window Δ is also a dispute window.** No published evidence can freeze
`U_k` on-chain — there is no covenant to freeze it. But a standardized,
machine-checkable evidence bundle (`A_j` plus the contradicting `L_k`, a forked `h_k`,
or a sealed exit notice plus a payout-less displacement) does two things during Δ: it
makes the referees *earmark* the bond where one exists (blocking its expiry-return
while a live contradiction stands), and it flips every conforming client's
accept-policy to *refuse new pulses* on that pool. Since the next pulse is invalid
until sealed and honest sealers will not seal a disputed tip, a credible dispute
**halts state progression** — the closest no-covenant analogue to a freeze. It stops
the attacker finding fresh victims; it does not, by itself, claw back the specific
contested coins.

## 8a. Recourse: when the count doesn't check out

This is the user-facing companion to §8. The governing fact, stated sharply because
every line depends on it:

> A user can only ever broadcast a lattice that was **actually signed**. No honest
> "correct" lattice exists unless it was ceremonially produced. So *recovering your
> position* is possible only by falling back to a previously-signed, still-spendable
> lattice — or, after revision 2, by the payout a conforming eviction owes you. If
> neither exists, the ceiling is **economic compensation from the bond**, and the
> floor is **unbacked loss**.

### Failure modes and where each lands

| Failure | What it is | Tag (determining condition) |
|---|---|---|
| **Wrong amount** | your slot pays less than your balance | Active signer: **POSITION-RECOVERABLE** (veto at the gate). Passive: **COMPENSATION-ONLY** via `A_k` contradiction |
| **Missing slot** | you are in `A_k` but absent from `L_k` (= wrong amount, slot 0) | Same as wrong amount; the fraud proof is the cleanest (Merkle inclusion in `A_k` vs absence in `root(L_k)`); doubles as a conservation alarm |
| **Conservation failure — malicious** | `Σ(slots) > value(U_k)`, a theft structured as a race among victims | **LIVENESS-HALT** (§7.1a predicate; the inflated `A_k` also contradicts `value(U_k)`) → compensation residue |
| **Conservation failure — buggy-honest** | ceremony bug; `A_k` matches the buggy lattice, so *no lie, no conflicting signature* | Without §7.1a: **UNBACKED-LOSS** (no slashable evidence). With §7.1a: **LIVENESS-HALT** at `k−1`. This is why §7.1a is a first-class rule |
| **Missing / invalid branch** | signatures don't verify, or you never received a branch | Invalid sig, active: **POSITION-RECOVERABLE** (veto). Passive: **COMPENSATION-ONLY** if `A_k`+inclusion retained or mesh/seal-recoverable; **UNBACKED** only if the data is *globally* lost |
| **Unlawful eviction** | your *noticed* exit was displaced by a transition that did not pay you (§7.5) | **LIVENESS-HALT** (sealers refuse; conforming clients treat the pool as disputed) + **COMPENSATION** on the objective notice/displacement pair where bonded |
| **Stale-but-correct** | your `L_k` is correct but `U_k` was already consumed by a newer (bad) transition | With §7.5 and an intact enforcement stack: the displacement owed you a payout — **POSITION-RECOVERABLE** in value. Against a fully colluding stack: **COMPENSATION-ONLY** (the revision-1 analysis below still governs that floor) |
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
3. **Exit-or-payout via notice (§7.5).** File a sealed exit notice and broadcast. Either
   the lattice matures (exit) or a conforming eviction pays your full balance on-chain
   immediately. A payout-less displacement is objective evidence *and* a §8 dispute that
   halts the pool. This rung is what makes rung 4's race analysis a floor rather than
   the everyday case.
4. **Detect-before-consumed exit via the last-good epoch.** Hold a correct `L_{k−1}`,
   detect the bad pulse, broadcast `L_{k−1}` before the bad transition confirms.
   **Honest verdict: mechanically, this loses the race to an active thief and works
   only against a dark or stalled Operator** (see below). It is a freeze remedy, not a
   theft defense.
5. **Equivocation fraud proof → bond compensation.** Two conflicting `P_k` signatures,
   an `A_j` contradicted by a later lattice with no member-signed debit, or a sealed
   notice displaced without payout. The federation pays victims — **money, not
   position**, capped at the bond.
6. **Residual unbacked loss.** What actually falls here: buggy-honest conservation
   *absent rule §7.1a*; a branch whose data is *globally* lost; sub-dust balances
   (structurally no exit); the over-the-bond portion of any theft (`loss > bond`); and
   an unbonded deployment whose entire enforcement stack (threshold, sealers, clients)
   is simultaneously compromised.

### The mechanical race, analyzed honestly

Your exit spends `<Δ> OP_CSV ... <P_k> OP_CHECKSIG`: the relative timelock means the
lattice root cannot be mined until **Δ blocks after `U_k` confirmed**. The attacker's
consuming transition carries **no CSV** (`nSequence` final, by design — §6, §8): it is
spendable immediately and confirms in the next block. So a colluding Operator consumes
`U_k` roughly Δ blocks before your exit is even valid, and your correct `L_k` becomes
un-broadcastable (its input is spent). Chain-extension dominance is a race the honest
side wins **only when the honest side holds the newer transition**; when the *thief*
holds the newer (bad) state, the same Δ that gives honest holders a contest window is a
head start handed to the attacker.

This mechanical asymmetry is permanent — it is what A5 exists to prevent anyone from
forgetting — and revision 2 does not repeal it; it **re-prices it**. Under §7.5 the
displacement that wins the race is conforming only if it pays you, so "losing the
race" and "losing the funds" are decoupled whenever the enforcement stack (enclave
policy, seal set, client conformance, optional bond) holds. The bare race analysis
above is the floor you land on when that entire stack fails simultaneously — and the
dark/stalled-Operator case (nobody broadcasts a consuming transition; your `L_k`
matures unopposed) remains the case pure mechanics handles with no trust at all.

> **Bottom line.** For an active, online party the gate is a true veto. For a member
> *denied exit* by a live Operator, recourse is **exit-or-payout** (§7.5), degrading to
> bonded compensation only under full-stack compromise. For a passive member *shorted*
> by an actively-colluding Operator, recourse terminates at **bonded compensation, not
> coin recovery** (this is the *amount* security model of §13.1) — because you cannot
> broadcast a correct lattice that was never signed. That is the structural price of
> pooling funds in one shared UTXO without a covenant; the protocol's job is to shrink
> the set of cases that reach it (rules §7.1a and §7.5, the full-table attestation,
> seal-set archival, TVL-tracking bond) and to make the compensation actually cover
> the loss.

## 9. Bond and enforcement layers

**Critical separation: the exit never touches the emulator.** The lattice is plain
pre-signed Bitcoin transactions. An emulator shutdown — including the Operator killing
its own attested execution environment — is a **freeze, not a theft**: watchtowers trip
on the missed seal or heartbeat commitment and every member exits on L1 with zero
Operator involvement. What remains to defend is the *amount* a passive member is owed
when an active set colludes (§8), and the *payout leg* of §7.5. There are two ways to
defend them; the simpler one is primary.

### Primary model: a FROST-in-TEE operator (no capital bond)

Take the Operator to be a **permissionless FROST federation running in TEEs** — anyone can
peer in via threshold resharing, and each node's signing share lives in an attested
enclave. The enclave runs the pulse-validity policy and **refuses to contribute its
FROST share** to any pulse that violates it:

- incorrect passive carry-forward or conservation (the §7.1 gate and §7.1a predicate);
- a pulse proposed before the previous epoch's seal `σ_k` exists (§7.1 step 6);
- **a displacement of a sealed exit notice that omits the member's full payout**
  (§7.5).

So a lattice that shorts a passive member — or an unlawful eviction — **cannot be
signed at all**: strictly stronger than "it can be signed but you are compensated," and
it needs **no TVL-sized capital and no separate referee quorum**. In this model the
continuity attestation `A_k` is **threshold-signed** by the federation (promoted from
the revision-1 optional hardening): lying about a passive balance requires colluding
`t` independently-operated enclaves, twice over (attestation *and* lattice). The
protocol then reduces to what it should be: a **framework that generates the recurrent
exit lattices in the background**, as part of the federation's normal per-pulse
signing — members and watchtowers receive their branch automatically, with no bond
ceremony.

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

### The seal set

The epoch seal (§7.1 step 6) needs issuers. Requirements and honest costs:

- **Duties:** recompute the §7.1a predicate; verify possession of the full artifact
  bundle (the seal *is* a data-availability receipt); countersign `h_k`; seal exit
  notices (§7.5); refuse to seal a disputed tip (§8). Nothing else — sealers are never
  in the exit path and hold no funds.
- **Default composition: the referee federation of the bonded backstop below,
  Operator excluded** — the same conflict rule as the slashing quorum (§9.1). The jobs
  compose naturally: referees need the artifacts to adjudicate anyway, and holding the
  bundle *at seal time* makes later adjudication evidence-complete rather than
  dependent on victims' retention.
- **Honest cost — a new liveness coupling.** Revision 1 gated pulses on on-chain
  inclusion (slow but dependency-free); revision 2 gates them on a k-of-n that must be
  online per pulse. A stalled seal set halts progress — but that failure is *visible*
  and lands in the existing fallback (auto-exit on the last sealed epoch), i.e. it is
  a freeze, never a theft. Size `n` generously and diversely.
- **Self-sealed mode.** A deployment unwilling to take that dependency may let the
  Operator threshold itself issue seals (in the primary model: the enclaves attest the
  predicate and DA before signing anyway). This preserves throughput and removes the
  third party at the cost of **same-trust-domain data availability** — the entity that
  produces the state also receipts its publication. Acceptable for a FROST federation
  with genuinely diverse membership; not recommended for a single-entity Operator.

### Optional economic backstop: the bonded federation

For deployments that prefer an economic guarantee over hardware trust — or that want a
*compensation* backstop against a TEE-threshold break — the original bonded model
follows. It is **optional**, not load-bearing; its enforcement is independent of the
Operator's infrastructure:

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
  - two valid signatures under the same epoch key `P_k` on conflicting spends;
  - a continuity attestation `A_j` contradicted by a later published lattice paying a
    member less, with no member-signed debit in between; or
  - a sealed exit notice `X_k(m)` displaced by a transition lacking `m`'s payout
    (§7.5).
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
    pool (§9) should verify the *referee* bonds are live and sized — and, since revision
    2, that the **seal set** is live — not only the Operator's bond.
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
  quorum is a conflict of interest and is forbidden. The same exclusion applies to the
  **sealing quorum** (§9, "The seal set").

**Blast radius.** Even if the *entire* referee/TEE layer is compromised, the worst case is
**the bond is stolen or a valid claim is denied — the deterrent evaporates** — but the
**pool funds are untouched**, because the exit lattices are pre-signed and independent of
the bond apparatus: members still sweep their last-good amount. Referee compromise degrades
the *amount-deterrent*, never the *exit*. As everywhere else, this hardens the trusted
layer; only a covenant (§12.2) converts amount-safety into cryptographic self-custody.

## 10. Attack analysis appendix

Seventeen adversarial findings shaped this spec — A1–A13 from the protocol red-team,
A14–A15 from the recourse analysis (§8a), A16–A17 from the revision-2 current-state
exit analysis (§7.5). Severity: **CRITICAL** (breaks the safety claim), **HIGH** (loses
funds or bricks exit under a realistic adversary), **MED** (griefing/liveness/cost).

| # | Attack | Severity | Resolution in this spec |
|---|---|---|---|
| A1 | **Operator-only heartbeat re-anchor voids all pre-signed exits** — new outpoint ⇒ txid change ⇒ every SIGHASH_ALL signature dead; re-signing needs deleted keys | CRITICAL | Heartbeat is a full cooperative on-chain pulse with complete lattice rebuild (§7.2). No cheap re-anchor construct exists or may be exposed (floating claims under GSR would relax this — §12.2) |
| A2 | **Silent-majority gap** — lattice signers are only Operator + `M_k`; nothing structurally forces correct passive slots; for 1-party pulses this degrades to "trust the Operator" | CRITICAL | Continuity attestation `A_k` over the *full* table each epoch (threshold-signed in the primary model, §9) + carry-forward verification by every transacting party (§7.1 step 4b) + cross-epoch fraud proof slashable on the bond where bonded (§9) |
| A3 | **"Publish the lattice" is unenforceable** — Operator signs last, can withhold mesh publication or the commitment selectively | HIGH | "No lattice *in my hands*, no pulse" (local possession gate, §7.1 step 4e); the epoch seal is a k-of-n **data-availability receipt** (§7.1 step 6); a withheld seal or batch commitment is a visible stall that trips auto-exit (§7.3) |
| A4 | **MuSig2 N-of-N brittleness** — one signer aborts mid-ceremony ⇒ epoch key can never sign again ⇒ if the lattice were incomplete, the exit leaf is permanently unspendable | HIGH | Lattice signed *before* the transition (§7.1 order); abort ⇒ pulse abandoned on still-protected `U_k`; passive members excluded from the aggregate (minimal signer set) |
| A5 | **Theft beats the race** — a colluding theft tx has no CSV; the lattice waits Δ; the defender is structurally slower | HIGH | Stated honestly: chain-extension dominance only kills *stale* lattices; anti-theft is the equivocation proof + enforcement stack (§8, §9), not a race. §7.5 re-prices the race for the *denial* case but does not repeal the mechanics (§8a) |
| A6 | **Anchor pinning on shared lattice nodes** — occupying a shared internal node's anchor grief-blocks every member exiting through it | HIGH | One **keyless P2A anchor per node** — anyone can bump, and TRUC **sibling eviction** makes an occupying low-fee child replaceable; per-claimant anchors at slot level only (per-claimant anchors on every node would be O(N log N) outputs). Claimant attribution via sealed exit notices (§7.5), not anchor provenance. Heartbeat-SLA compensation where bonded |
| A7 | **Partial-lattice broadcast griefing** — broadcasting the root but only some branches leaves other members' subtrees unwalked | MED | Monotonically harmless: the tree is fully pre-signed; any member (or watchtower) pushes their own branch with CPFP; delays only. The *full current-root* case is **not** harmless and is A17 |
| A8 | **"Deletion attestations" are unfalsifiable** — you cannot prove a key was deleted | HIGH | Deletion demoted to hygiene; the trust anchor is equivocation detection, which requires **mandatory artifact retention** (§8); a resurrected key that signs anything new creates the fraud proof |
| A9 | **Renew-sweep races in-flight exits** — sweep maturity near `renew` can consume `U_k` under a maturing lattice | HIGH | Compiler-enforced ordering invariant `sweepDelay ≥ Δ + margin` creating a lattice-exclusive window; `margin` includes virtual-chain depth and stampede fees (§7.4) |
| A10 | **Bond circularity & sizing** — emulated slashing dies with the emulator; fixed bonds get out-run by TVL | HIGH | Judicial federation bond, evidence-based, emulator-independent (§9); TVL-tracking sizing with client-side refusal; heartbeat cadence caps at-risk-per-epoch ≤ bond |
| A11 | **O(N) lattice re-sign cascade** — SIGHASH_ALL invalidates all descendants on any root change; "incremental subtree reuse" does not survive the txid cascade | MED→HIGH | Costed honestly (§7.1 step 3): O(N) compute for 2–3 parties, O(1) interactivity; two-tier hot-band sharding as the scaling valve; GSR floating-claim constructions named as the real fix (§12.2) |
| A12 | **Depositor verification is not enough** — verifying your slot at deposit does not protect later epochs you never sign | MED | Deposit completes only with branch + attestation + coverage checks in hand; continued protection explicitly requires a watchtower (§5, §8) |
| A13 | **Off-chain `h_k` equivocation** — Operator shows different chains to different parties while committing one hash on-chain | MED | `h_k` must be co-signed by Operator + threshold of `M_k`, then sealed by the k-of-n seal set (§7.1 step 6): a fork necessarily carries contradictory signatures |
| A14 | **Buggy-honest conservation failure** — a ceremony bug makes `Σ(slots) ≠ value(U_k)` while `A_k` matches the buggy lattice, so there is no lie and no slashable evidence → silent unbacked loss | HIGH | Public finality predicate (§7.1a): conservation + consistency are recomputable from committed data and are a precondition of the seal; failure makes pulse `k` non-final and forces auto-exit on `k−1` |
| A15 | **Sub-dust no-exit** — balances below the 330-sat floor sit in a cooperative-only dust slot with no unilateral exit | MED | Named as a permanent, bounded recourse gap (§8a, §12.1 item 6); mitigated by client below-floor warnings and attesting the dust aggregate so over-debit is compensation-provable |
| A16 | **Live-Operator exit denial** — chain-extension displaces a *legitimate current-state* exit; each displacement carries balances forward correctly, so under revision 1 denial produced **no slashable evidence** (no equivocation, clean attestation); composes with expiry into theft-at-`renew` | HIGH (CRITICAL near `renew` absent §7.5) | Exit notices + **eviction-with-payout** (§7.5): displacing a noticed exit without the full on-chain payout is non-final, unsealable, enclave-unsignable, and bond-slashable; stalling instead is a visible fault → pool-wide auto-exit. Guarantee becomes **exit-or-payout** |
| A17 | **Current-root broadcast griefing** — the fully pre-signed, mesh-published root is broadcastable by anyone; a fee-bumped root forces mass exit (≈N× fee leverage) or a defensive displacement costing an on-chain tx + O(N) re-sign; retries ≈ free (supersedes the full-root case of A7, which revision 1 graded "harmless") | HIGH | §7.5 repricing: unbumped roots are inert (TRUC zero-fee parent); a bumped root is answered by a conforming eviction pulse — the broadcaster is **paid out in full and removed at their own request**; defense folds into heartbeat cadence (§7.2); third-party bumps gift the member a fast exit |

## 11. Compiler surface (future work — gated zones)

Changes touch `src/parser/grammar.pest`, `src/models/mod.rs`, and
`src/compiler/mod.rs`, all of which are supervised zones; this section is a proposal
only, phrased against the **current** surface (grouped ABI, author-written `tapscript`
leaves; the former `options { ... }` block and `serverVariant` shape no longer exist).

- **Leaf surface — no new grammar production.** Reserve a builtin identifier `pulse`
  (resolved like `server`/`emulator`), legal only inside `tapscript` leaves:

  ```solidity
  contract Pool(int exit, int renew, int sweepDelay /*, ... */) {
      // covenant functions (cooperative path, Operator-emulated) ...

      function unilateral(signature pulseSig) tapscript {
          require(older(exit));            // Δ, the contest window
          require(checkSig(pulseSig, pulse));
      }
  }
  ```

  emitting

  ```
  <exit> OP_CHECKSEQUENCEVERIFY OP_DROP <PULSE_KEY> <pulseSig> OP_CHECKSIG
  ```

  `<PULSE_KEY>` is a placeholder in the emitted ASM (same convention as
  `<SERVER_KEY>`), bound per epoch by the SDK ceremony. Presence of `pulse` marks the
  function group `recurrent` in the ABI; `pulseSig` is emitted as `injected` witness
  (it is supplied by the pre-signed lattice, never by an end-user wallet).

- **ABI**: the recurrent leaf entry carries `"recurrent": true` plus a `lattice`
  template object: slot script (`SingleSig(<memberPk>)` + slot CSV — the existing
  pattern), tree arity, anchor policy (keyless P2A per node; per-claimant anchors at
  slot level), dust policy (330-sat floor, cooperative-only dust slot), the
  continuity-attestation format, the **epoch-seal format**, the **exit-notice format**
  (§7.5), the dispute-evidence bundle formats (§13.4 — fixing these here is what keeps
  conforming clients from splitting on what counts as a valid halt trigger), and a
  bond reference for client-side coverage checks.

- **Timelock invariant**: the validator rejects configurations where an
  Operator-sweep leaf (the `after(renew)` + `older(sweepDelay)` + operator-key
  pattern) could mature inside the exit window (`sweepDelay < exit + margin`), per
  §7.4; the margin inputs (virtual-chain-depth cap, stampede buffer) live in the ABI
  lattice template.

- **Explicitly absent**: any "operator-only re-anchor" construct (A1), and any
  displacement path that skips the §7.5 payout.

Everything else — ceremony ordering, artifact retention, watchtower triggers, TRUC
packaging, seal-set membership, coverage refusal — is SDK/ceremony policy, not
compiler surface.

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
   retention (§8). The primary model threshold-signs the attestation (§9); a
   single-entity deployment keeps k-of-n multi-Operator co-signing of `A_k` as its
   hardening — lying about a passive balance then requires collusion across
   independent parties, not just one.
2. **Heartbeats stay quorum-gated ceremonies.** Re-anchoring invalidates SIGHASH_ALL
   signatures, so every heartbeat is a full pulse. Discipline: heartbeat cadence is a
   protocol parameter enforced client-side; pools that cannot sustain their cadence
   should not grow.
3. **The defender stays slower than the thief.** The theft path has no CSV; the
   lattice waits Δ. Only the enforcement stack deters collusion: if `theft value >
   bond`, collusion of the Operator + all transacting parties of an epoch is
   profitable in the bonded model. Discipline: heartbeat cadence and client-side
   coverage checks cap at-risk-per-epoch ≤ bond — wallets refuse pulses that would
   breach it (§9).
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
7. **Exit-or-payout is enforced, not consensus.** The payout leg of §7.5 rests on the
   same trusted layer as the amount model (enclave policy, seal set, client
   conformance, optional bond). Under full-stack compromise the A16 racing gap
   reopens — and composes with the expiry sweep. Discipline: sealed notices (the
   evidence outlives the stack), client dispute-halt on any unlawful eviction, and the
   `renew`-adjacent auto-exit margin (§7.4). Under GSR (item 3 below) the displacement
   path disappears structurally and the rule becomes moot.

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
3. **The theft path disappears structurally** (closes the A5 asymmetry — and with it
   A16: there is no displacement to constrain when there is nothing the Operator and
   the transacting parties can co-sign that pays anywhere other than the committed
   distribution).
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
| **Exit mechanism** (can I get *out*?) | **1-of-N, plus exit-or-payout** | The lattice is fully pre-signed and non-custodial; *any one* honest data-holder in `{you, your watchtowers, the seal set, mesh archivers}` can broadcast it. You yourself suffice (1-of-1). Against a **dark** Operator, exit always completes on pure mechanics. Against a **live racing** Operator, §7.5 makes the only conforming displacement a full payout — exit-or-payout — with the honest caveat that the *payout leg* is enforced by the trusted layer (next row), not by consensus. |
| **Exit amount** (is the *number* in my slot right?) | **Enforced — not a clean 1-of-N** | The set whose honesty protects a passive member's balance in a pulse is `{Operator ∪ M_k}` — the Operator plus whoever is transacting. One honest member of that set refuses the bad pulse at the gate (§7.1 step 4b). But that set **excludes the victim** and can be **as small as two** (Operator + one transacting party — and if both collude, the honest count in it is zero). Below "1 honest in that set," safety degrades to the enforcement stack: enclave-threshold refusal in the primary model, *bonded compensation* in the backstop (§9) — an enforced layer, not a cryptographic one. |

**Why the amount model is weaker than the systems PULSE resembles.** In a statechain or
a coinpool, every signer is checking *their own* balance and updates are N-of-N, so any
one refusal blocks — a true 1-of-N where the honest party is *defending their own funds*.
In Arkade, a VTXO owner is 1-of-1 over *their own* coins. In PULSE, **the victim is not a
required signer of the transition that can rob them**: the honest party who could save a
passive member is a *disinterested third party* (some other transacting party running
the §7.1 step 4b carry-forward check), not the victim. That carry-forward check is
therefore **policy-enforced, not incentive-compatible** — a transacting party has no
economic stake in a stranger's passive slot, so the check holds only because conforming
software performs it, and it is not a Nash equilibrium. (The primary model turns this
policy into something an honest enclave threshold *enforces* — §9 — which is the point
of that model.) This is the honest game-theoretic floor, and it is why "1-of-N" must
always be qualified as *"1-of-N for the mechanism, enforced for the amount."* Revision
2's §7.5 closes the mechanism-*denial* gap; it deliberately does not touch this amount
model.

### 13.2 The trilemma

The amount model is not weak by oversight; it is the corner the design chose. You cannot
have all three of:

- **(a) non-interactive passive members** — they sign nothing while idle (the entire
  open-membership selling point);
- **(b) no covenant** — the working assumption (§12);
- **(c) trustless safety of a passive member's *amount*** — cryptographic, not bonded.

PULSE takes **(a) + (b)** and pays by relaxing **(c)** to an enforced (enclave or
bonded) guarantee. A real covenant (the GSR annex, §12.2) buys **(a) + (c)** by
dropping (b). Forcing the victim to co-sign every pulse that touches the pool buys
**(b) + (c)** by dropping (a) — but that is just a coinpool, and it destroys the
passive/open-membership property. The trilemma *is* the design, stated honestly; it is
not a defect to be patched.

### 13.3 Dialectical summary

| Thesis | Antithesis | Synthesis |
|---|---|---|
| Pre-signed lattices give passive members a standing unilateral exit with no covenant | The lattice is signed only by `{Operator + transacting parties}`, never the victim — a unilateral exit to an amount *someone else wrote* | **Self-custody of the exit mechanism, delegated (enforced) custody of the exit amount** |
| Recurrent pulses keep the exit fresh | Recurrence puts the Operator in every pulse — perpetual operator dependency | Liveness of *progress* is operator-gated; liveness of *exit* is operator-free (you hold the last lattice), and displacement of an exit owes you a payout (§7.5) |
| Enforcement stack + equivocation proof deters theft | Economic/enclave security ≠ cryptographic; above the bond theft is +EV; and the preventing check has no incentive behind it | A cryptographically-enforced *mechanism* around an institutionally-enforced *amount* — a hybrid, not trustless |

### 13.4 Can anyone halt epoch creation?

Four vectors — three bounded, one intentional:

1. **The Operator can halt *all* epoch creation unilaterally** (it is a mandatory signer
   of every pulse). This is a real censorship/liveness power, but it is **bounded to
   "freeze + force mass exit," not theft**: a frozen pool just means everyone leaves on
   the last lattice. And since revision 2 it is **pool-wide or nothing**: the Operator
   cannot *selectively* suppress one member's exit — displacement without payout is
   unlawful eviction (§7.5), so targeted censorship requires stalling the whole pool,
   which is visible and trips auto-exit. It is the same shape as Arkade's normal
   operator-liveness assumption, with a wider blast radius.
2. **The seal set can halt epoch creation by refusing seals** (revision 2's new
   liveness coupling — §9). Same bound: visible stall, freeze-not-theft, auto-exit on
   the last sealed epoch. Deployments that reject this dependency run self-sealed
   (§7.1 step 6) and give up third-party data-availability receipts.
3. **Any single transacting party can halt *their own* pulse** by aborting the MuSig2
   round (N-of-N: one missing nonce or partial stalls it — A4). This blocks only pulses
   that party is in; it cannot censor others transacting with the Operator. Bounded
   griefing.
4. **Anyone with *objective* fraud evidence can halt epoch creation via the dispute
   artifact** (§8a) — this is intentional (the social freeze). Critical caveat: conforming
   clients must halt only on **machine-checkable** evidence; halting on unverified
   disputes turns "cry wolf" into a free pool-wide DoS. The admissible evidence is the
   three types defined in §9 (two conflicting `P_k` signatures; an `A_j` contradicted by
   a later lattice; a sealed exit notice displaced without payout) packaged as the §8a
   bundle; their exact wire serialization is fixed in the ABI (§11) — two
   implementations that disagree on the format would split the social layer, so the
   format must be fixed there, not left to convention.

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
parameters (§9, §12.1 item 1) are sized against the same `k`. Keep the **operator
threshold, the seal set, and the referee set pairwise independent** (§9, §9.1) so their
compromises do not correlate.

**Realizing the federated Operator.** Its canonical realization is the **FROST-in-TEE
primary model of §9**: a threshold-attested signer that refuses to produce its share for an
invalid pulse, so a passive-member-shorting lattice — or an unlawful eviction (§7.5) —
cannot be signed at all; which also turns A2's policy-but-not-incentive-compatible client
check into something an honest threshold enforces, and raises key-resurrection (A8) to
threshold collusion. A non-collusive **2PC-MPC** network (user + a
hundreds-to-thousands-node MPC with identifiable abort, producing Schnorr/Taproot-
compatible signatures) is an alternative instantiation of the same role, and its
identifiable-abort slashing can subsume the *optional* referee federation (§9). Both sit
on the **cooperative path only** — the exit stays pre-signed and signer-independent — and
neither makes the victim a signer, so neither escapes the trilemma (§13.2): amount trust
moves from "one Operator" to "the threshold," quantitatively far stronger but still
committee/enclave trust, not cryptographic self-custody.

**The threshold benefit is only as real as the operator set's Sybil resistance.**
"Collusion now requires breaking the threshold" holds *only if the nodes (or enclaves) are
genuinely independent* — and that independence **cannot be proven cryptographically**; it
is the same unprovable real-world property as key deletion (A8) and federation
non-collusion (§9). It rests on economics and social structure: diverse membership, staking
or fidelity bonds sized **above the stealable value** (the analogue of `requiredCoverage`,
§12.1 item 3), identifiable abort (which punishes a *defector* but not a *colluding
majority*), and genuine distribution — so that breaking the threshold means compromising
`t` *independent* operators (or their enclaves), not one entity's. If those fail — the
"nodes" are one entity behind a façade, or a staked majority colludes — the threshold
collapses back to the single-Operator-collusion case of §8, **but no worse**: exit
stays signer-independent and the model already assumes that collusion is possible, so a fake
threshold degrades PULSE to its existing floor, never beneath it. Wallets should therefore
gate the "threshold-secured" label on a measured distribution bound (e.g. a
Nakamoto-coefficient floor), the same way they refuse an under-bonded pool (§9) — the
benefit is quantitative, never a cryptographic guarantee of independence.

### 13.6 Feasibility: the lattice is an Arkade VTXO tree

The "exit lattice" is **structurally an Arkade VTXO tree**, which is deployed and
covenant-free — so the construction is buildable on Bitcoin today with no soft fork:

- **The tree:** a Taproot root spending the shared UTXO, internal branches splitting
  value, `SingleSig + CSV` leaves — signed N-of-N via MuSig2 with the Operator included.
  Arkade is itself covenant-free — its VTXO trees are pre-signed and operator-cosigned
  with no covenant opcode — establishing that all-of-all pre-signing emulates a covenant
  with **no introspection opcode and no fork**. PULSE's epoch-key-then-delete is the same
  sign-once-then-delete key technique (with the unprovable-deletion caveat, A8).
- **The fee plumbing:** keyless per-node anchors via **P2A** (standard relay since
  Bitcoin Core 28.0), **TRUC/v3** relay with sibling eviction, and ephemeral anchors —
  all merged. §7.1 step 3's anchor policy is real, not aspirational. Implementer
  caveat: a P2A-bearing lattice transaction only propagates across peers on Core ≥28.0
  (or equivalent relay policy), and a lattice that does not propagate is a failed
  exit — so wallets should broadcast through P2A-aware relay rather than assume
  universal support.
- **The off-chain artifacts:** exit notices and epoch seals (§7.5, §7.1 step 6) are
  plain signed messages with no consensus footprint — they constrain *conforming
  software and federations*, not Bitcoin.
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

> PULSE has **two security models, not one.** The **exit mechanism is 1-of-N with
> exit-or-payout**, and emulator-independent — pure pre-signed L1 transactions, any one
> honest data-holder can broadcast, Operator or emulator shutdown means *freeze, never
> theft* — and, since revision 2, a live Operator can displace an in-flight exit **only
> by paying the member in full** (§7.5), so exit can be stalled by no one and every
> denial leaves objective evidence. The **exit amount is enforced, not trustless**: a
> passive member's balance is protected only by the honesty of `{Operator ∪ the
> transacting parties}` of a pulse — a set that excludes the victim and can be as small
> as two. The **primary model** closes that set with a **FROST-in-TEE Operator** (§9)
> whose attested enclaves refuse to sign an invalid pulse or an unlawful eviction, so
> the bad lattice cannot be produced — hardware-attestation trust, no capital; an
> **optional bond** adds an economic *compensation* backstop for those who prefer it to
> hardware trust; a k-of-n **seal set** receipts data availability per pulse and keeps
> finality off the block clock. Either way the amount — and the payout leg of
> exit-or-payout — rests on enclave-threshold or committee trust, not cryptographic
> self-custody — the **trilemma** (§13.2): with non-interactive passive members and no
> covenant, amount-safety *must* be enforced by a trusted layer rather than by
> consensus. Covenant-grade trustlessness of the amount is reachable only through the
> GSR annex (§12.2); absent any fork, this **trustless-mechanism / enforced-amount**
> model is the end state, and the design is engineered to be livable as exactly that.
