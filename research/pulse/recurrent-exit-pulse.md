# PULSE — Recurrent Unilateral Exit for Emulator-Enforced Pools

**Pooled Unilateral-exit via Lattice State Epochs. Revision 2.4.**

A protocol for giving open-membership pool contracts on Arkade a *standing* unilateral
exit, enforced by recurrent state updates between the transacting parties. This document
is a design specification: it defines the protocol lifecycle, the trust model, the
attack analysis — thirty-one adversarial findings (A1–A31), detailed in §10 — that shaped
it, and the compiler surface that would standardize it. It proposes no code changes; the
compiler-facing sections are future work.

Cross-references: [`options.md`](../../examples/options/options.md) (the two-tapleaf
model this design generalizes), [`bonds.md`](../../examples/bonds/bonds.md) (pool
covenants and today's exit asymmetry).

## Table of contents

- [0. Amendment log](#0-amendment-log)
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
  - [7.4a Anchor age: the second ordering invariant](#74a-anchor-age-the-second-ordering-invariant)
  - [7.5 Exit notice and eviction-with-payout (D5)](#75-exit-notice-and-eviction-with-payout-d5)
  - [7.6 Own-balance enforcement without a signing share](#76-own-balance-enforcement-without-a-signing-share)
- [8. Invalidation model](#8-invalidation-model)
  - [What the stale-lattice race requires](#what-the-stale-lattice-race-requires)
  - [Miners: consensus versus relay policy](#miners-consensus-versus-relay-policy)
- [8a. Recourse: when the count doesn't check out](#8a-recourse-when-the-count-doesnt-check-out)
  - [Failure modes and where each lands](#failure-modes-and-where-each-lands)
  - [The recourse ladder (strongest → weakest)](#the-recourse-ladder-strongest--weakest)
  - [The mechanical race, analyzed honestly](#the-mechanical-race-analyzed-honestly)
- [9. Bond and enforcement layers](#9-bond-and-enforcement-layers)
  - [Primary model: a FROST-in-TEE operator (no capital bond)](#primary-model-a-frost-in-tee-operator-no-capital-bond)
  - [The seal set](#the-seal-set)
  - [Optional economic backstop: the bonded federation](#optional-economic-backstop-the-bonded-federation)
  - [9.1 Hardening the referees (TEE-constrained, bonded, conflict-free)](#91-hardening-the-referees-tee-constrained-bonded-conflict-free)
  - [9.2 Self-enforcing equivocation bonds (EOTS with pre-committed nonces)](#92-self-enforcing-equivocation-bonds-eots-with-pre-committed-nonces)
  - [9.3 Distributed-systems hardening (token-free)](#93-distributed-systems-hardening-token-free)
  - [9.4 Capital requirements, quantified](#94-capital-requirements-quantified)
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

## 0. Amendment log

**Revision 2** — changes relative to the revision-1 draft (PR #45,
`docs/recurrent-exit-pulse.md`):

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

**Revision 2.1** — follow-up on the same branch:

10. **§9.2 — self-enforcing equivocation bonds.** Extractable one-time signatures
    (EOTS, the Babylon finality-provider primitive) with pre-committed per-epoch
    nonces make any double-signed attestation, seal, or commitment leak the signer's
    key, letting anyone execute a pre-signed burn of a plain-BTC bond — judge-free,
    token-free, no fork. This **corrects the §9 "rejected alternative"**: the
    nonce-reuse rejection is valid for *transaction* signatures only, not for
    protocol artifacts whose validity conforming software judges.
11. **§9.3 — distributed-systems hardening**, all token-free: the SUNDR
    fork-linearizability ceiling as the design's theoretical frame, a
    witness-cosigned transparency log for the commitment chain (1-of-N split-view
    detection), proactive FROST share refresh on the heartbeat cadence, and
    erasure-coded data availability with sampling.
12. **§9.4 — capital requirements quantified**, including an honest correction of
    revision 2's `requiredCoverage` claim: heartbeat cadence does **not** bound the
    lie-once drain (only the signing threshold does — consensus checks nothing but
    signatures). Sizing is now per adversary class, with a worked example,
    per-identity amortization rules, a fee-floor formula, and a renewal-ladder
    liquidity schedule.
13. **Six new findings (A18–A23)** red-teaming the new machinery: accidental
    self-slash, nonce-chain withholding, burn-tx pinning, DA sampling eclipse,
    reshare capture, and correlated per-identity bonds.
14. Evidence lists (§8, §13.4), the GSR annex (§12.2), §13.1, and the trust
    statement updated for the self-enforcing layer; new vocabulary (`EOTS`, nonce
    chain, `B_eq`, `w_max`).

**Revision 2.2** — corrections arising from an independent formal-verification pass
over revision 2.1 (TLA+ models of the ceremony and the timed exit race; Lean proofs of
the §9.2 algebra). Those artifacts live alongside this document in
[`formal/`](./formal/), with their assumptions, bounds and expected results recorded in
[`formal/VERIFICATION-2.2.md`](./formal/VERIFICATION-2.2.md); `formal/verify.py`
re-runs them. They are research artifacts and change no compiler behaviour. The
corrections they produced:

15. **A24 — honest-operation self-slash (§9.2), the substantive fix in this
    revision.** Revision 2.1 specified nonce commitments indexed *per epoch*, while
    the same operator threshold signs two artifacts per epoch (`A_k` and `h_k`). Those
    are distinct messages under one committed nonce — the extraction condition — so a
    correct implementation of 2.1 would have leaked its own key and burned its own bond
    during honest operation. The nonce index is now the *(epoch, artifact role)* pair.
    This is a protocol change, not an editorial one: anyone who built against §9.2 as
    previously written must re-derive their nonce schedule.
16. **§9.2 extraction premise stated precisely.** Extraction requires `e₁ ≠ e₂`;
    distinct *messages* imply distinct *challenges* only under collision resistance of
    the challenge hash. Revision 2.1's prose asserted the message form, which is the
    weaker, not-quite-sufficient statement. Equal challenges extract nothing.
17. **§7.1 "atomic" scoped honestly.** Abandonment is clean only through step 4; a
    transition signed in step 5 is broadcastable and cannot be recalled by declaring
    the ceremony abandoned.
18. **§7.1a distinguishes selection from spendability.** Auto-exit on `k−1` names the
    epoch clients select; because a signed transition can be broadcast before any seal
    exists, it does not promise that epoch's input is unspent. §8a's race analysis
    governs recovery.
19. **§7.5 identifies which defense actually prevents an unlawful eviction.** Of the
    four listed consequences, only enclave/threshold refusal operates before a
    transaction exists; client non-finality, seal refusal, and bond slashing are
    after-the-fact. Seal refusal is not a consensus veto.

**Expansion pass** — a second round extended the models and closed the gaps the first
round left, adding one finding:

20. **A25 — pre-seal eviction window (§7.5).** Modeling the notice-sealing step
    showed the payout obligation, as revision 2.2 first worded it, began only when
    the seal set receipted the notice — while the one leg that actually prevents a
    spend was gated on the same condition. The interval between filing and sealing
    was therefore unprotected, and an Operator could widen it by stalling the
    sealers. The obligation now attaches on the validly signed notice presented to
    the signing threshold; the seal governs third-party adjudication only. The fix
    was verified: the model that violated the safety property holds once refusal
    keys on the filed notice.
21. **A24 and A18 now have executable models.** A nonce-schedule module reproduces
    the honest-operation self-slash in three states with no adversary and no crash,
    and four dependency-free Lean theorems state the side condition that separates
    extraction-as-a-defence from extraction-as-a-liability, showing the per-epoch
    schedule provably fails it and the per-(epoch, role) schedule provably satisfies
    it.
22. **Two first-round gaps closed.** The A4 ordering invariant is now independently
    falsifiable, via a configuration admitting an implementation that releases a
    signed transition before the lattice exists; and the §7.4 timelock inequality,
    which tested the chosen parameters rather than the protocol, was demoted to an
    assumption, leaving the sweep-versus-exit property as the checked one.

Standing limits after both passes, recorded so they are not mistaken for results: the
modules share assumptions by documentation rather than by a machine-checked refinement
relation; trust-layer oracles (threshold refusal, honest sealers, attestation) remain
assumed, never derived; and the §13.2 trilemma remains unformalized — what was proved
there is a restricted game whose theft-authorization is an explicit premise, not an
impossibility result.

**Revision 2.3** — own-balance enforcement stated so it cannot be read as a signing
share:

23. **§7.6 — a member enforces their own balance by exiting with it.** They do not
    join `P_k` and the pulse does not wait on them. Their node checks one number,
    their slot, and broadcasts the last good branch if it is short. The Operator
    displaces that broadcast only by paying them in full (§7.5). Silence is not a
    veto, and a false complaint withdraws only their own money, so the check is not
    a pool-wide DoS (§13.4). Missing the contest window accepts the new amount for
    that member alone.

**Revision 2.4** — the stale-state race, re-examined against what Bitcoin's timelock
and miners actually enforce. Six findings (A26–A31). Everything here uses Bitcoin as it
is today.

24. **A26 — the stale-lattice race was not unconditional. This is the substantive
    fix in this revision.** The exit-leaf delay counts from the confirmation of the
    pool output, not from an exit attempt. Once the last on-chain pool output is Δ
    blocks old, its lattice is valid, and that lattice is stale as soon as one pulse
    has followed. Earlier revisions said the honest side "structurally wins" this
    race. It wins only if the next transition confirms first. New §7.4a states the
    invariant — no pool output stays unspent for Δ blocks while a final pulse is
    pending on it — and the three duties that keep it: a heartbeat cadence bounded by
    `heartbeatInterval + margin_a ≤ Δ`, an admission rule (no off-chain pulse on an
    anchor at or past its deadline), and an extension duty on every holder of the
    pending transitions. A seal is still necessary for finality and is no longer
    sufficient: the chain conditions must also hold in the client's own view of the
    chain (§7.1a). This is a protocol change: Δ now also bounds how long pulses may
    stay off-chain, and a deployment sized against an earlier revision must choose
    Δ and its heartbeat interval together.
25. **The watcher is named (§5, §7.3, §8, §13.1, §13.3).** Who must hold what, how
    often they must look at the chain, and who pays the fee. Retention is extended to
    the transitions since the last on-chain pool output, and a transacting party
    signs only when it holds them (§7.1 step 4g). Every trigger is a fact
    recorded in blocks; none depends on seeing a transaction in a mempool. §7.6 is
    restated on the same basis: a member checks their slot before the transition
    that changed it confirms, not "before Δ ends".
26. **A28 — transitions get a fee path (§7.1 step 5).** A transition's fee was fixed
    at signing with no way to raise it. It is now a TRUC transaction with one keyless
    anchor output, so anyone can pay for its confirmation. Stated consequence: about
    one pending transition confirms per block through public relay.
27. **A27 — a miner model (§8).** A new subsection separates the consensus rules
    this design can rely on from the relay policy it cannot. "An unbumped root cannot
    confirm" is corrected in §7.5, §8 and A17: it cannot *relay*. The value that can
    change hands between two on-chain pool outputs is capped at `v_max`, and a fee
    reserve sized against timelock bribery backs the extension duty (§7.4a, §9.4).
    The reserve is money outside the pool. Nothing on-chain enforces it.
28. **A29 — deposit inputs (§7.1, §7.4a).** A pending transition may spend only
    inputs their owner cannot respend alone, each with a respend deadline of its
    own, which the same three duties serve.
29. **A30 — Δ is a block count (§4, §6, §8, §11).**
30. **A31 — no eviction window on an old pool output (§7.4a, §7.5, §13.4).** The
    §7.5 answer to a broadcast root assumed the Operator could still spend the pool
    output first. A root can be broadcast only once it is already mature, so that
    window does not exist. Deployments choose between a keep-alive heartbeat and
    accepting that an idle pool can be unwound for the price of one root.
31. **§9.4 worked example made consistent.** It had a daily heartbeat and no value
    for Δ; it now carries Δ, `margin_a`, `v_max` and the fee reserve.
32. **A new formal module, [`formal/Anchor.tla`](./formal/Anchor.tla).** It
    model-checks the invariant of item 24 at two sets of small bounds. Four further
    configurations each remove one defence, or thin the margin, and reproduce the
    rollback; three more are reachability witnesses. Assumptions, bounds and results
    are in [`formal/VERIFICATION-2.4.md`](./formal/VERIFICATION-2.4.md). That some
    holder broadcasts by the deadline, and that miners include a broadcast transition
    within a bounded number of blocks, are assumptions of the model, not results.
33. **An alternative is recorded and not adopted (§7.4a, §12.1 item 8):** a
    pre-signed kickoff transaction that would start the delay only when someone
    moves.

Standing limits of this revision: that a holder acts in time and that miners include
its transaction are assumed, never derived; the bribery bound is taken from the cited
analysis and neither re-derived nor modeled here; the model checks safety only, so
nothing is shown about a pool making progress under these rules; and findings A27–A31
have no formal counterpart.

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
  ways — it clears, or you are paid.
- You never have to show up when other people transact. Your escape cheque is kept
  current by whoever *is* in the room, and a **watchdog service** can cash it for you
  if the bank goes dark.
- Periodically (the **heartbeat**), the whole arrangement is refreshed on the actual
  blockchain, like renewing a lease. That is the "recurrent" rhythm: many off-chain
  **pulses** between on-chain heartbeats.
- **Old cheques are never torn up. They are beaten to the counter.** Every stack of
  cheques has a waiting period, and its clock starts when the piggy bank it was
  written for was last recorded on the blockchain — not when someone tries to cash
  one. A newer arrangement wins only if it is recorded before that clock runs out. So
  the heartbeat comes round more often than the waiting period, and if the bank is
  late, the watchdog or the panel records the newer paperwork instead. This is the
  one chore that cannot be skipped.

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

- **Older tickets lose only because newer paperwork is recorded first.** Nobody tears
  up the tickets from an earlier move. Every set has a waiting period before it can
  be cashed, and that clock starts when the jar it was written for was last recorded
  on the public ledger, not when someone tries to cash a ticket. So the clerk records
  the newer paperwork on a schedule shorter than the waiting period. If the clerk is
  late, your watchdog or the independent panel records it instead: they already hold
  everything needed, and it costs them a ledger fee. This is the one chore that
  cannot be skipped. If nobody did it in time, someone holding an older ticket with a
  better number could cash it. The rules cap how much may change hands between two
  recordings, so the worst case stays small and the ledger fee is always worth
  paying.

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

- **Checking your own number is not a vote.** You do not sign other people's moves, and
  staying offline does not freeze the jar. Your node, or a watchdog, looks at one figure
  on each new set of tickets: your share. If it is right, you keep the new ticket and
  say nothing. If it is short, or the new ticket never arrives, you cash the last ticket
  that was right. The clerk can stop that cash-out only by paying you your full balance
  and taking you off the books. A made-up complaint just withdraws your own money. You
  cannot hold the jar shut. You do have to look before the new paperwork is recorded
  on the public ledger; missing that means you accept the new number, and nobody
  else's ticket waits on you.

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
  fresh and cheap to cash, and is what makes the newest tickets the ones that count.
  The practical upshot: don't go *completely* dark forever — check in now and then (or
  let your watchdog do it), and your money stays yours.

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
   production — as long as the on-chain pool output it rests on is before its anchor
   deadline. On an older output nothing new is final until a transition has
   confirmed (§7.4a).
4. **Bounded lifetime.** The pool's `renew` expiry forces a recurrent on-chain refresh
   (the heartbeat), which resets exit cost and re-protects the full membership. The
   exit delay Δ bounds the refresh more tightly than `renew` does: pulses stay
   off-chain for less than Δ after the last on-chain pool output (§7.4a).
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
| **Transition tx `T_k`** | The plain, fully-signed, broadcastable transaction implementing pulse `k`. It carries one keyless fee anchor so that any holder can pay for its confirmation (§7.1 step 5) |
| **Epoch key `P_k`** | MuSig2 aggregate of *ephemeral, sign-once* keys of `{Operator} ∪ M_k`. Passive members are **never** in the aggregate |
| **Exit lattice `L_k`** | Fully pre-signed splitting tree spending `U_k`'s exit leaf into one slot per member, per `S_k` |
| **Slot** | A lattice leaf output: `SingleSig(memberPk)` with the member's own exit CSV |
| **Continuity attestation `A_k`** | Schnorr attestation over the Merkle root of the *full* state table `S_k` — Operator-signed; threshold-signed in the primary model (§9) |
| **Pulse commitment `h_k`** | `H(h_{k-1} ‖ S_k ‖ txid(T_k) ‖ root(L_k) ‖ A_k)`, co-signed by Operator + threshold of `M_k` |
| **Epoch seal `σ_k`** | k-of-n countersignature over `h_k` by the seal set, issued only after the §7.1a predicate passes **and** the sealers hold the full artifact bundle. The per-pulse finality gate (§7.1 step 6): necessary for finality and never sufficient on its own, because the chain conditions of §7.4a must hold as well |
| **Seal set** | The k-of-n entities issuing epoch seals — independent of the Operator; defaults to the referee federation of §9. Never in the exit path |
| **Exit notice `X_k(m)`** | Member `m`'s signed declaration invoking unilateral exit at epoch `k`; sealed notices are objective, timestamped evidence (§7.5) |
| **Eviction pulse** | A transition consuming `U_k` while an exit is in flight; conforming **only if** it pays the noticed/claiming member(s) in full on-chain (§7.5) |
| **Heartbeat** | A pulse whose transition tx lands on-chain, re-anchoring the pool tip with a freshly built full lattice. Landing it confirms every pending transition before it, in order (§7.2); it is due before the anchor deadline (§7.4a) |
| **Anchor `U_a`** | The pool output currently confirmed on-chain; `H_a` is the height of the block that confirmed it. It moves each time a transition confirms, whoever broadcast it |
| **Pending chain** | The signed, unconfirmed transitions `T_{a+1} … T_k` between the anchor and the sealed tip; `D` is its length |
| **Δ (`exit`)** | The exit leaf's relative timelock, a block count measured from the confirmation of the pool output the leaf sits on. It is a contest window only while that output is younger than Δ (§6, §7.4a) |
| **Anchor deadline** | `H_a + Δ − margin_a`: the height by which the first pending transition `T_{a+1}` must be broadcast so that it confirms before `L_a` matures at `H_a + Δ`. From this height on, no off-chain pulse is admitted on `U_a` (§7.4a) |
| **Extension duty** | The obligation of every holder of the pending chain to broadcast and fee-bump `T_{a+1}` once the anchor deadline is reached with it still unconfirmed (§7.4a) |
| **Off-chain pulse, on-chain pulse** | An off-chain pulse becomes final when it is sealed, so it is admitted only while the chain conditions of §7.4a hold: the anchor is before its deadline, the exposure stays within `v_max`, and no respend deadline has been reached. A pulse proposed when one of them fails, or with a deposit input its owner could respend alone, is an on-chain pulse: broadcast at once, and not final on its seal (§7.4a, duty 2) |
| **Respend height, respend deadline** | For a deposit input of a pending transition, the respend height is the first height at which one party alone could spend that input some other way. The transition confirms below it. Its respend deadline falls `margin_a` before that height, and earlier again for each pending transition beneath (§7.4a) |
| **Rollback exposure `E`, cap `v_max`** | The total debited from member balances by the pending pulses. It bounds what any group of members would regain if the pool fell back to the anchor state or to any pending epoch. Capped at `v_max` per anchor window (§7.4a, §8) |
| **`renew`** | The pool's absolute expiry, after which the Operator's sweep path eventually matures |
| **Bond** | The Operator's optional on-chain security deposit, held by a `k`-of-`n` federation of referees independent of the Operator; pays victims on objective evidence or returns to the Operator at expiry (§9) |
| **`requiredCoverage`** | The minimum bond size for a given adversary class — quantified per class in §9.4 (revision 2.1 corrects revision 2's at-risk-per-epoch claim) |
| **EOTS** | Extractable one-time signature: a Schnorr signature that is protocol-valid only under the nonce pre-committed for its *(epoch, artifact role)* slot; two signatures under one committed nonce with distinct challenges leak the secret key (§9.2, A24) |
| **Nonce chain** | The Merkle-committed sequence of signing nonces published at genesis and each heartbeat, indexed by *(epoch, artifact role)*; attestations, seals, and commitments are valid only under the nonce committed for their own slot (§9.2, A24) |
| **Equivocation bond `B_eq`** | Plain-BTC bond whose only pre-timelock spend is a pre-signed burn completable by anyone holding the EOTS-extracted key — self-executing slashing of the double-sign class (§9.2, §9.4) |
| **Outflow cap `w_max`** | Client/enclave-enforced bound on one pulse's net on-chain outflow; bounds every *detectable* theft class (§9.4) |

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
| **Passive member** | **Nothing after deposit** | Own deposit/withdraw only — but they, or a watchtower for them, look at the chain at least once per watch interval (§7.4a) | Must *retain* exit artifacts and the pending chain (or delegate to a watchtower, §8); interactivity is borne by transactors |
| **Transacting parties** | Lattice + transition + `h_k`, in **one ceremony** (two MuSig2 rounds, one network round-trip) | Their own transaction | Typically 1–2 parties |
| **Operator** | Every pulse + attestation + commitment | Always-on | Lands the pending chain before each anchor deadline (§7.4a). Absence ⇒ freeze ⇒ holders extend the chain, then everyone exits via lattices |
| **Seal set** | Epoch seals only | Per pulse (k-of-n threshold) | Data-availability custodian; never in the exit path; a stalled seal set is a visible liveness fault (§7.1 step 6). It holds every pending transition, so it carries the extension duty as broadcaster of last resort (§7.4a): a fee wallet, still no key and no pool funds |
| **Watchtower** | Nothing (lattice and transitions are fully pre-signed) | Watching blocks, at least once per watch interval | Can broadcast *anyone's* exit and file the owner's exit notice if delegated; **must** extend the chain at the anchor deadline (§7.4a); non-custodial, but needs fee funds of its own |
| **Heartbeat participants** | Operator + that pulse's transacting parties only | — | Passive members are **not** needed at heartbeats |
| **Genesis** | Operator only, if the pool starts empty and members join via deposit pulses | — | **No all-hands N-of-N ceremony ever exists** |

A member who wants their own balance enforced does not join this table as a signer to
get it. The check, and the rule that their silence is not a veto, are §7.6.

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
- **Δ counts from confirmation, not from broadcast.** The delay is a consensus rule
  ([BIP 68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki) /
  [BIP 112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)): the
  lattice root is invalid in every block lower than `Δ` above the block that confirmed
  `U_k`, and valid in every block from there on. Nothing restarts the count when
  someone decides to exit. So Δ is a contest window only for an output that was *just*
  confirmed. An output that has been on-chain for Δ blocks has no window left: its
  lattice can confirm in the next block. Stale-state safety therefore needs a second
  ordering invariant — no pool output reaches that age while a final pulse is pending
  on it (§7.4a, A26). `Δ` is a block count, not a duration (A30).
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
   `U_0` in a batch transaction. `U_0` is the first anchor: the block that confirms it
   starts the first anchor window (§7.4a).

### 7.1 Pulse ceremony (D1) — atomic; order is load-bearing

A pulse either completes fully or is abandoned, leaving the pool on `U_k`, whose
lattice is already valid. **Abandonment is clean only up to step 5.** Once `T_{k+1}`
is signed it is a broadcastable transaction, and no ceremony-level declaration recalls
it: an aborting party can refuse to continue, but it cannot un-sign. So "atomic" here
means *steps 1–4 are abandonable*, not that a signed transition can be withdrawn —
see §8a, where this is exactly why "the pool stays on the last good epoch" is a claim
about which epoch clients *select*, not a guarantee that its input is still unspent.

1. **Propose.** A transition `T_{k+1}` is proposed, changing only the transacting
   parties' balances. The Operator emulates the contract's introspection covenant
   against it. `S_{k+1} = S_k` with only `M_{k+1}` slots changed. If any exit notice
   is outstanding against `U_k` (§7.5), the proposal **must** include the noticed
   members' full payouts, or it is non-conforming from the start. Any input other
   than `U_k` — a deposit — must be one its owner cannot respend alone, and an
   off-chain pulse is proposed only on an anchor that is before its deadline (§7.4a).
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
   - (d) the pulse's net on-chain outflow respects the pool's `w_max` cap, and — if
     the deployment is bonded — coverage per §9.4 still holds;
   - (e) **its own lattice branch is in its hands** — *"no lattice in my hands, no
     pulse."* Publication to the relay mesh alone is never trusted;
   - (f) **the anchor is before its deadline, the pulse keeps the rollback exposure
     within `v_max`, every deposit input is one its owner cannot respend alone, and
     no respend deadline in the pending chain has been reached** (§7.4a). If any of
     these fails the pulse can only be an on-chain one: broadcast at once, and not
     final on its seal (§7.4a, duty 2);
   - (g) **every pending transition since the anchor is in its hands**, together with
     the transactions that bring their deposit inputs on-chain. Without them it
     could not land its own pulse (§7.3, §7.4a).
5. **Transition signing.** Only now do the Operator + transacting parties sign
   `T_{k+1}` (SIGHASH_ALL, nSequence final). `T_{k+1}` uses the fee plumbing of a
   lattice node: a TRUC (version 3) transaction with **one keyless P2A anchor
   output**. Its own fee is fixed at signing and can never be raised — a re-signed
   transition would be a second spend of `U_k` — so the anchor is its only fee path,
   and it is what lets a party with no key in the pool pay for its confirmation
   (A28). Two consequences of
   [TRUC](https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki)'s
   one-parent-one-child limit, both relay policy rather than consensus (§8):
   - pending transitions confirm **about one per block** through public relay,
     because `T_{k+2}` cannot enter a mempool while `T_{k+1}` is unconfirmed. Since
     every transition confirms eventually (§7.2), a pool that relies on public relay
     sustains at most one pulse per block; a pulse may batch any number of parties;
   - a transition must fit TRUC's 10,000-vB limit, which bounds how many payouts one
     eviction pulse (§7.5) can carry.
6. **Commit and seal.** `h_{k+1}` is **co-signed by the Operator + a threshold `t` of
   `M_{k+1}`** so the Operator cannot unilaterally author forks (`t ≥ 1`; a fork then
   requires `t` contradicting signatures, so higher `t` is more fork-resistant at the
   cost of more required online co-signers — `t = 1` minimal, `t = |M_{k+1}|`
   maximal). Full artifacts `(S_{k+1}, T_{k+1}, L_{k+1}, A_{k+1})` go to the relay
   mesh, content-addressed by `h_{k+1}`, **and to the seal set**, which issues the
   epoch seal `σ_{k+1}` only after (i) recomputing the §7.1a predicate and (ii)
   confirming the full bundle is *in its hands* — the seal is a **data-availability
   receipt**, not a mere countersignature. The bundle includes `T_{k+1}` itself and
   every transaction needed to bring its deposit inputs on-chain, and the seal set
   does not seal an off-chain pulse on an anchor at or past its deadline (§7.4a).
   **The next pulse is invalid until `σ_k` is issued.** Sealing is off-chain and
   per-pulse, so pulse rate is decoupled from block production (principle 3); the
   Operator's next on-chain batch commits the current **seal-chain head**, so a
   withheld seal or a withheld batch commitment is a *visible liveness fault* within
   one batch interval that trips auto-exit (§7.3).
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
checks (genesis `h_0` is checked at deposit). **This selects an epoch; it does not
promise that epoch's input is still spendable.** A transition signed in step 5 is
broadcastable before any seal exists (§7.1), so `U_{k−1}` may already be consumed by
the time the halt fires. Auto-exit on `k−1` is therefore the correct *client policy*
and simultaneously the weakest link in the recourse ladder — §8a's race analysis
governs what it actually recovers. This converts a malformed or
over-allocating lattice from a *silent loss* into a *liveness halt*, and it does so
without any covenant: the data is public and the arithmetic is objective. The only
residual is a counterparty who already treated pulse `k` as final off-chain before
checking — so external settlement must gate finality on this same predicate (in
practice: on the epoch seal, which implies it).

**A third condition comes from the chain, not from the pulse (revision 2.4).** The two
checks above say the pulse is well-formed. They do not say it will outlive the lattice
of the anchor beneath it. A conforming client therefore treats a sealed pulse as final
only while, in its own view of the chain, the anchor is before its deadline, the
rollback exposure through that pulse is within `v_max`, no respend deadline in the
pending chain has been reached, and every pending pulse beneath it is final (§7.4a).
If the anchor has reached its deadline with the pulse's ancestors still unconfirmed,
the client does two things: it performs the extension duty, and it treats the
pending pulses as unsettled until `T_{a+1}` confirms. External settlement gates on
the same pair — the seal *and* the anchor's age. The seal does not stand in for the
second: a pulse sealed on an anchor at or past its deadline is an on-chain pulse,
sealed and not final before a transition has confirmed (§7.4a, duty 2). Unlike a
failure of checks 1–2, this is no reason to exit on `k−1`: the pulse is valid and
only needs to reach the chain.

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
- **Landing a heartbeat confirms the whole pending chain.** `T_{k+1}` spends `U_k`,
  so the tip cannot reach the chain without every transition before it, in order,
  about one per block (§7.1 step 5). Pulses defer the pool's on-chain transactions
  and take finality off the block clock; they do not remove the transactions. There
  is no shortcut: a transition that spent the on-chain pool output directly, skipping
  the pending ones, would be a second spend of that output — a commitment fork (§8a).
- The Operator cannot heartbeat unilaterally; it can only propose one. Cadence is
  quorum- and economics-gated: required frequency rises with pool TVL so that
  **at-risk-per-epoch stays ≤ the Operator bond** (§9) — and, independently, so the
  virtual-chain-depth cap of §7.4 holds.
- **Proposing needs a ceremony; landing does not.** The pending transitions are
  already fully signed, so whoever holds them can broadcast them and pay their fees.
  The extension duty of §7.4a relies on exactly that. Only a pool with nothing
  pending needs a new cooperative pulse to move its anchor.
- **Cadence is also a safety bound, independent of economics (revision 2.4).**
  Whenever a pulse is pending, the first pending transition confirms before the
  anchor's own lattice matures. As a parameter rule:
  `heartbeatInterval + margin_a ≤ Δ` (§7.4a).
- **Eviction pulses land on-chain by definition** (§7.5). A well-run Operator folds
  them into the heartbeat schedule — an eviction is simply a heartbeat that also pays
  the leavers — so the cost of defending against exit griefing amortizes into
  scheduled maintenance rather than being a separate loss.

### 7.3 Unilateral exit walk (D3)

1. A trigger fires — **voluntary**: the member (or their watchtower) files an exit
   notice `X_k(m)` (§7.5) and proceeds regardless of Operator health; or
   **defensive**: a missed epoch seal or batch commitment, `height ≥ renew − Δ −
   margin`, or a **conflicting published artifact**. (A missed anchor deadline is a
   trigger too, but for extending the chain rather than for exiting — see below.)
2. Broadcast the pending chain if there is one: the unconfirmed transitions since the
   anchor, in order, each fee-bumped through its anchor output, about one confirming
   per block (§7.1 step 5). Then, once `U_k` has been confirmed for Δ blocks,
   broadcast the **lattice root**, spending `U_k`'s exit leaf. If `U_k` is an anchor
   that is already older than Δ, the root is valid at once (§6).
3. Broadcast the member's **branch path** (log N transactions), CPFP-bumping via the
   node anchors.
4. After the slot's own CSV matures, sweep `SingleSig(memberPk)` to a wallet.

**Outcome guarantee.** The walk ends in the slot sweep — or, if a conforming eviction
pulse displaces it, in an immediate on-chain payout of the member's full balance
(§7.5). Both are exits; neither requires the Operator's goodwill.

**A missed anchor deadline starts with extension, not exit.** When the anchor reaches
its deadline with a sealed pulse still pending, every holder broadcasts the pending
chain (§7.4a). That is the first half of step 2 and nothing more: it restores safety
and leaves the pool running on a fresh anchor. A missed deadline is a visible Operator
fault, like a missed seal. Whether one miss also trips auto-exit is deployment policy;
the extension itself is not optional.

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

### 7.4a Anchor age: the second ordering invariant

§7.4 orders the Operator's sweep after the exit. A second ordering was missing until
revision 2.4, and without it the first row of §8 is false (A26).

**The gap.** Call the pool output currently confirmed on-chain the **anchor** `U_a`,
and `H_a` the height of the block that confirmed it. The delay on its exit leaf counts
from `H_a` (§6), so the root of its lattice `L_a` becomes valid at height `H_a + Δ`
whether or not anyone has asked to exit, and stays valid for as long as `U_a` is
unspent. Every pulse after the anchor makes `L_a` stale, but nothing on-chain says so
while the transitions `T_{a+1} … T_k` — the **pending chain** — are unconfirmed. From
`H_a + Δ` on, the stale root and `T_{a+1}` are two equally valid spends of `U_a`, and
the stale root needs one block. If it confirms, every pulse since the anchor is void,
seals and attestations included, and the pool pays out `S_a`. Whoever was better off
at `S_a` regains what they have paid away since. They need no accomplice: the root is
pre-signed and mesh-published, and a fee-bumped broadcast is enough.

**The invariant.**

```
if a final pulse is pending on U_a, T_{a+1} confirms below height H_a + Δ
```

No pool output stays unspent on-chain for Δ blocks while a pulse that counts as final
is waiting on it. A pulse that is not yet final — the on-chain pulse of duty 2 below
— is outside the rule: if the anchor's lattice beats it, nothing anyone relied on is
undone. The rule is stated on the anchor, and the anchor moves every time a
transition confirms, whoever broadcast it: the Operator's heartbeat, a watcher, a
member starting an exit, or an adversary landing part of the chain to attack from a
later stale epoch. Each transition gets a fresh Δ from the confirmation of its own
parent, so only one transition is ever under this deadline — the first pending one.
A miner may put several transitions into one block, which relay policy would not;
the last of them still leaves a freshly confirmed output with a full Δ ahead of it.
(A deposit input can put a deeper transition under a deadline of its own; see
"Inputs from outside the pool" below. Under the two-tier sharding of §7.1 step 3
the rule applies to every output that pulses spend, the hot band's as well as the
pool's.)

**Anchor deadline and `margin_a`.** The deadline is `H_a + Δ − margin_a`. The
Operator broadcasts `T_{a+1}` before the chain reaches that height. If `T_{a+1}` is
still unconfirmed there, the holders of the pending chain take over (duty 3), and
`margin_a` is the number of blocks they need. It is the sum of:

- the **watch interval** — the longest gap between two looks at the chain by the
  parties relied on to act if the Operator does not. An always-on watchtower
  contributes one block; a wallet that syncs once a day contributes 144;
- the **unconfirmed ancestry** of a pending transition outside the pool chain: every
  transaction that must confirm before it can (a deposit made from a virtual output
  brings that output's path and its checkpoint with it), about one per block;
- a **non-inclusion allowance** `n = ⌈ln ε / ln q⌉`: enough blocks that miners holding
  a share `q` of the hash power mine all of them with probability at most `ε` (§8).
  `q = 0.5` and `ε = 10⁻⁶` give 20 blocks; `q = 0.9` gives 132;
- the **fee-spike buffer** of §7.4 and the deployment's reorg depth.

Three duties keep the invariant. The first is the normal case. The other two are what
make it hold when the Operator is late, dark, or not on the honest side.

1. **Cadence — the Operator.** Whenever the pending chain is not empty, the Operator
   lands it so that `T_{a+1}` is broadcast before the anchor deadline. That is the
   heartbeat (§7.2). As a parameter rule that the ABI template carries and wallets
   check (§11):

   ```
   heartbeatInterval + margin_a ≤ Δ
   ```

   `heartbeatInterval` is the most blocks the Operator lets pass between an anchor's
   confirmation and its own broadcast of `T_{a+1}`.

2. **Admission — the signing threshold, the seal set, every client.** An off-chain
   pulse is final on its seal, so it is admitted only on an anchor that is **before
   its deadline**, and only if it keeps the rollback exposure within `v_max` (below).
   At or past the deadline nothing new is final until a transition has confirmed and
   a younger anchor exists. This also covers a pool that has been idle past Δ: its
   next pulse is an **on-chain pulse** — signed, broadcast at once, final when
   `T_{a+1}` confirms. Until then the anchor's own lattice can still beat it, which
   only means the pulse did not happen.

   **A seal is necessary for finality and never sufficient.** It is a
   data-availability receipt and is silent on this race. On an anchor at or past its
   deadline no pulse becomes final, the on-chain pulse included: no client, sealer
   or external settler counts one as final, or settles against it, until a
   transition has confirmed and the pulse is either on-chain itself or admissible on
   the younger anchor. Finality is also a prefix: a pulse is final only if every
   pending pulse beneath it is, so nothing proposed on top of a pending on-chain
   pulse counts before that pulse does. An on-chain pulse may be proposed while
   final pulses are still pending; it confirms after them.

   A proposal says which of the two kinds it is, and the signing threshold and the
   seal set refuse one that claims to be off-chain on an anchor at or past its
   deadline. That holds an Operator that is merely late. It does not hold one that
   proposes a late pulse as on-chain and then presents its seal as final, because
   `h_k` and the seal read the same for both kinds. The check that cannot be skipped
   is therefore each client's own: it looks at the anchor's age itself, whatever the
   proposal said, in a view of the chain it knows to be current. A client that
   cannot tell how far behind its tip is counts nothing new as final. The other two
   do not see the chain equally well either: a signing enclave is told the chain tip
   by its host, which can show it an old one, so its refusal is a second line (§9).
3. **Extension — every holder of the pending chain.** If the anchor reaches its
   deadline and `T_{a+1}` is still unconfirmed, every party that holds it broadcasts
   it with a fee-paying child on its anchor output and raises the fee until it
   confirms. Each confirmation moves the anchor and opens a fresh window; if the
   Operator stays silent the holders do the same for `T_{a+2}` and the rest at each
   new deadline, or at once if they mean to exit (§7.3). Holders are the transacting
   parties, watchtowers, the seal set (which receipted the whole bundle, §7.1 step
   6), mesh archivers, and any member who retained the pending chain (§8). A
   self-sealed deployment has no seal set apart from the Operator, so there the
   fallback is the rest of that list. Several holders acting at once cost one fee,
   not several: only one child of an anchor output can confirm. The duty covers
   transitions of **sealed, undisputed pulses** only — a holder never extends through
   a pulse it holds a dispute against, or through a transition that skips a noticed
   member's payout (§7.5, §7.6). Every trigger is a fact recorded in blocks: the
   anchor's height, its age, the confirmation of a transition or of a deposit's
   ancestor. None is a mempool observation.

A missed deadline is objective — the anchor's height and the seal chain show it — so a
bonded deployment can make the Operator repay the fees others spent extending. That is
deployment policy; the duties are not.

**Exposure cap.** The **rollback exposure** is the total debited from member balances
by the pending pulses:

```
E = Σ_{i=a+1..k} Σ_m max(0, S_{i−1}(m) − S_i(m))
```

It is public arithmetic over committed tables, and it bounds what any group of members
would regain if the pool fell back to the anchor state or to any pending epoch.
Admission refuses an off-chain pulse that would lift `E` above `v_max`; the pool lands
a heartbeat first, which brings `E` back to zero. The cap exists because the fee
needed to keep miners from waiting scales with what an attacker stands to gain (§8),
and because it bounds the loss if every duty above fails. Behind the extension duty
sits a **fee reserve** of at least `λ_min · v_max` beyond the ordinary fees for landing
`D` transitions, held by the Operator and by the watchtowers and sealers that carry
the duty. `v_max` is a different quantity from `w_max`, which limits net on-chain
outflow per pulse and says nothing about balance changing hands inside the pool.

**Nothing on-chain enforces the reserve.** It is ordinary money outside the pool.
No script locks it, and nothing in the protocol shows whether it is still there: a
holder that has spent its reserve looks like every other holder until a deadline
comes and it cannot pay. Each party therefore counts only what it holds itself. A
sealer whose fee wallet is below the reserve refuses off-chain pulses until it is
refilled, as it would on an anchor past its deadline. A member who keeps no
reserve, directly or through a watchtower trusted to hold one, is relying on some
other holder to pay (§8, condition 3). `v_max` is fixed in the template (§11) so
that each of them knows what it has to back. Set above what those wallets hold, the
cap fails just as quietly.

**Inputs from outside the pool (A29).** A transition that also spends a deposit is
valid only while that deposit is unspent. If its owner can spend it elsewhere before
the transition confirms, they void that transition and every one after it: a rollback
with no lattice involved. So a pending transition spends, besides `U_k`, only inputs
whose owner **cannot respend them alone** — outputs that need the Operator's
co-signature for any other spend until a stated height, such as an Arkade boarding
output before its timeout path opens, or an Arkade VTXO spent through a checkpoint
transaction. Each such input has a **respend height**: the first height at which one
party alone could spend it some other way — the owner through a timeout path, or the
Operator by sweeping an expired batch. The transition that spends the input has to
confirm below that height. That is a second deadline on the pending chain, and the
three duties serve it as they serve the anchor deadline. The **respend deadline** is
`margin_a` blocks before the respend height, and earlier still by what every pending
transition beneath that one needs in order to confirm first: its own ancestry and a
non-inclusion allowance of its own. The Operator has the chain confirmed through
that transition before the respend deadline. From that height on, no off-chain pulse
is admitted with the input or on top of it. And if the transition is still
unconfirmed at that height, every holder starts landing the chain through it and
stays with it until it confirms. The same applies when the input's own ancestry
appears on-chain: if a deposited virtual output is unrolled, its delays start to
run, and holders respond by confirming its checkpoint and then the pending chain
through that transition before they expire. An input without this protection is
admissible only in an on-chain pulse, which is final when its own transition
confirms and not before. For an input that does have it, the protection until the
transition confirms is the Operator threshold's refusal to co-sign a conflicting
spend — the trusted layer of §9, not consensus.

**Idle pools, and what an old anchor does to §7.5 (A31).** With nothing pending the
invariant asks for nothing: the anchor may sit past `H_a + Δ`, and its lattice is
then the *current* state's exit with no wait at the root — the standing exit at its
strongest. The price is that the eviction window of §7.5 does not exist on such an
anchor. A current root that someone fee-bumps, or hands to a miner, confirms before
the Operator can answer, and the pool unwinds. A deployment that wants the eviction
defence at all times keeps the anchor young even when idle, with a **keep-alive
heartbeat** inside every `Δ − margin_a` blocks: a full pulse each time, with a
co-signer besides the Operator (§7.2), an on-chain transaction, and the O(N)
re-sign. A deployment that does not accepts that anyone can unwind an idle pool for
the price of one root. This is a cost-against-griefing choice, declared in the ABI
template (§11); neither option affects the safety of balances.

**What the invariant costs.** Δ used to be only the wait before an exit. It is now
also the ceiling on how long pulses stay off-chain. A short Δ means fast exits and
frequent landings; a long Δ means the reverse. The coupling exists because the delayed
leaf sits directly on the pool output, so its clock starts when that output confirms
rather than when someone contests it. A pre-signed **kickoff** transaction between the
pool output and the delayed leaf would start the clock only when the kickoff
confirms, which removes the periodic deadline. It costs one more pre-signed
transaction, and one more on-chain transaction, for every pool output it protects,
and it still needs the same watcher once a kickoff appears. Revision 2.4 does not
adopt it (§12.1 item 8).

### 7.5 Exit notice and eviction-with-payout (D5)

Revision 1 analyzed stale-lattice broadcasts, commitment withholding, and fresh
colluding theft (§8) — but left a fourth case unexamined: **an exit of the correct,
current state, broadcast while the Operator is alive.** Chain-extension dominance cuts
both ways, and both directions were unhandled:

- **Griefing (A17).** The current lattice root is fully pre-signed and mesh-published
  *by design* — anyone can broadcast it, once the pool output it spends has been
  confirmed for Δ blocks (§6). Getting that output on-chain, if it is still virtual,
  costs the griefer the pending chain's fees. An unbumped root does not *relay* (a
  TRUC zero-fee parent needs a CPFP child to enter a mempool), but that is relay
  policy, not consensus: a miner handed a mature root directly can include it with
  no fee at all (A27). A current root that confirms is a forced mass exit in which
  the griefer pays for one root and one branch while every other member pays their
  own branch walk (≈N× damage leverage). The only way to prevent it is to spend the
  pool output **before the root matures**, which costs the Operator an on-chain
  transaction **plus a full O(N) lattice re-sign**, again and again for as long as
  the threat stands. The griefer spends nothing until a root confirms. (Revision 2
  described the Operator's move as a response to a *bumped root in flight*. There is
  no such moment: a root that can be broadcast is already mature — A31.)
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
> **Eviction-with-payout.** From the moment `m` presents a validly signed `X_k(m)`
> to the signing threshold, any transition consuming `U_k` — and any subsequent
> transition, until the notice is discharged — is **conforming only if it pays `m`'s
> full `S_k` balance to an on-chain output under `m`'s slot key.**
>
> **The obligation attaches on the signed notice, not on its seal (A25).** These are
> two different instants and the gap between them is exploitable. The signing
> threshold can verify `m`'s signature on the notice itself, so it needs no receipt
> from anyone to refuse a short payout; the seal exists to make the case *adjudicable
> by third parties* — dispute halt, bond slashing, compensation — not to gate the one
> leg that actually prevents the spend. Keying refusal on the seal would leave the
> filing-to-sealing interval unprotected, and an Operator who evicts inside that
> window (or who stalls the seal set to widen it) would owe nothing at all. A displacing transition without that payout is an **unlawful
> eviction**: non-final under §7.1a-extended client policy, refused by the seal set,
> unsignable under the primary model's enclave policy (§9), and — where the optional
> bond exists — slashable on the objective evidence pair (sealed `X_k(m)`, sealed or
> broadcast displacement lacking the payout).
>
> **Only one of those four actually stops the spend.** Enclave refusal is the sole
> leg that operates *before* a transaction exists: a signature the threshold will not
> produce is a transaction that cannot confirm. Client non-finality, seal refusal, and
> bond slashing are all *after-the-fact* — Bitcoin accepts a validly signed transition
> whether or not any sealer blessed it, so those three bound the attacker's ongoing
> business and compensate the victim, they do not veto the displacement. Deployments
> must therefore state which signing threshold enforces the payout rule; a bonded
> deployment with no signing-policy enforcement has deterrence but no prevention.

Consequences:

- **Exit-or-payout.** After a notice, one of exactly two things happens within the
  contest window: the lattice matures (exit), or a conforming eviction pulse pays the
  member immediately (a *faster* exit). A live adversarial Operator can no longer
  stall an exit; a dark one never could. Refusing to pulse at all is the remaining
  option, and it is a **visible stall** — missed seal, missed batch commitment — that
  trips pool-wide auto-exit (§7.3). (The window is what is left of Δ on the pool
  output in question. On an anchor already older than Δ nothing is left: the lattice
  is mature and the exit simply proceeds — §7.4a.)
- **Griefing is repriced into a self-service exit — while the anchor is young.** As
  long as the pool output is spent before it reaches Δ confirmations, no root is ever
  broadcastable; the only request the Operator has to answer is a notice, and
  filing one *is* requesting eviction: the "griefer" is paid out in full and removed
  from the pool (re-entry costs an ordinary deposit pulse). A third party who lands
  the pending chain has paid for the Operator's heartbeat and nothing more. A flood
  of simultaneous notices degenerates into a cooperative unwind — which is the
  correct limit for a pool most of whose members want out. On an anchor that has aged
  past Δ none of this applies: a root cannot be answered, and the pool unwinds at the
  price of one root. Whether a pool is ever in that state is the keep-alive choice of
  §7.4a (A31).
- **The honest Operator's defense playbook is now legitimate and cheap.** Do not
  watch the mempool for roots: an unbumped one never shows up there, and a mature one
  can be mined without passing through it (§8). Act on what is objective — a notice
  — and evict with payout before the pool output's anchor deadline, folded into the
  heartbeat that deadline requires anyway (§7.2, §7.4a), so the defense cost
  amortizes into scheduled maintenance. Never displace without paying: that is the
  one forbidden move, and it is the one that creates evidence.
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

### 7.6 Own-balance enforcement without a signing share

A member who wants only their own balance enforced does not join `P_k` and is not a
required signer of the pulse. A required share would make every other member's
transition wait on that one node. An offline node, or a refusal, would halt the pool.
That is a DoS, and it is the coinpool corner of the trilemma (§13.2): forcing the
victim to co-sign every pulse buys amount safety by dropping non-interactive
membership. This section is the other corner, stated as an operation.

The signing set (the Operator, or the enclave threshold in the primary model, plus
the parties whose balances are changing) signs the new lattice without them. The
member's node keeps the last branch whose slot matched the balance they accepted,
and checks one number in each new lattice: their own slot.

- **The number matches.** They store the new branch and send nothing.
- **The number is short, or the branch never arrives.** They file an exit notice and
  walk the last good epoch (§7.3): land its pool output if it is not on-chain yet,
  then broadcast the root and their branch once that output is Δ blocks old (§6). A
  live Operator displaces that exit only by an eviction pulse that pays their full
  balance on-chain and removes them (§7.5). The next pulse continues for everyone
  else, with that payout included.

Silence is not a veto. An offline node does not freeze the pool, and the ceremony
has no signature of theirs to wait for. A false complaint only withdraws their own
money: once the payout lands they have no balance left to dispute until they deposit
again, so one member cannot hold the pool open. Re-entry is an ordinary deposit
pulse (§7.5), which is what keeps a withdraw-and-rejoin loop from being a free
repeated halt.

The remaining requirement is local. The member, or a watchtower holding that one
branch, must notice a short slot before the transition that shortened it confirms
on-chain. A heartbeat lands it less than Δ after the previous on-chain pool output
(§7.4a), and a compromised signing set can land it sooner. Missing the window means
they accept the new amount. It does not stop anyone else's pulse. This is amount
enforcement by exit-or-payout of a single slot (§13.1). It does not prevent the
signing set from producing the short tree; a fully compromised set can still win the
race of §8a, because the displacing transition carries no CSV. What it does prevent
is a member having to sit in the ceremony, and a pool having to stop when they don't.

## 8. Invalidation model

| Threat | Mechanism | Nature |
|---|---|---|
| **Stale lattice broadcast** (old epoch's exit) | Chain-extension dominance: transitions have no CSV; a lattice root is invalid until its pool output has Δ confirmations; a holder of the next `T` confirms it first and voids the stale lattice. Holds only under the anchor-age invariant (§7.4a): cadence, admission, extension duty | A race the honest side wins **if** one holder of the pending chain acts by the anchor deadline and the transition is mined within `margin_a` (conditions below). Revisions before 2.4 graded it unconditional (A26) |
| **Commitment withholding / forks** | Chained seal dependency + co-signed commitments: a missing seal stalls the pool visibly and trips auto-exit; a forked `h_k` carries a contradictory signature | Detection + liveness fallback |
| **Spurious current-state exit broadcast** (griefing — A17) | No root can be mined while its pool output is younger than Δ, so with the anchor kept young (§7.4a) there is nothing to broadcast; a notice is met with a conforming eviction pulse: the member's slot is paid out in full and the pool continues (§7.5). On an anchor older than Δ a root confirms as soon as a miner has it, bumped or handed over directly — "unbumped roots cannot confirm" was relay policy, not consensus (A27) — and the pool unwinds (A31) | Priced, self-limiting; defense folds into heartbeat cadence — while the anchor is young. An unanswerable forced unwind on an aged one |
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

Revision 2.4 adds a second retained set, with a different job: **every transition
since the current anchor, together with the transactions needed to bring their
deposit inputs on-chain.** Without them a member can neither walk their own exit
(§7.3 step 2) nor perform the extension duty (§7.4a). They are small, and each can be
dropped once it has confirmed.

**The contest window Δ is also a dispute window.** No published evidence can freeze
`U_k` on-chain — there is no covenant to freeze it. But a standardized,
machine-checkable evidence bundle (`A_j` plus the contradicting `L_k`, a forked `h_k`,
a sealed exit notice plus a payout-less displacement, or an EOTS extraction pair —
§9.2, the one class whose punishment executes itself) does two things during Δ: it
makes the referees *earmark* the bond where one exists (blocking its expiry-return
while a live contradiction stands), and it flips every conforming client's
accept-policy to *refuse new pulses* on that pool. Since the next pulse is invalid
until sealed and honest sealers will not seal a disputed tip, a credible dispute
**halts state progression** — the closest no-covenant analogue to a freeze. It stops
the attacker finding fresh victims; it does not, by itself, claw back the specific
contested coins.

### What the stale-lattice race requires

The first row above is a race, and revision 2.4 states what winning it takes. The
stale lattice is certain to lose only if the successor transition confirms before the
stale root can be mined. That needs all four of:

1. **Someone holds the successor.** Every pending transition of a sealed pulse is in
   the bundle the seal set receipted (§7.1 step 6), on the relay mesh, and in each
   member's or watchtower's retained set (above). The transacting parties of every
   pulse hold the whole pending chain, because they do not sign without it (§7.1
   step 4g).
2. **Someone looks at the chain in time.** One of those holders checks the chain at
   least once per watch interval and acts at the anchor deadline (§7.4a). What they
   check is recorded in blocks. Nothing depends on seeing a stale root in a mempool;
   it may never be in one (below).
3. **Someone pays.** A transition's own fee is fixed and may be zero. Whoever
   broadcasts it attaches a child to its anchor output (§7.1 step 5) and needs funds
   of their own to do so — the fee reserve of §7.4a. That reserve is held outside
   the pool and nothing on-chain shows it is there, so this condition is one each
   holder can vouch for only about itself.
4. **Miners include it within `margin_a`.** An assumption about hash power,
   quantified next.

This is the kind of assumption a payment channel makes of each party or its
watchtower, with two differences. The party who must act is **any one** holder rather
than a named counterparty — 1-of-N again (§13.1). And the deadline is not set off by
a cheat: it comes round on every anchor whether or not anyone is attacking, which is
why the Operator's ordinary heartbeat discharges it and the holders' duty is the
fallback. If any one of the four fails, a sealed pulse is reversible by anyone
holding an older lattice, and the loss is bounded by `v_max`.

### Miners: consensus versus relay policy

Earlier revisions treated mempool behaviour as if it bound miners. It does not. A
miner can include any valid transaction it is handed directly, paid for outside the
transaction, and relay policy never sees it. What a miner cannot do is break a
consensus rule: every node rejects the block.

| Rule this design leans on | Kind | Binds a miner paid directly? |
|---|---|---|
| Exit-leaf delay: no root until its pool output has Δ confirmations (BIP 68/112) | Consensus | **Yes** |
| Valid signatures; one spend per output | Consensus | **Yes** |
| A zero-fee parent needs a fee-paying child (package relay) | Relay policy | No |
| One unconfirmed parent, one unconfirmed child, size limits (TRUC) | Relay policy | No |
| A higher fee replaces a lower one; sibling eviction | Relay policy | No |
| Whichever spend reached mempools first | Not a rule | No |

Three consequences.

**While the delay runs, no one can mine a stale root.** Paying a miner directly buys
nothing, because the block would be invalid. All that colluding miners can do for a
stale state in that period is keep the successor transition out of **every** block
until the delay ends. With a share `q` of the hash power that succeeds with
probability `q^n` over the `n` blocks between the successor's broadcast and the
root's maturity — and `n` is the non-inclusion allowance inside `margin_a`, not Δ,
because the successor may be broadcast as late as the anchor deadline. Twenty blocks
hold `q = 0.5` to about one in a million; `q = 0.9` needs 132. Those figures are for
miners that leave the transition out of their own blocks and still build on everyone
else's. Miners above one half that also orphan other miners' blocks can keep it out
for as long as they like, and against them no timelock in any off-chain protocol
holds.

**Bribing miners to wait has a price the honest side can make unaffordable.** Paying
miners to ignore the successor until the stale root matures is the timelock-bribery
game analysed for HTLCs. For every miner to prefer waiting, the bribe must exceed the
successor's fee premium over an ordinary fee, divided by the smallest miner's share
of the hash power ([MAD-HTLC](https://arxiv.org/abs/2006.12031), Theorem 2): a miner
that finds few blocks is unlikely to collect the later bribe and takes the fee in
hand. Turned around (Corollary 2 there), a successor whose fee can be raised to about
`λ_min · E` — `E` the rollback exposure, `λ_min` the smallest relevant miner's share
— makes the required bribe larger than the prize. That analysis estimates
`λ_min ≈ 0.01`, so the budget is on the order of **1% of the exposure**, and it is
spent only if someone actually bribes. Two limits, from the same source. More blocks
do not help against miners who are all rational in this sense; only the fee does.
Conversely, one miner that simply takes the best fee on offer, finding one block in
the window, defeats the bribe whatever its size. (The analysis assumes that neither
side mines or colludes with a miner; an attacker with hash power of its own is the
previous case.) This is the reason for `v_max` and the fee reserve of §7.4a.

**Once the delay has run, only relay policy is left, so the pool must never be in
that state with a pulse pending.** On an anchor older than Δ, one miner, or just a
fee-bumped broadcast, confirms a root. With a pulse pending that root is stale, which
is what the anchor-age invariant forbids. With nothing pending it is the current
state's exit: fine for the member, and the forced unwind of A31 for the pool. For the
same reason "an unbumped root cannot confirm" was wrong as a safety statement — it
cannot *relay*. Every trigger in this document is keyed to blocks.

**Count Δ in blocks.** A delay denominated in time (BIP 68's 512-second units) is
measured on median-time-past, which miners producing six of eleven consecutive blocks
can push up to about two hours ahead of real time, ending the delay early. It also
contains fewer blocks when blocks are slow, while everything the honest side needs is
counted in confirmations. `Δ` and `margin_a` are therefore block counts (A30), and a
`pulse` leaf with a time-based delay is rejected (§11). The slot-level delay (§7.1
step 3) is not part of this race and may stay as the deployment has it.

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
un-broadcastable (its input is spent). (On an anchor already older than Δ — an idle
pool — your root is valid at once and the head start shrinks to an ordinary fee
race; §7.4a.) Chain-extension dominance is a race the honest side wins **only when
the honest side holds the newer transition**; when the *thief* holds the newer (bad)
state, the same Δ that gives honest holders a contest window is a head start handed
to the attacker.

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
  (§7.5);
- a pulse whose net on-chain outflow exceeds the pool's `w_max` cap (§9.4);
- an off-chain pulse on an anchor at or past its anchor deadline, one that lifts the
  rollback exposure above `v_max`, or one proposed once a respend deadline in the
  pending chain has been reached (§7.4a);
- a second spend of a deposit input that a transition it already signed consumes
  (§7.4a).

One caveat on the first of the two revision-2.4 items. An enclave learns the chain
tip from its host, which can show it an old one. Its refusal of late off-chain pulses
is therefore a second line: the checks that count are the seal set's and, in the
end, each client's own (§7.1 step 4f, step 6; §7.4a duty 2), made against chain
views the Operator does not supply.

So a lattice that shorts a passive member — or an unlawful eviction — **cannot be
signed at all**: strictly stronger than "it can be signed but you are compensated," and
it needs **no TVL-sized capital and no separate referee quorum**. In this model the
continuity attestation `A_k` is **threshold-signed** by the federation (promoted from
the revision-1 optional hardening) and **EOTS-bound** (§9.2): lying about a passive
balance requires colluding `t` independently-operated enclaves, twice over
(attestation *and* lattice), and attesting two states for one epoch leaks the
aggregate key and burns the equivocation bond. The
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
  notices (§7.5); refuse to seal a disputed tip (§8); refuse to seal an off-chain
  pulse on an anchor at or past its deadline, one that lifts the rollback exposure
  above `v_max`, or one proposed once a respend deadline in the pending chain has
  been reached (§7.4a); and, holding every pending transition, broadcast and
  fee-bump the pending chain when an anchor deadline or a respend deadline arrives
  with pulses pending (the extension duty, §7.4a). Nothing else — sealers are never
  in the exit path and hold no keys to pool funds. The extension duty does mean each
  sealer needs a fee wallet of its own, holding at least the reserve of §7.4a.
  Nobody else can see into that wallet, so a sealer checks it against itself: while
  it is short, the sealer refuses off-chain pulses as it would on an anchor past its
  deadline. Seals are **EOTS-bound per epoch** (§9.2), so sealing two
  conflicting tips leaks the sealer's key and burns its fidelity bond; and sealers
  double as **witnesses of the commitment transparency log** (§9.3), signing tree
  heads whose consistency anyone can gossip-check.
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
- **Scope of the nonce-reuse rejection — corrected in revision 2.1.** Forced-nonce-reuse
  key-leak punishment (make any second `P_k` signature leak the aggregate secret) does
  **not** work for **transaction signatures**: Bitcoin consensus accepts any valid
  nonce, so a cheater spending `U_k` simply signs with a fresh nonce, and Script cannot
  pin it. Revision 2 over-generalized this into rejecting key-leak punishment
  wholesale. For **protocol artifacts whose validity is judged by conforming
  software** — `A_k`, `σ_k`, `h_k` — the *protocol* can pin the nonce, and §9.2 does
  exactly that.
- **Sizing and client enforcement.** The bond is per-pool and TVL-tracking. Wallets
  refuse to participate in pulses of an under-bonded pool (`bond <
  requiredCoverage(...)`) — client-side policy informed by a bond-reference field in the
  ABI (§11). **Revision 2.1 correction:** revision 2 claimed heartbeat cadence bounds
  at-risk-per-epoch. It does not bound the worst class — a fully colluding signer set
  can drain the pool in a *single* transition, because L1 consensus checks nothing but
  the signature set (§2), and no cadence or client cap stops a transaction that
  confirms. What cadence and the outflow cap `w_max` bound is every **detectable**
  class. Honest sizing is therefore per adversary class and quantified in §9.4: full
  lie-once deterrence for a single-Operator deployment needs `bond ≥ p·T` (all passive
  value) — usually uneconomic, which is precisely why the threshold model is primary
  and this bond is an optional, *fractional* backstop there. Below full coverage, the
  residual is exactly the +EV-above-bond risk of §12.1 item 3: a
  capital-efficiency-vs-coverage policy choice, not a free parameter.
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

### 9.2 Self-enforcing equivocation bonds (EOTS with pre-committed nonces)

The §9 nonce-reuse rejection, correctly scoped, leaves a door open — and Babylon's
finality providers walked through it first. Bitcoin consensus accepts any valid nonce
on a **transaction** signature, so Script cannot pin nonces there. But `A_k`, `σ_k`,
and `h_k` are **protocol artifacts**: their validity is judged by conforming clients,
sealers, and enclaves, and the protocol can therefore demand a specific nonce. That is
an **extractable one-time signature (EOTS)**, and it makes the double-sign class of
misbehavior *self-punishing on plain Bitcoin, today, with no judges, no token, and no
fork*:

- **Nonce commitment — one nonce per *(epoch, artifact role)*, never per epoch.** At
  genesis and at each heartbeat, every artifact signer (the operator threshold for
  `A_k`/`h_k`; each sealer for `σ_k`) publishes a Merkle commitment to its nonces
  `R_1 … R_H` covering the horizon to the next heartbeat plus margin (A19). For a
  FROST signer this is the aggregate nonce, fixed by the standard preprocessing round.
  **The index must be the (epoch, role) pair.** The operator threshold signs two
  artifacts in the same epoch — the attestation `A_k` and the commitment `h_k` — and
  those are different messages; reusing one `R_k` across both is a same-nonce,
  distinct-challenge pair, which is precisely the extraction condition above. An
  operator following a per-epoch schedule would therefore **leak its own key and burn
  its own bond during entirely honest operation** (A24). Role separation inside the
  signed message does *not* help: different messages are what drives the extraction.
  Commit `R_{k,A}`, `R_{k,h}`, `R_{k,σ}` as distinct leaves — or give each role its own
  key — and treat any role whose nonce index is not distinct as unsafe to deploy.
- **Validity rule.** An attestation, seal, or commitment for epoch `k` is valid
  **only if signed under the committed `R_k`.** A fresh-nonce signature is not
  "cheating detected" — it is *not an artifact at all*: every conforming verifier
  rejects it, so signing with a fresh nonce buys the cheater nothing. This is the move
  Script cannot make and conforming software can.
- **Extraction.** Two artifacts for the same epoch under the same `R_k` with
  **distinct challenges** leak the secret key by plain Schnorr algebra:
  `s₁ − s₂ = (e₁ − e₂)·x ⇒ x = (s₁ − s₂)/(e₁ − e₂)`. Anyone holding both artifacts —
  one honest gossip partner suffices — computes `x`. State the premise precisely: the
  division needs `e₁ ≠ e₂`, and *distinct messages give distinct challenges only under
  collision resistance of the challenge hash*. Equal challenges yield a zero
  denominator and extract nothing, so the mechanism's soundness rests on the hash, not
  on message inequality alone.
- **The bond that spends itself.** The equivocation bond `B_eq` is a taproot UTXO with
  exactly two paths: (i) a **pre-signed burn transaction** (output provably
  unspendable, plus a P2A anchor for fees — A20) whose signature is
  adaptor-encrypted under the artifact key `X`, completable by *anyone* who learns the
  extracted `x`; and (ii) owner reclaim behind a CLTV that clears the dispute window.
  Equivocate → any observer completes the adaptor and burns the bond. No referee
  co-signs anything. (The owner can always burn its own bond early; that is harmless.
  Babylon's production stack adds a covenant-emulation committee because its staking
  script needs richer paths; this construction imports only the EOTS + timelocked-bond
  primitive and needs none.)

**What this upgrades.** A13-class forks (`h_k` equivocation, double-allocating across
two off-chain histories), double-attestation of a passive balance, and double-sealing
all collapse from *"objective evidence a k-of-n referee quorum adjudicates"* to
**automatic bond loss triggered by any single observer**. The deterrent's honesty
assumption for the equivocation class drops from "≥1 honest referee in k-of-n" to
"≥1 honest gossiper + Bitcoin." The judicial federation survives for exactly two jobs:
routing *compensation* (a burn deters but does not repay — deployments wanting
restitution keep the §9 bond tranche), and the lie-once class below. A deployment that
wants slashing to *pay victims* instead of burning can re-sign the slashing
transaction each pulse toward the current `S_k` distribution, enforced as part of the
ceremony by the enclaves — more machinery, actual restitution; the burn variant is the
floor that works with zero ceremony weight.

**Honest limits, stated plainly.** (i) **Lie-once is immune**: a smash-and-grab that
attests once and steals on-chain never produces a second signature — the
contradiction is signature-vs-chain-fact, and no key leaks. That class stays with the
judicial/compensation layer and the threshold model. (ii) **Self-slash is a real
operational hazard** (A18): a crash-restart that re-signs an epoch, or an attacker
feeding a signer two versions of one epoch, burns an *honest* signer's bond — the
same state-loss discipline Lightning demands, and Babylon operators have paid this
tax in practice. (iii) **Burn ≠ compensation** — victims are made whole only by the
judicial tranche or the re-signed-slash variant. (iv) For a FROST signer the leak is
the *aggregate* key, so the burn hits the **collective** bond; attributing which
members colluded needs the accountability tooling of §9.3, after which individual
fidelity bonds are actionable via §9.1's paths.

### 9.3 Distributed-systems hardening (token-free)

Four results from the distributed-systems literature slot into PULSE without a token,
and together they reshape what the federations are trusted *for*:

- **The ceiling: fork-linearizability (SUNDR).** An untrusted coordinator serving
  state to clients who do not talk to each other can always *fork* their views — and
  can never *merge* a fork back undetected once they do talk. This is the
  twenty-year-old result that frames the whole design: fork **prevention** by the
  Operator is impossible without the victim's signature or a covenant (the §13.2
  trilemma, in DS terms), so **detection is the optimum** — and the right
  architecture is exactly what PULSE now has: make detection 1-of-N (this section),
  make punishment self-executing on detection (§9.2), and keep a judicial layer only
  for the classes detection cannot reach.
- **Witness-cosigned transparency log.** The `h_k` chain becomes an append-only
  Merkle log, certificate-transparency style: sealers sign successive *tree heads*
  (EOTS-bound, §9.2), and any two signed heads either verify a consistency proof or
  yield an extractable equivocation. Watchtowers and counterparties track O(1) heads
  and gossip them; a split-view (A13) now requires showing every gossip partner a
  consistent forgery *forever*, and any single crossing of the two views triggers the
  §9.2 burn. The seal set's trust profile sharpens to: **k-of-n for liveness, 1-of-N
  for safety-detection** — one honest (or merely leaky) witness breaks equivocation
  secrecy.
- **Proactive share refresh + duty rotation.** The FROST shares are proactively
  reshared on the heartbeat cadence (Herzberg-style PSS): a mobile adversary must
  compromise `t` members **within one refresh window**, not accumulate breaches over
  the pool's lifetime. Membership churn per window is rate-limited (A22), and
  per-epoch sealer duty subsets are drawn by public randomness (Bitcoin block hashes
  suffice) so an adaptive attacker cannot know far in advance which seats to target.
- **Erasure-coded data availability with sampling.** The artifact bundle is
  Reed-Solomon coded so that any `k` of `n` sealers reconstruct it in full; the epoch
  seal attests chunk possession, and members/watchtowers randomly sample chunks
  against the committed root over independent transports. The §8 invariant "the data
  only needs to exist *somewhere*" upgrades from replication-trust to coded
  redundancy with cheap probabilistic verification — the data-availability math
  without a data-availability token (its residual is A21).

### 9.4 Capital requirements, quantified

Parameters: pool TVL `T`; passive fraction `p` (passive value `P = p·T`); operator
threshold `t`-of-`n` with per-member fidelity bond `b_m`; seal set `k_s`-of-`n_s`
with per-seat bond `b_s`; referee quorum `k_r`-of-`n_r` with per-seat bond `b_r`
(bonded mode only); operator backstop `B_op = c·P` with coverage ratio `c ∈ [0,1]`;
equivocation bond `B_eq`; per-pulse net outflow cap `w_max`; rollback-exposure cap
`v_max` per anchor window and smallest relevant miner share `λ_min` (§7.4a, §8);
detection-to-halt lag `d` epochs (honest sealers: `d = 1`); settlement-gating gossip
lag `g` epochs; cost of capital `r`; annual pool volume `V`.

**Per adversary class** — what can be taken, what bounds it, and what capital answers
it:

| Class | Max extractable | Bounded by | Capital answer |
|---|---|---|---|
| Lie-once drain, threshold **intact** | 0 | enclave refusal (§9) — the theft cannot be signed | none |
| Lie-once drain, threshold **broken** | `P` (one transition; consensus checks only signatures) | nothing on-chain | `B_op = c·P` — optional, fractional backstop; `c = 1` is full coverage |
| Shorting inside a conserving lattice | ≤ `w_max · d` | §7.1a + carry-forward, checked at seal time | absorbed by `B_op`; ≈ 0 with honest sealers (unsealable, `d = 1`) |
| Equivocation / fork (double-sign class) | ≈ value released against fake finality during `g`: ≤ `w_max · g` through the pool, plus whatever external credit integrators extend off-seal | universal seal-gating + transparency log (§9.3) | `B_eq ≥ s · w_max · g` (safety factor `s` ≈ 2–3) — **self-executing** (§9.2) |
| Operator-set Sybil (fake threshold) | `P` | fidelity-bonded admission | `t · b_m ≥ P` |
| Seal-set Sybil (detection blackout inside the set) | enables the above to go unsealed-yet-unnoticed *inside* the set; public log gossip still detects outside it | bonded admission + log gossip | `k_s · b_s` ≥ an operational floor; secondary, because safety-detection is 1-of-N beyond the set (§9.3) |
| Stale-lattice rollback (A26) — needs no signer at all, only an old lattice | ≤ `v_max` | the anchor-age invariant (§7.4a); admission caps the exposure | a **fee reserve** ≥ `λ_min · v_max`, spent only if miners are actually bribed. The defence is a transaction, not compensation. The reserve sits in the fee wallets of the Operator, watchtowers and sealers, outside the pool; no script locks it and no one else can audit it (§7.4a). A bonded deployment may also treat a confirmed stale root with sealed successors as a compensable Operator fault |

**Worked example.** `T = 10` BTC, `p = 0.8` (`P = 8`), hourly pulses, daily heartbeat
(`D ≤ 24`), `w_max = 0.2` (2% of TVL per pulse), `g = 2`, `s = 2.5` ⇒ `B_eq = 1`;
threshold 5-of-9; sealers 3-of-7; referees 3-of-5 in bonded mode. For the anchor
window: `Δ = 432` blocks (about three days) and `margin_a = 288` (144 for a wallet
that syncs daily, 132 in case 90% of the hash power leaves the transition out, 12
for ancestry, fee spikes and reorgs), so the anchor deadline falls 144 blocks after
each anchor and the daily heartbeat meets it; `v_max = 1` and `λ_min = 0.01` ⇒ a fee
reserve of `0.01` BTC, and a pool that moves more than 1 BTC between members inside a
day lands its heartbeat early. (Earlier revisions gave this example a daily heartbeat
and no value for Δ. A daily heartbeat needs Δ to exceed one day by the whole of
`margin_a`.)

| Deployment | Locked capital | Against 10 BTC TVL |
|---|---|---|
| Single-Operator, fully bonded (`c = 1`): `B_op = 8`, referees `3 × 2.7` (quorum-corruption ≥ `B_op`), `B_eq = 1` | ≈ **17 BTC** | ≈ 170% — uneconomic beyond small pools; honest use is an explicit `c < 1` |
| FROST-in-TEE + fractional backstop (`c = 0.25`): `B_op = 2`, `B_eq = 1`, member fidelity `9 × 1.6 = 14.4` (from `5·b_m ≥ 8`), sealers `7 × 0.15 ≈ 1` | ≈ 18.4 nominal, **but the 14.4 is per-identity, not per-pool** | ≈ 30% pool-dedicated; **≈ 5–8% per pool across a 10-pool book** under the aggregation rule below |
| FROST-in-TEE, no capital backstop (`c = 0`): `B_eq = 1` + sealers ≈ 1 + amortized identity fidelity | ≈ 2 BTC pool-dedicated | ≈ 10–20% effective; the amount-risk left is an *uncompensated* threshold break (§9) |

The quantified conclusion: **EOTS deterrence is cheap** (`B_eq` scales with
`w_max · g`, not TVL — a ~1-BTC bond covers a 10-BTC pool's fork class), **and the
only expensive item is lie-once coverage**, which the threshold model makes optional.
The revision-2 intuition "cadence keeps bonds affordable" survives only in this
corrected form: cadence and `w_max` shrink the *detectable* classes that `B_eq` and
the backstop residual price; they do nothing against a fully broken signer set.

**Aggregation rule (A23).** Fidelity bonds are per-*identity*. Strict soundness
requires `b_identity ≥ Σ_pools (that identity's marginal share of stealable value)`
across every pool where it sits in a threshold or quorum. Anything less is
fractional-reserve deterrence — permissible only as an explicit, client-visible ratio;
clients exclude under-aggregated identities when counting `t`/`k`, exactly as they
refuse under-bonded pools.

**Liquidity, not loss.** For honest actors every satoshi above is opportunity cost,
not risk capital — bonds return at expiry. The floor on operator economics: annual
capital cost `≈ r · L` (with `L` the dedicated lock) must clear from fees, so the
minimum viable fee is `f ≥ r · L / V`. At `L = 3` BTC (backstop + `B_eq`),
`r = 5%/yr`, `V = 500` BTC/yr: `f ≥ 3` bps — the deterrence stack prices in at *basis
points* once the TVL-sized bond is optional.

**Renewal ladder.** Every bond is CLTV-timelocked, so coverage must be a *schedule*,
not a lump: split each bond into tranches with staggered expiries (spacing a multiple
of the heartbeat period), each tranche's reclaim path opening ≥ one full dispute
window after its nominal retirement, and replacement tranches posted **before** the
outgoing one enters that overlap. The client-side invariant is
`Σ(live tranches) ≥ required coverage at every height` — a lapsing ladder is treated
exactly like an under-bonded pool: wallets refuse pulses. This is what lets referees
and threshold members rotate out without coverage ever dipping.

## 10. Attack analysis appendix

Thirty-one adversarial findings shaped this spec — A1–A13 from the protocol
red-team, A14–A15 from the recourse analysis (§8a), A16–A17 from the revision-2
current-state exit analysis (§7.5), A18–A23 from the revision-2.1 red-team of the
self-enforcing bond and federation-hardening layers (§9.2–§9.4), A24–A25 from the
revision-2.2 formal-verification passes (§0), and A26–A31 from the revision-2.4
review of the stale-state race against Bitcoin's timelock and mining rules (§7.4a,
§8). Severity:
**CRITICAL** (breaks the safety claim), **HIGH** (loses funds or bricks exit under a
realistic adversary), **MED** (griefing/liveness/cost).

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
| A13 | **Off-chain `h_k` equivocation** — Operator shows different chains to different parties while committing one hash on-chain | MED | `h_k` must be co-signed by Operator + threshold of `M_k`, then sealed by the k-of-n seal set (§7.1 step 6): a fork necessarily carries contradictory signatures. EOTS-binding (§9.2) makes those signatures leak the signer's key — a fork is now **self-slashing** — and the transparency log (§9.3) makes it 1-of-N-detectable |
| A14 | **Buggy-honest conservation failure** — a ceremony bug makes `Σ(slots) ≠ value(U_k)` while `A_k` matches the buggy lattice, so there is no lie and no slashable evidence → silent unbacked loss | HIGH | Public finality predicate (§7.1a): conservation + consistency are recomputable from committed data and are a precondition of the seal; failure makes pulse `k` non-final and forces auto-exit on `k−1` |
| A15 | **Sub-dust no-exit** — balances below the 330-sat floor sit in a cooperative-only dust slot with no unilateral exit | MED | Named as a permanent, bounded recourse gap (§8a, §12.1 item 6); mitigated by client below-floor warnings and attesting the dust aggregate so over-debit is compensation-provable |
| A16 | **Live-Operator exit denial** — chain-extension displaces a *legitimate current-state* exit; each displacement carries balances forward correctly, so under revision 1 denial produced **no slashable evidence** (no equivocation, clean attestation); composes with expiry into theft-at-`renew` | HIGH (CRITICAL near `renew` absent §7.5) | Exit notices + **eviction-with-payout** (§7.5): displacing a noticed exit without the full on-chain payout is non-final, unsealable, enclave-unsignable, and bond-slashable; stalling instead is a visible fault → pool-wide auto-exit. Guarantee becomes **exit-or-payout** |
| A17 | **Current-root broadcast griefing** — the fully pre-signed, mesh-published root is broadcastable by anyone; a fee-bumped root forces mass exit (≈N× fee leverage) or a defensive displacement costing an on-chain tx + O(N) re-sign; retries ≈ free (supersedes the full-root case of A7, which revision 1 graded "harmless") | HIGH | §7.5 repricing, as corrected in revision 2.4: while the anchor is younger than Δ no root can be mined, so the only request to answer is a notice, and it is answered by a conforming eviction pulse — the member is **paid out in full and removed at their own request**; defense folds into heartbeat cadence (§7.2). The earlier wording ("unbumped roots are inert"; "a bumped root is answered") rested on relay policy and on a response window that does not exist once a root is mature — see A27 and A31 |
| A18 | **Accidental self-slash / induced double-sign** — a crash-restart re-signs an epoch under the committed nonce on a different message (the Lightning state-loss classic; Babylon operators have paid this tax), or an attacker feeds a signer two candidate versions of one epoch; an *honest* signer's key leaks and its bond burns | HIGH (operational) | Durable, attested sign-once state per epoch inside the enclave; restart resumes from the sealed chain head and never re-signs a sealed epoch; burn-not-transfer slashing removes the attacker's direct profit from inducing it (§9.2) |
| A19 | **Nonce-chain exhaustion / withholding** — the signer stops committing nonce chains (or "loses" them), so no valid attestation can exist and pulses stall | MED | Commitment horizon must cover ≥ next heartbeat + margin; a missing nonce commitment is a visible liveness fault — same class as a withheld seal: stall ⇒ auto-exit (§9.2, §7.3) |
| A20 | **Burn-tx pinning** — the pre-signed burn is fixed-fee; a cheater pins it or rides a fee spike through the reclaim CLTV, then reclaims the bond intact | MED | P2A anchor on the burn (any executor CPFPs); TRUC topology; reclaim CLTV sized ≥ dispute window + fee-spike margin (§9.2, §7.4) |
| A21 | **DA sampling eclipse** — a Sybilled mesh answers samples for data that is globally missing, faking availability to light verifiers | MED | Sampling over independent transports against the committed root; the seal remains a k-of-n *possession* receipt — sampling supplements it, never replaces it; sealers are bonded identities (§9.3) |
| A22 | **Reshare capture** — permissionless proactive resharing lets one entity accumulate `t` shares across refresh windows behind distinct facades | HIGH | Fidelity-bond-gated admission (§9.1, §9.4); rate-limited membership churn per refresh window (§9.3); Nakamoto-coefficient floor gating the "threshold-secured" label (§13.5) |
| A23 | **Correlated per-identity bonds** — one identity's fidelity bond, amortized across many pools, under-collateralizes a correlated theft across its whole book | MED→HIGH | The §9.4 aggregation rule: `b_identity ≥ Σ(marginal exposure)` across the identity's book, else the fractional-reserve ratio is computed, displayed, and the identity is excluded from `t`/`k` counts by conforming clients |
| A24 | **Honest-operation self-slash via per-epoch nonce reuse** — the operator threshold signs both `A_k` and `h_k` in epoch `k`; under a nonce schedule indexed by epoch alone, those two distinct messages share one committed `R_k`, which is exactly the EOTS extraction condition. A fully honest, protocol-following operator leaks its own key and its bond is burned by any observer. Distinct from A18, which is a crash/restart fault: this one fires on the specified happy path | CRITICAL (for any deployment of §9.2 as previously written) | Nonce index is the *(epoch, artifact role)* pair, not the epoch: commit `R_{k,A}`, `R_{k,h}`, `R_{k,σ}` separately, or give each artifact role its own key (§9.2). Message-level role separation is explicitly **not** a fix. Surfaced by the Lean formalization of §9.2, which showed extraction needs distinct challenges rather than distinct messages |
| A25 | **Pre-seal eviction window** — the payout obligation was keyed to the moment a notice *is sealed*, but the only leg that prevents a spend (threshold refusal, §7.5) was gated on the same condition. Between filing and the seal set's receipt the Operator owes nothing, so it may evict paying zero — with an intact signing policy and a fully healthy seal set — and may widen the window by stalling the sealers | HIGH | The obligation attaches on the **validly signed notice** presented to the signing threshold, which can check that signature without anyone's receipt; the seal governs third-party adjudication only (§7.5). Surfaced and its fix verified by the revision-2.2 expansion pass, which also showed the seal set cannot veto a spend at all |
| A26 | **Stale lattice on an aged anchor** — the exit-leaf delay counts from the confirmation of the pool output, not from an exit attempt. Once the last on-chain pool output is Δ blocks old, the root of *its* lattice is valid, and so is the first pending transition. If the stale root confirms first, every pulse since that output is void and the pool pays out the old table. Any member holding that lattice can do it alone, with a live and honest Operator, between two heartbeats. Earlier revisions graded the stale-lattice race as one "the honest side structurally wins" | CRITICAL | The anchor-age invariant (§7.4a): no pool output stays unspent for Δ blocks while a final pulse is pending on it. Kept by cadence (`heartbeatInterval + margin_a ≤ Δ`), admission (no off-chain pulse on an anchor at or past its deadline), and the extension duty (any holder of the pending chain lands it at the deadline). Model-checked at small bounds in `formal/Anchor.tla`; that a holder acts by the deadline and that miners include the transition within the margin are assumptions there, not results (§8) |
| A27 | **Relay policy mistaken for consensus** — "an unbumped root cannot confirm", first-seen ordering and fee replacement are mempool rules. A miner handed a transaction directly, and paid outside it, is bound by none of them; and miners can be paid to leave a transition out until a stale root matures | HIGH with A26; MED alone | Safety statements rest on consensus rules only: the delay, signatures, one spend per output (§8, "Miners: consensus versus relay policy"). Against censorship, `margin_a` carries a non-inclusion allowance. Against bribery, the rollback exposure is capped at `v_max` and a fee reserve ≥ `λ_min · v_max` backs the transition (§7.4a). The reserve is held outside the pool, where no script locks it and no other party can audit it; each holder counts its own, and a sealer without it refuses off-chain pulses. Against a majority of the hash power that also orphans other miners' blocks nothing holds, here or in any timelocked protocol |
| A28 | **A transition with no fee path** — the transition's fee is fixed when the cosigners sign and nothing said how it is paid or raised. A transition signed at a low fee cannot be confirmed on demand, which the heartbeat, the exit walk and the extension duty all require | HIGH | TRUC transition with one keyless anchor output; whoever broadcasts attaches the fee (§7.1 step 5). Consequence stated: pending transitions confirm about one per block through public relay, which bounds the sustained pulse rate and adds `D` blocks to an exit walk (§7.2, §7.3) |
| A29 | **Respendable deposit inputs** — a pending transition that spends a deposit is void if the depositor spends that deposit elsewhere first, and so is every transition after it: a rollback with no lattice involved and no timelock to wait for | HIGH | A pending transition spends only inputs whose owner cannot respend alone, each with a respend height. The transition confirms below that height: its respend deadline falls `margin_a` before it, earlier again for each pending transition beneath, and the three duties serve it like the anchor deadline. Anything else is admitted only in an on-chain pulse; the enclave refuses to co-sign a conflicting spend (§7.4a, §9). The protection of such an input before confirmation is the Operator threshold, not consensus — stated as such |
| A30 | **Time-denominated Δ** — a delay in 512-second units is measured on median-time-past, which miners producing six of eleven consecutive blocks can advance by about two hours, and it holds fewer blocks when blocks are slow | MED | Δ and `margin_a` are block counts; the validator rejects a time-based `exit` in a `pulse` leaf (§8, §11) |
| A31 | **No eviction window on an aged anchor** — the §7.5 response to a broadcast root assumed the Operator can still spend the pool output first. A root can be broadcast only when it is already mature, so there is no such window: on an idle pool whose anchor is older than Δ, one fee-bumped root unwinds the pool. This is A17 again, by a path §7.5 did not close | MED | Stated in §7.5 and §8. Deployments choose: a keep-alive heartbeat inside every `Δ − margin_a` blocks keeps the window open at the cost of an on-chain pulse per interval, or the pool accepts that it can be unwound while idle (§7.4a). Balances are safe either way |

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
          require(older(exit));            // Δ in blocks, from this output's confirmation
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

- **Anchor-age invariant (revision 2.4)**: the lattice template also carries
  `heartbeatInterval`, the inputs of `margin_a` (watch interval, ancestry depth,
  non-inclusion allowance, fee and reorg buffer), `v_max`, the fee reserve each
  duty holder is expected to keep, and whether the deployment runs a keep-alive
  heartbeat. `margin_a` is never given as one number. The validator computes it as
  the sum of its inputs, so a template cannot state a margin smaller than its own
  watch interval plus its allowance. The validator rejects configurations with
  `heartbeatInterval + margin_a > exit`, and an `exit` that is not a BIP 68 block
  count (type flag set), per §7.4a and §8. It cannot check that the declared inputs
  are true. A wallet or watchtower that looks at the chain less often than the
  declared watch interval is not one of the watchers the margin counts on, and the
  reserve is a declared figure, not a balance anyone can read (§7.4a).

- **Explicitly absent**: any "operator-only re-anchor" construct (A1), and any
  displacement path that skips the §7.5 payout.

Everything else — ceremony ordering, artifact retention, watchtower triggers, anchor
and respend deadlines, admission and the extension duty, TRUC packaging, seal-set
membership, coverage refusal — is SDK/ceremony policy, not compiler surface.

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
   should not grow. Since revision 2.4 the cadence also has a hard ceiling that is
   about safety, not cost: `heartbeatInterval ≤ Δ − margin_a` (§7.4a). What clients
   enforce is the admission rule — no off-chain pulse on an anchor at or past its
   deadline.
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
8. **Someone must watch, every anchor window.** Old lattices are never revoked. They
   are outrun: each stays harmless only because a successor transition confirms
   before its delay ends (§7.4a). That takes one honest holder of the pending chain
   who looks at the chain inside every anchor window and can pay a fee, and enough
   hash power that is not colluding to mine the transition within `margin_a` (§8).
   Discipline: the heartbeat cadence of item 2, the extension duty carried by
   watchtowers and the seal set, the exposure cap `v_max`, and its fee reserve. A
   pre-signed kickoff transaction between the pool output and the delayed leaf would
   replace the periodic deadline with one that starts only when someone moves, and
   would give §7.5 a response window on every anchor (A31), at the cost of one more
   transaction off-chain and on-chain for every pool output it protects. Revision
   2.4 records that alternative and does not adopt it.

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
   needing judges. (Revision 2.1 note: §9.2's EOTS bonds already deliver judge-free
   slashing for the *double-sign* class pre-GSR; what GSR adds is Script-verifiable
   slashing for general fraud predicates — "this payout was unbacked," "this
   displacement skipped the §7.5 payout" — which EOTS cannot express.)

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
| **Exit amount** (is the *number* in my slot right?) | **Enforced — not a clean 1-of-N** | The set whose honesty protects a passive member's balance in a pulse is `{Operator ∪ M_k}` — the Operator plus whoever is transacting. One honest member of that set refuses the bad pulse at the gate (§7.1 step 4b). But that set **excludes the victim** and can be **as small as two** (Operator + one transacting party — and if both collude, the honest count in it is zero). Below "1 honest in that set," safety degrades to the enforcement stack: enclave-threshold refusal in the primary model, *bonded compensation* in the backstop (§9) — an enforced layer, not a cryptographic one. For the *equivocation* subclass specifically, deterrence needs only **one honest observer**: EOTS-bound artifacts make any double-sign self-slashing (§9.2). |

**Both rows rest on a timing condition that revision 2.4 makes explicit.** Old
lattices are never revoked. Each one is outrun, by a successor transition that
confirms before its delay ends (§7.4a). So *which table gets paid out* is itself
1-of-N **on a deadline**: one holder of the pending chain — the Operator, a
watchtower, a sealer, an archiver, or the member — must look at the chain inside
every anchor margin and be able to pay a fee, and enough hash power must stand
outside any collusion to mine that transition within `margin_a` (§8). Nothing in it
depends on observing a mempool. If it fails, a sealed pulse can be undone by anyone
holding an older lattice, with the loss capped at `v_max`. Payment channels make the
same kind of assumption; earlier revisions of this document did not state it.

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
| A newer state beats an older one by extending the chain; nothing has to be revoked | The older lattice is never revoked, and its delay runs from confirmation: it matures on schedule whether or not anyone is attacking | **Latest-state-wins is 1-of-N on a deadline**: a heartbeat cadence inside Δ, any holder of the pending chain as fallback, exposure capped at `v_max` (§7.4a) |

### 13.4 Can anyone halt epoch creation?

Six vectors — five bounded, one intentional:

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
   four types defined in §9 (two conflicting `P_k` signatures; an `A_j` contradicted by
   a later lattice; a sealed exit notice displaced without payout; an EOTS extraction
   pair, §9.2 — the one class whose punishment also *executes itself* with no
   federation action) packaged as the §8a bundle; their exact wire serialization is
   fixed in the ABI (§11) — two
   implementations that disagree on the format would split the social layer, so the
   format must be fixed there, not left to convention.

5. **A member enforcing only their own balance cannot halt epoch creation.** Their
   tool is the §7.6 broadcast of their last good branch, which is an exit of their
   slot, not a missing signature. The conforming response is to pay that slot and
   continue (§7.5). Putting their key into `P_k` so that they "can enforce" would
   create the halt §7.6 rejects: the pool would stop whenever that node was down or
   refused. A false complaint withdraws only the complaining member.

6. **Anyone holding the current lattice can end an idle pool whose anchor is older
   than Δ** (A31). The root is mature, so it confirms before the Operator can answer
   with an eviction pulse, and the pool unwinds. Bounded the same way as vector 1:
   everyone leaves with their current balance, and nothing is stolen. A deployment
   closes it with the keep-alive heartbeat of §7.4a, at the price of an on-chain
   pulse per interval.

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
  universal support. Since revision 2.4 the transitions use the same plumbing (§7.1
  step 5), so the same caveat applies to the heartbeat and to the extension duty
  (§7.4a).
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
> finality off the block clock. **Equivocation anywhere in the artifact chain is
> self-slashing**: attestations, seals, and commitments are EOTS-bound, so a
> double-sign leaks the signer's key and lets anyone burn its plain-BTC bond — no
> judges, no token (§9.2) — leaving the judicial layer only lie-once compensation, and
> pricing the deterrence stack in basis points rather than TVL (§9.4). **Both models
> rest on a timing condition** (revision 2.4): old lattices are never revoked, only
> outrun, so a sealed pulse stays final only if the first unconfirmed transition
> beneath it confirms before the pool output it spends is Δ blocks old. The
> Operator's heartbeat does that in the normal case and any one holder of the pending
> chain otherwise, and it needs miners that include the transition within the margin
> (§7.4a, §8). Either way the amount — and the payout leg of exit-or-payout — rests
> on enclave-threshold or committee trust, not cryptographic
> self-custody — the **trilemma** (§13.2): with non-interactive passive members and no
> covenant, amount-safety *must* be enforced by a trusted layer rather than by
> consensus. Covenant-grade trustlessness of the amount is reachable only through the
> GSR annex (§12.2); absent any fork, this **trustless-mechanism / enforced-amount**
> model is the end state, and the design is engineered to be livable as exactly that.
