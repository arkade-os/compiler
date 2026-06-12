# PULSE — Recurrent Unilateral Exit for Emulator-Enforced Pools

**Pooled Unilateral-exit via Lattice State Epochs.**

A protocol for giving open-membership pool contracts on Arkade a *standing* unilateral
exit, enforced by recurrent state updates between the transacting parties. This document
is a design specification: it defines the protocol lifecycle, the trust model, the
attack analysis that shaped it, and the compiler surface that would standardize it. It
proposes no code changes; the compiler-facing sections are future work.

Cross-references: [`options.md`](./options.md) (two-tapleaf model, exit/renew options),
[`bonds.md`](./bonds.md) (pool covenants and today's exit asymmetry),
[`arkade-primitives-spec.md`](./arkade-primitives-spec.md) (recursive covenants,
emulated introspection).

---

## 1. ELI5

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
| **msg.senders `M_k`** | The parties whose balances change in pulse `k` (online by definition; typically 1–2) |
| **Transition tx `T_k`** | The plain, fully-signed, broadcastable transaction implementing pulse `k` |
| **Epoch key `P_k`** | MuSig2 aggregate of *ephemeral, sign-once* keys of `{Operator} ∪ M_k`. Passive members are **never** in the aggregate |
| **Exit lattice `L_k`** | Fully pre-signed splitting tree spending `U_k`'s exit leaf into one slot per member, per `S_k` |
| **Slot** | A lattice leaf output: `SingleSig(memberPk)` with the member's own exit CSV |
| **Continuity attestation `A_k`** | Operator-signed Schnorr over the Merkle root of the *full* table `S_k` |
| **Pulse commitment `h_k`** | `H(h_{k-1} ‖ S_k ‖ txid(T_k) ‖ root(L_k) ‖ A_k)`, co-signed by Operator + threshold of `M_k`, committed in the Operator's next on-chain batch |
| **Heartbeat** | A pulse whose transition tx lands on-chain, re-anchoring the pool tip with a freshly built full lattice |
| **Δ (`exit`)** | The exit leaf's relative timelock — the contest window |
| **`renew`** | The pool's absolute expiry, after which the Operator's sweep path eventually matures |

## 5. Interactivity requirements

| Role | Signs | Online when | Notes |
|---|---|---|---|
| **Passive member** | **Nothing after deposit** | Own deposit/withdraw only | Must *retain* exit artifacts (or delegate to a watchtower); interactivity is borne by transactors |
| **msg.senders** | Lattice + transition + `h_k`, in **one ceremony** (two MuSig2 rounds, one network round-trip) | Their own transaction | Typically 1–2 parties |
| **Operator** | Every pulse + attestation + commitment | Always-on | Absence ⇒ freeze ⇒ everyone exits via lattices |
| **Watchtower** | Nothing (lattice is fully pre-signed) | Monitoring only | Can broadcast *anyone's* exit; non-custodial; delegable |
| **Heartbeat participants** | Operator + that pulse's msg.senders only | — | Passive members are **not** needed at heartbeats |
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
   `requiredCoverage(initialTVL)`.
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

1. **Propose.** A transition `T_{k+1}` is proposed, changing only the msg.senders'
   balances. The Operator emulates the contract's introspection covenant against it.
   `S_{k+1} = S_k` with only `M_{k+1}` slots changed.
2. **Attest.** The Operator signs the continuity attestation `A_{k+1}` over the Merkle
   root of the *entire* `S_{k+1}` — every member, not just msg.senders. One Schnorr
   signature; O(1) on-chain footprint; O(log N) inclusion proofs per member.
3. **Lattice first.** The parties build and MuSig2-sign `L_{k+1}` under
   `P_{k+1} = MuSig2(Operator, M_{k+1})`:
   - Root spends `U_{k+1}`'s exit leaf; the tree splits into per-member slots
     (`SingleSig(memberPk)` + the member's own exit CSV).
   - **Dedicated per-claimant anchor outputs** (P2A) on every node; TRUC (v3)
     transaction topology; lattice txs are non-RBF — fee bumping is anchor/CPFP only.
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
4. **Verification gate.** Each msg.sender verifies, *before releasing anything*:
   - (a) its own slot value in `L_{k+1}`;
   - (b) **every passive slot equals the `S_k` carry-forward**, Merkle-checked against
     `A_{k+1}`;
   - (c) the Operator bond still covers the pool's passive TVL (§9);
   - (d) **its own lattice branch is in its hands** — *"no lattice in my hands, no
     pulse."* Publication to the relay mesh alone is never trusted.
5. **Transition signing.** Only now do Operator + msg.senders sign `T_{k+1}`
   (SIGHASH_ALL, nSequence final).
6. **Commit.** `h_{k+1}` is **co-signed by the Operator + a threshold of `M_{k+1}`**
   (so the Operator cannot unilaterally author forks) and committed in the Operator's
   next on-chain batch transaction. Full artifacts `(S_{k+1}, T_{k+1}, L_{k+1},
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

### 7.2 Heartbeat (D2) — there is no cheap operator-only re-anchor

A forced design finding: re-anchoring `U_k` under a new on-chain output changes its
outpoint, and every pre-signed signature (the transitions *and* the lattice) commits to
the old outpoint under SIGHASH_ALL. Re-signing would require the deleted ephemeral
keys. Therefore, **without `SIGHASH_ANYPREVOUT`, the heartbeat must itself be a
cooperative on-chain pulse**:

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
watchtower) that discards these has no fraud proof.

## 9. Bond and enforcement layers

**Critical separation: the exit never touches the emulator.** The lattice is plain
pre-signed Bitcoin transactions. An emulator shutdown — including the Operator killing
its own attested execution environment — is a **freeze, not a theft**: watchtowers trip
on the missed heartbeat commitment and every member exits on L1 with zero Operator
involvement. The bond exists only as a *deterrent against active collusion-theft*
(§8, row 3), and its enforcement must therefore be independent of the Operator's
infrastructure:

- **A `checkSigFromStack` punishment leaf would be circular — rejected.**
  `checkSigFromStack` is an *emulated* Arkade opcode, not Bitcoin L1 consensus (it is
  consensus on Liquid, and proposed for Bitcoin as BIP-348). An Arkade-native bond
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
- **Rejected alternative, documented honestly:** forced-nonce-reuse key-leak punishment
  (make any second `P_k` signature leak the aggregate secret) does **not** work with
  plain CHECKSIG: a cheater simply signs with a fresh nonce, and Script cannot pin the
  nonce without CSFS.
- **Sizing and client enforcement.** The bond is per-pool and TVL-tracking. Wallets
  refuse to participate in pulses of an under-bonded pool (`bond <
  requiredCoverage(passiveTVL)`) — client-side policy informed by a bond-reference
  field in the ABI (§11).
- **Upgrade path.** BIP-348 CSFS on Bitcoin makes slashing L1-native and the
  federation evaporates. See §12 for what CTV/APO additionally close.

## 10. Attack analysis appendix

Thirteen adversarial findings shaped this spec. Severity: **CRITICAL** (breaks the
safety claim), **HIGH** (loses funds or bricks exit under a realistic adversary),
**MED** (griefing/liveness/cost).

| # | Attack | Severity | Resolution in this spec |
|---|---|---|---|
| A1 | **Operator-only heartbeat re-anchor voids all pre-signed exits** — new outpoint ⇒ txid change ⇒ every SIGHASH_ALL signature dead; re-signing needs deleted keys | CRITICAL | Heartbeat is a full cooperative on-chain pulse with complete lattice rebuild (§7.2). No cheap re-anchor construct exists or may be exposed |
| A2 | **Silent-majority gap** — lattice signers are only Operator + `M_k`; nothing structurally forces correct passive slots; for 1-party pulses this degrades to "trust the Operator" | CRITICAL | Continuity attestation `A_k` over the *full* table each epoch + carry-forward verification by every msg.sender (§7.1 step 4b) + cross-epoch fraud proof slashable on the bond (§9) |
| A3 | **"Publish the lattice" is unenforceable** — Operator signs last, can withhold mesh publication or the on-chain commitment selectively | HIGH | "No lattice *in my hands*, no pulse" (local possession gate, §7.1 step 4d); chained `h_k` dependency turns withholding into a visible stall that trips auto-exit (§7.1 step 6, §7.3) |
| A4 | **MuSig2 N-of-N brittleness** — one signer aborts mid-ceremony ⇒ epoch key can never sign again ⇒ if the lattice were incomplete, the exit leaf is permanently unspendable | HIGH | Lattice signed *before* the transition (§7.1 order); abort ⇒ pulse abandoned on still-protected `U_k`; passive members excluded from the aggregate (minimal signer set) |
| A5 | **Theft beats the race** — a colluding theft tx has no CSV; the lattice waits Δ; the defender is structurally slower | HIGH | Stated honestly: chain-extension dominance only kills *stale* lattices; anti-theft is the equivocation proof + bond (§8, §9), not a race |
| A6 | **Anchor pinning on shared lattice nodes** — occupying a shared internal node's anchor grief-blocks every member exiting through it | HIGH | Dedicated per-claimant anchors; TRUC topology; minimized shared-anchor surface in the lattice template (§7.1 step 3); heartbeat-SLA compensation from the bond |
| A7 | **Partial-lattice broadcast griefing** — broadcasting the root but no branches forces the pool into exit mode | MED | Monotonically harmless: the tree is fully pre-signed; any member pushes their own branch with CPFP; delays only, priced to the griefer via fees |
| A8 | **"Deletion attestations" are unfalsifiable** — you cannot prove a key was deleted | HIGH | Deletion demoted to hygiene; the trust anchor is equivocation detection, which requires **mandatory artifact retention** (§8); a resurrected key that signs anything new creates the fraud proof |
| A9 | **Renew-sweep races in-flight exits** — sweep maturity near `renew` can consume `U_k` under a maturing lattice | HIGH | Compiler-enforced ordering invariant `sweepDelay ≥ Δ + margin` creating a lattice-exclusive window (§7.4) |
| A10 | **Bond circularity & sizing** — emulated slashing dies with the emulator; fixed bonds get out-run by TVL | HIGH | Judicial federation bond, evidence-based, emulator-independent (§9); TVL-tracking sizing with client-side refusal; heartbeat cadence caps at-risk-per-epoch ≤ bond |
| A11 | **O(N) lattice re-sign cascade** — SIGHASH_ALL invalidates all descendants on any root change; "incremental subtree reuse" does not survive the txid cascade | MED→HIGH | Costed honestly (§7.1 step 3): O(N) compute for 2–3 parties, O(1) interactivity; two-tier hot-band sharding as the scaling valve; APO named as the real fix (§12) |
| A12 | **Depositor verification is not enough** — verifying your slot at deposit does not protect later epochs you never sign | MED | Deposit completes only with branch + attestation + bond-coverage check in hand; continued protection explicitly requires a watchtower (§5, §8) |
| A13 | **Off-chain `h_k` equivocation** — Operator shows different chains to different parties while committing one hash on-chain | MED | `h_k` must be co-signed by Operator + threshold of `M_k` (§7.1 step 6): a fork necessarily carries someone's contradictory signature |

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
  cooperative-only dust slot), continuity-attestation format, and a bond reference for
  client-side coverage checks.

- **Timelock invariant**: the compiler rejects configurations where the operator sweep
  could mature inside the exit window (`sweepDelay < exit + margin`), per §7.4.

- **Explicitly absent**: any "operator-only re-anchor" construct (A1).

Everything else — ceremony ordering, artifact retention, watchtower triggers, TRUC
packaging, bond-coverage refusal — is SDK/ceremony policy, not compiler surface.

## 12. Open problems and the covenant upgrade path

Stated honestly: PULSE is the strongest construction available *without* new Bitcoin
consensus features, and these are its residual gaps.

1. **Passive carry-forward is attestation-bonded, not consensus-enforced.** A passive,
   watchtower-less member who retains nothing degrades to bonded-Operator trust.
   **CTV (BIP-119)** would let the covenant *consensus-enforce* slot carry-forward
   across epochs, closing A2 cryptographically.
2. **Heartbeats need a quorum.** Because re-anchoring invalidates SIGHASH_ALL
   signatures, every heartbeat is a ceremony. **APO (BIP-118 /
   `SIGHASH_ANYPREVOUT`)** would let pre-signed lattices float across re-anchors,
   enabling operator-free heartbeats and true incremental (O(log N)) lattice updates
   (closing A1 and A11).
3. **The defender is slower than the thief.** The theft path has no CSV; the lattice
   waits Δ. Only the bond deters collusion; if `theft value > bond`, collusion of the
   Operator + all of `M_k` is profitable. Heartbeat cadence must cap at-risk-per-epoch
   accordingly. APO-style zero-delay defensive paths would close this structurally.
4. **Bond slashing is federated until CSFS.** **BIP-348 (`OP_CHECKSIGFROMSTACK`)** on
   Bitcoin L1 makes the equivocation proof consensus-verifiable inside the bond's
   punishment leaf, removing the judicial federation entirely.
5. **Key deletion is unprovable** — inherent; no covenant fixes it. The design
   therefore never relies on it (§8, A8).

### Trust statement

> PULSE converts open-membership pool custody from **trusted-Operator** to
> **bonded-Operator + equivocation detection**, contingent on member liveness
> (watchtowers) and retained exit artifacts. The **exit guarantee is
> emulator-independent**: pure pre-signed L1 transactions — Operator or emulator
> shutdown means freeze, never theft. The **theft deterrent** is economic: a
> federation-held bond slashed on objective equivocation evidence, with federation
> trust confined to the deterrent layer until BIP-348 makes slashing L1-native.
> Active members in recent epochs get 1-honest-of-(msg.senders ∪ Operator) plus the
> bond. Passive, watchtower-less members degrade to bonded-Operator trust.
> Covenant-grade trustlessness requires CTV/APO — §12 names exactly which residual
> gap each one closes.
