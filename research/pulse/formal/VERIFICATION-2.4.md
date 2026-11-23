1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.

# Verification record — anchor-age pass, revision 2.4

Extends the revision-2.2 record ([`VERIFICATION-2.2.md`](VERIFICATION-2.2.md)), which
extends the revision-2.1 record ([`README.md`](README.md)). This pass adds one TLA+
module, `Anchor.tla`, for finding A26 and the anchor-age invariant of §7.4a. It also
re-runs every TLC configuration of the earlier records and both Lean files.

**Result:** two finite configurations of the new module are **model-checked** by TLC.
Five negative configurations and five reachability witnesses produce their intended
counterexamples. Nothing new is **proved** in this pass; the Lean declarations of the
earlier records are re-checked unchanged. The two facts the result depends on most
are **assumed**: that some holder of the pending transitions broadcasts by the
deadline, and that miners include a broadcast transition within a bounded number of
blocks. Bitcoin enforces neither.

Source: [`research/pulse/recurrent-exit-pulse.md`](../recurrent-exit-pulse.md),
revision 2.4, SHA-256
`e6b0043fbfd08fe240f2affa37a63b7b3034c82c25570d02f5c843a9419d74f7` — the file as
committed together with this version of the record. Section and finding numbers
below refer to that revision.

Tool identities, stated rather than assumed: `TLC2 Version 2026.11.19.180144 (rev:
bc1b506)` from the v1.8.0 release asset, jar SHA-256
`fdffef247f563ef6edbfd44958d2a82db79e7564e07cb673262d896353fa6713`. This is a third
build of TLC: neither the `957b23b2...` jar of the 2.1 record nor the `20322939...`
jar of the 2.2 record. OpenJDK 21.0.13, Linux x86_64. Lean 4.22.0 (commit
`ba2cbbf0`) and mathlib commit `79e94a093aff4a60fb1b1f92d9681e407124c2ca` (tag
`v4.22.0`), the versions the earlier records pinned.

The fifteen TLC configurations of the 2.2 record reproduce their distinct-state
counts exactly on this build. Their files, the three older modules,
`NonceSchedule.lean` and `Pulse.lean` are byte-identical to the hashes that record
lists. `verify.py` is the one inherited file that changed: it gained the twelve
`Anchor` cases.

## Revised after review

This is the second version of this record. The first described a narrower
`Anchor.tla` (SHA-256 `a2962a45c07f08741b25038215c373e133864fbb20654aa2475a1548657742d3`)
with nine configurations. What changed:

- **The model is wider.** The first version let at most one signed pulse be
  non-final, let a block confirm at most one transition, and had the watcher act at
  the deadline height itself. It recorded, as expectations it had not checked, that
  the first two restrictions lose nothing. All three restrictions are gone
  (decisions 3, 4 and 9). Every count below comes from the wider model, and the two
  expectations are now checked at the stated bounds.
- **Three configurations were added:** `AnchorSlowWatch` (negative),
  `AnchorStackReachable` and `AnchorBurstReachable` (witnesses).
- **`Pulse.lean` was re-run** against the pinned mathlib. The first version skipped
  it.
- **The ledgers name the assumptions next to the properties.** `AnchorAge` and
  `NoStaleWin` rest on a guard that stops the model's chain until a holder has
  broadcast. Bitcoin has no such guard. The property ledger, the assumption ledger
  and decision 7 now say so in the same place as the result.
- **Three gaps are listed that were not.** Deposit inputs and their respend
  deadlines, the fee reserve, and what `Exit.tla` does not cover are spelled out
  under "What is not formalized".

The source changed between the two versions as well. It now says that a seal is
necessary for finality and never sufficient (§7.1a, §7.4a duty 2), that a deposit
input puts a respend deadline on the pending chain (§7.4a), that nothing on-chain
enforces the fee reserve (§7.4a, §9), and that the validator computes `margin_a`
from its inputs (§11). Of these, the finality rule is the one `Finalize` models
(decision 9). The others have no formal counterpart.

## What this pass added

**New module `Anchor.tla` — finding A26.** The module models the race in the first
row of §8: a pending transition against the lattice of the pool output it spends,
once that output is confirmed. It has one pool, up to `MaxPulse` pulses, and abstract
blocks. There are four actions:

- `Sign`: the next transition is signed, at any time and on any anchor. Nothing
  becomes final;
- `Finalize`: a client treats the next signed pulse as final. With `Admission` on,
  only while the anchor is before its deadline;
- `Broadcast`: anyone broadcasts the next pending transition;
- `Block`: the chain grows by one block, which holds a mature lattice root, or the
  next `k ≥ 1` signed pending transitions in order, or neither. The adversary
  chooses which.

An off-chain pulse is `Sign` followed by `Finalize`. An on-chain pulse is `Sign`
alone: it becomes final when a block confirms it, or before that if a transition
beneath it confirms and `Finalize` is enabled again on the younger anchor.

Neither a root nor a transition needs a broadcast or a fee to enter a block, so
nothing in the model depends on relay policy. `Broadcast` matters to the honest side
only: it is the event `BoundedInclusion` counts from.

Three constants switch the defences of §7.4a on and off. Each is an **assumption**
about parties or miners. None is something Bitcoin enforces.

| Constant | `TRUE` means | Source |
|---|---|---|
| `Admission` | no pulse is treated as final on an anchor at or past its deadline | §7.4a duty 2 |
| `ExtensionDuty` | a pending final transition is broadcast no later than `Watch − 1` blocks after the deadline height | §7.4a duty 3 |
| `BoundedInclusion` | a broadcast transition confirms within `Incl` blocks unless a conflicting spend confirms first | §7.4a non-inclusion allowance; §8 |

With all three on and `Margin ≥ Watch + Incl`, `AnchorAge` and `NoStaleWin` hold in
`Anchor.cfg` and `AnchorWide.cfg` (**model-checked**). With any one of them off, or
with `Margin` one block short of `Watch + Incl`, TLC reaches a confirmed stale root
in at most nine states.

`AnchorNoDuty.cfg` is the shortest statement of A26, and its trace is one that
revisions up to 2.3 permitted. One pulse is signed and treated as final, nobody
lands it, and the block at height Δ confirms the root of epoch 0. The only
adversarial step in that trace is the content of one block. On Bitcoin that step is a
pre-signed root broadcast with a fee-paying child.

**Five witnesses guard against a vacuous result.** "A stale root never confirms"
would also hold in a model where no root can confirm, where no pulse is ever pending
close to maturity, or where pulses that were final off-chain never reach the chain.
`AnchorRootReachable.cfg`, `AnchorNearMaturityReachable.cfg` and
`AnchorLandingReachable.cfg` each assert one of those three under the parameters of
`Anchor.cfg`, and each is expected to fail. Two more show that the wider steps are
taken. `AnchorStackReachable.cfg` asserts that no signed, non-final pulse ever sits
on pending final ones on an anchor at or past its deadline. `AnchorBurstReachable.cfg`
asserts that no block confirms more than one transition. All five fail.

## Property ledger

"Model-checked" means the exact finite abstraction and bounds below. It is not a
proof for a larger Δ, more pulses, longer runs, or real Bitcoin executions.

| Property | Label and method | Source and assumptions |
|---|---|---|
| `Anchor.TypeOK` | **model-checked**, TLC, `Anchor.cfg` and `AnchorWide.cfg` | §7.4a; representation invariants, including `anchor ≤ final ≤ signed` |
| `AnchorAge` | **model-checked**, TLC, the same two configurations. Conditional on three **assumed** switches | §7.4a, the invariant: no pulse treated as final is still pending when the lattice of the output under it can be mined in the next block. Holds only with `Admission`, `ExtensionDuty` and `BoundedInclusion` on and `Margin ≥ Watch + Incl`. `ExtensionDuty` carries the most weight: it is a guard that stops the model's chain until a holder has broadcast, and Bitcoin does not wait (decision 7). Without it the property fails (`AnchorNoDuty.cfg`). It also fails without `BoundedInclusion` (`AnchorCensored.cfg`) and without `Admission` (`AnchorNoAdmission.cfg`) |
| `NoStaleWin` | **model-checked**, TLC, the same two configurations. Conditional on the same three **assumed** switches | §8 first row, A26: the lattice of a superseded epoch never confirms. Same assumptions, same three counterexamples |

### Assumption ledger

- **Assumed — §6, BIP 68/112:** the root of `L_j` can be included in the block of height `anchorAt + Delta` and in no earlier block. Consensus enforces this on Bitcoin. Here it is the model's definition of maturity.
- **Assumed — §7.4a duty 3, §8 conditions 1–3:** at least one party holds the pending transitions, looks at the chain at least once in every `Watch` blocks, and can pay to broadcast. Modeled as `ExtensionDuty`, through the guard `DutyDue`: while a final pulse is pending and its first transition is unbroadcast, the model produces no block beyond height `deadline + Watch − 1`. **Both positive results rest on this guard.** It does not describe Bitcoin, where blocks arrive whether or not anyone has acted. It asserts that a holder acts in time and derives nothing about it. Which party that is, how it got the data, and whether its fee wallet still holds the reserve of §7.4a are not modeled. Nothing on-chain enforces that reserve either.
- **Assumed — §7.4a, §8 condition 4:** a broadcast transition that is still valid confirms within `Incl` blocks. Modeled as `BoundedInclusion`. This is an assumption about miners, not a Bitcoin guarantee. Miners with most of the hash power, or miners paid to wait, break it, and `AnchorCensored.cfg` shows what follows.
- **Assumed — §7.4a duty 2, §9:** no pulse is treated as final on an anchor at or past its deadline. Modeled as `Admission`, one guard on `Finalize` that stands for the signing threshold, the seal set and every client. Everyone in the model sees the same chain, so an enclave shown an old tip by its host (§9), or a client whose view is behind, has no counterpart. The trust-layer caveats of the earlier records apply unchanged: nothing about TEE attestation, enclave code or committee honesty is derived.
- **No longer assumed — §7.1 step 5:** that at most one pending transition confirms per block. The first version of the model held the adversary to that relay-policy limit. A block may now confirm any number of signed transitions (decision 3).
- **Assumed:** signatures bind, a confirmed transaction is never reorganised out, and time is the block height.

## Bounds and adversary

`Anchor.cfg` explores Δ = 5, `Margin` = 3, `Watch` = 1, `Incl` = 2, at most 3 pulses
and 17 blocks. The anchor deadline falls two blocks after each anchor. The graph has
17,408 distinct states (30,834 generated, depth 27).

`AnchorWide.cfg` explores Δ = 9, `Margin` = 6, `Watch` = 2, `Incl` = 4, at most 4
pulses and 32 blocks: 251,011 distinct states (562,634 generated, depth 45).

Heights are abstract block counts. The model has no amounts, so the exposure cap
`v_max` and the fee reserve have no counterpart in it. Both configurations sit at
`Margin = Watch + Incl`. One block less and the properties fail:
`AnchorThinMargin.cfg` and `AnchorSlowWatch.cfg` show it for the first set of
bounds, and a run by hand with `Margin` = 5 shows it for the second.

**These bounds are not sizing guidance.** `Margin`, `Watch` and `Incl` are small
integers chosen to keep the state space finite. A deployment's `margin_a` is the sum
§7.4a gives: its real watch interval, its ancestry depth, its non-inclusion
allowance and its buffers. The relation checked here, `Margin ≥ Watch + Incl`, is
the part of that sum the model can see. A margin sized as "more than the inclusion
bound" with the watch interval left out is the configuration `AnchorSlowWatch.cfg`
shows failing.

The adversary chooses the content of every block, when pulses are signed, when a
signed pulse is treated as final, and when anything is broadcast. It can put several
pending transitions in one block, broadcast or not. It cannot include a root before
maturity or confirm a transition that was never signed. When the matching switch is
on it also cannot make a pulse final on an anchor at or past its deadline, prevent
the broadcast that is due `Watch − 1` blocks after the deadline, or keep a broadcast
transition out of more than `Incl − 1` consecutive blocks without confirming a
conflicting spend. Honest parties are not separate processes. Their obligations
appear as the guard on `Finalize` and the `DutyDue` guard on `Block`.

## Counterexamples and witnesses

Each row is a **model-checked counterexample at the stated bounds**, not an exploit
in shipped software. All ten use Δ = 5, so the root of epoch 0 is valid from block
5, and all but `AnchorThinMargin.cfg` have the first anchor deadline at height 2.

Two numbers are reported for each of these configurations, and they measure
different things. "N states" in the table below is the length of the trace TLC
printed, initial state included. The count under "Full results" is the number of
distinct states TLC had explored when it stopped at the violation.

| Configuration | Expected violated property | Trace |
|---|---|---|
| `AnchorNoDuty.cfg` | `NoStaleWin` | Pulse 1 is signed and treated as final at height 0. Nobody broadcasts `T_1`. Block 5 confirms the root of epoch 0. 8 states. This is A26 as revisions up to 2.3 left it |
| `AnchorNoAdmission.cfg` | `NoStaleWin` | Pulse 1 is signed at height 0 and the pool idles to height 3, past the deadline. There the pulse is treated as final and broadcast at once. Block 4 leaves it out, which `Incl = 2` permits. Block 5 confirms the root of epoch 0. 9 states |
| `AnchorCensored.cfg` | `NoStaleWin` | Pulse 1 is signed, treated as final and broadcast at height 0. Blocks 1–4 leave it out. Block 5 confirms the root. 9 states. With no bound on inclusion, broadcasting early does not help (§8, A27) |
| `AnchorThinMargin.cfg` | `NoStaleWin` | `Margin = Incl = 2`, so the deadline is height 3. Pulse 1 is signed and treated as final at height 0 and broadcast at the deadline. Block 4 leaves it out. Block 5 confirms the root. 9 states. The margin has to exceed the inclusion bound |
| `AnchorSlowWatch.cfg` | `NoStaleWin` | `Margin = 3` as in `Anchor.cfg`, but `Watch = 2`: the holder's first look at or after the deadline, height 2, may come at height 3. Pulse 1 is signed and treated as final at height 0 and broadcast at height 3. Block 4 leaves it out. Block 5 confirms the root. 9 states. A margin sized for a watcher that is always on does not cover one that looks every second block |
| `AnchorRootReachable.cfg` | `RootNeverConfirms` (witness) | Nothing is signed. Block 5 confirms the root of epoch 0, which is the current state. 6 states. A root can confirm in this model, and on an idle anchor nothing answers it (A31) |
| `AnchorNearMaturityReachable.cfg` | `PendingNeverNearMaturity` (witness) | Pulse 1 is signed and treated as final at height 0 and broadcast at the deadline. Block 3 leaves it out. At height 3 the transition is still pending and block 4 is the last block in which the root is invalid. 7 states |
| `AnchorLandingReachable.cfg` | `OffChainNeverLands` (witness) | Three pulses are signed and then treated as final at height 0. Block 1 confirms all three transitions. 8 states |
| `AnchorStackReachable.cfg` | `NoStackOnPendingFinal` (witness) | Two pulses are signed at height 0 and only the first is treated as final. Blocks 1 and 2 are empty. At height 2 the anchor is at its deadline with pulse 1 final and pending and pulse 2 signed, not final, on top of it. 6 states. Signing pulse 2 at height 2 instead leads to the same state |
| `AnchorBurstReachable.cfg` | `OneConfirmationPerBlock` (witness) | Two pulses are signed at height 0. Block 1 confirms both transitions. Neither was broadcast. 4 states |

`AnchorNoAdmission.cfg`, `AnchorThinMargin.cfg` and `AnchorSlowWatch.cfg` end on the
same step. At height 4 the broadcast transition is due for inclusion (`InclDue`
holds) and the root of epoch 0 is mature, and the adversary's block holds the root.
That is the exception stated in decision 5: the inclusion bound does not outrank a
conflicting spend that is already valid. The three traces that fail by one block
all take it.

Four further parameter sets were run by hand against the same module. They are
**model-checked** in the same sense, but they are not part of `verify.py`. They can
be repeated by editing the constants of `Anchor.cfg`.

- Δ = 12, `Incl` = 3, `Watch` = 1, 5 pulses, 40 blocks: the three invariants hold
  with `Margin` = 7 (789,902 distinct states) and with `Margin` = 4 (919,445).
  `AnchorAge` is violated with `Margin` = 3.
- The same with `Watch` = 3: they hold with `Margin` = 6 (919,445 distinct states).
  `AnchorAge` is violated with `Margin` = 5.
- Δ = 4, `Incl` = 1, `Watch` = 1, 4 pulses, 20 blocks: they hold with `Margin` = 2
  (52,989 distinct states). `AnchorAge` is violated with `Margin` = 1.
- The bounds of `AnchorWide.cfg` with `Margin` = 5: `AnchorAge` is violated.

At every set of bounds tried, the invariants hold with `Margin = Watch + Incl` and
fail one block below it. Nothing here shows that the same relation holds at other
bounds.

## Formalization decisions

1. **§6, §7.4a — the maturity height.** The source says a pool output that is "Δ blocks old" has a valid lattice. The model fixes the off-by-one from BIP 68: with the output confirmed in block `anchorAt`, the root can be included in block `anchorAt + Delta` and in none below (`RootValidNext`). Time-based delays are not modeled; revision 2.4 rejects them (A30).
2. **§7.4a, §7.1 step 3 — one output chain, no reorgs.** One pool and one chain of pool outputs; the hot-band sub-pool of the two-tier sharding is not modeled. `U_0` is confirmed at height 0 before the model starts. A confirmed transition or root is never undone, so the reorg term of `margin_a` has no counterpart.
3. **§7.1 step 5 — one transition per block binds the honest side only.** The source derives "about one per block" from relay policy, which does not bind a miner. `MineNext` therefore lets a block confirm the next `k` signed pending transitions for any `k ≥ 1`, whether or not they were broadcast. The honest side gets no such help: `BoundedInclusion` promises one transition, the first pending one, and only after its broadcast. Each confirmed output starts its own Δ at the block that confirmed it, so a burst leaves the last of them as a fresh anchor. The first version of this model held the adversary to one per block and recorded, unchecked, that this loses nothing. The wider step is now in the state space (`AnchorBurstReachable.cfg`), and the invariants hold with it at the stated bounds.
4. **§7.4a — `margin_a` as `Margin`, `Watch` and `Incl`.** `Margin` stands for the whole of `margin_a`. Two of its components are constants of their own, because the result depends on them: `Watch`, the watch interval, and `Incl`, the non-inclusion allowance. Ancestry depth and the fee and reorg buffers have no counterpart (decisions 2 and 13). A holder that looks at the chain once in every `Watch` blocks takes its first look at or after the deadline at most `Watch − 1` blocks past it, and the model's chain does not grow beyond that height until a pending final transition is broadcast. `Watch = 1` is the source's always-on watchtower, which acts at the deadline height itself. A broadcast at height `b` can confirm in block `b + 1` at the earliest and is due by block `b + Incl`, and the root is valid from block `deadline + Margin`. The relation the model checks is therefore `Margin ≥ Watch + Incl`.
5. **§7.4a, §8 — `BoundedInclusion` in place of a probability.** The source's non-inclusion allowance is probabilistic (`q^n ≤ ε`). The model uses a deterministic bound: a broadcast transition that is still valid is in a block no later than `Incl` blocks after its broadcast, unless a conflicting spend confirms first. The exception matters. The block in which inclusion is due may hold a mature root instead, so the adversary keeps the transition out of `Incl − 1` blocks and still chooses the content of the next one. This is an environmental assumption of the same kind as the `Tick` deadline of `Exit.tla` (2.1 record, decision 7).
6. **§8 — the adversary owns block contents; there is no mempool.** The model has no mempool, fee, relay rule or bribe. A mature root or a signed transition can enter a block without ever being broadcast, which is the point of A27. `Broadcast` exists for the honest side: it is the event `BoundedInclusion` counts from, and it is open to anyone at any time. Beyond this adversary, findings A27 and A28 are not formalized.
7. **§7.4a duty 3 — the extension duty as a deadline that stops the chain.** `DutyDue` disables `Block` while a final pulse is pending, its first transition is not broadcast, and the tip is `Watch − 1` blocks past the deadline. A mandatory deadline is stronger than weak fairness, and it is not something Bitcoin provides: real blocks arrive whether or not a holder has acted. The guard asserts §8 conditions 1–3 — some holder exists, looks, and can pay — and proves nothing about them. Every positive result in this record is conditional on it, and `AnchorNoDuty.cfg` is what the same model does without it. No fairness is assumed of the Operator: its heartbeat is an early `Broadcast` and is never forced.
8. **§7.1a, §7.4a duty 2 — what "final" means, and one admission guard.** `final` counts the pulses a conforming client has treated as final. `Finalize` is that act, taken for the next signed pulse in order, so finality is a prefix as in the source. A pulse also becomes final when a block confirms it. Once a pulse is in `final` it stays there: the model has no step by which a client takes its reliance back. That is the cautious reading of §7.1a, which tells a client to treat pending pulses as unsettled once the anchor reaches its deadline. Whoever relied on them earlier is still exposed, and the invariants are about that party. A single guard stands for the three enforcers the source names (signing threshold, seal set, clients). The model does not separate a compromised enforcer from an honest one, and it has one view of the chain, so it says nothing about which of them is sufficient. `Admission = FALSE` is the protocol of revisions up to 2.3. The exposure cap `v_max` is not modeled.
9. **§7.4a duty 2, §7.1 step 4f — off-chain and on-chain pulses.** The source speaks of two kinds of pulse, named in the proposal. The model has no kinds. A pulse is off-chain if it passes `Finalize` before a block confirms it, and on-chain if it does not. Any number of signed, non-final pulses may sit on top of pending final ones, on any anchor, and a signed pulse may pass `Finalize` later if the anchor is then before its deadline. That is the source's rule: a seal is necessary for finality and never sufficient, and a pulse sealed on an old anchor counts once a transition has confirmed and it is admissible on the younger one. The first version of the model allowed one non-final pulse at most, and only on an empty pending chain, and recorded, unchecked, that stacking adds nothing to these invariants. The stacked state is now reachable (`AnchorStackReachable.cfg`), and the invariants hold with it at the stated bounds.
10. **§7.2, §7.4a duty 1 — the heartbeat and its parameter rule.** The Operator's heartbeat is not a separate action. It is `Broadcast` before the deadline. The rule `heartbeatInterval + margin_a ≤ Δ` is not checked, because the model has no `heartbeatInterval`. What is checked is the deadline that rule is meant to meet.
11. **§7.5, §7.6 — disputes and notices.** Not modeled. The duty's restriction to "sealed, undisputed pulses" has no counterpart: every final pulse is treated as undisputed. A31 appears only as the `AnchorRootReachable` witness, where a current root confirms on an idle anchor. The eviction window is not modeled.
12. **§8 first row — what counts as a stale win.** A confirmed root sets `staleWon` only if a pulse treated as final is unconfirmed at that moment (`anchor < final`). A root that beats pulses which are signed and not final is not a violation, following §7.4a ("the pulse did not happen"). A root on an idle anchor is the exit of the current state.
13. **§7.4a, A29 — non-pool inputs.** A transition spends only the pool output. Deposit inputs, respend heights, respend deadlines and the ancestry term of `margin_a` are left out. A respend deadline can fall before the anchor deadline, and it can bind a transition deeper in the pending chain than the first. Neither interaction is checked anywhere in this bundle.
14. **Safety only.** No liveness or fairness property is checked. `CHECK_DEADLOCK` is off because the bounded horizon ends every behaviour. Nothing here shows that a pool makes progress under the admission rule.
15. **A history variable.** `landed` counts the pulses that were final before a block confirmed them. No action reads it. It exists for the `AnchorLandingReachable` witness.

## Full results

| Configuration | Expected | Result |
|---|---|---|
| `Ceremony` | holds | 4,126 states / 1,124 distinct, depth 20 |
| `CeremonyFaults` | holds | 5,865 / 1,632 |
| `Exit` | holds | 457 / 176 |
| `Nonce` | holds | 15 / 12 |
| `ExitFiledNoticeFix` | holds | 1,001 / 352 |
| `CeremonyNoFinalityGate` | `FinalitySound` violated | 349 distinct |
| `CeremonyLastSealed` | `LastSealedSpendable` violated | 246 distinct |
| `CeremonySealOnly` | `NoTheft` violated | 303 distinct |
| `CeremonyBadOrder` | `LatticeBeforeTransition` violated | 40 distinct |
| `ExitSealOnly` | `NoTheft` violated | 3 distinct |
| `ExitUnboundedMining` | `NoSweepUnderExit` violated | 99 distinct |
| `ExitUnsealedNotice` | `NoTheft` violated | 3 distinct |
| `ExitNoFairness` | `ExitOrPayout` violated | 176 distinct |
| `NoncePerEpoch` | `NoKeyLeak` violated | 4 distinct |
| `NonceCrash` | `NoKeyLeak` violated | 9 distinct |
| `Anchor` | holds | 30,834 / 17,408, depth 27 (new) |
| `AnchorWide` | holds | 562,634 / 251,011, depth 45 (new) |
| `AnchorNoDuty` | `NoStaleWin` violated | 431 distinct (new) |
| `AnchorNoAdmission` | `NoStaleWin` violated | 718 distinct (new) |
| `AnchorCensored` | `NoStaleWin` violated | 775 distinct (new) |
| `AnchorThinMargin` | `NoStaleWin` violated | 716 distinct (new) |
| `AnchorSlowWatch` | `NoStaleWin` violated | 716 distinct (new) |
| `AnchorRootReachable` | `RootNeverConfirms` violated (witness) | 121 distinct (new) |
| `AnchorNearMaturityReachable` | `PendingNeverNearMaturity` violated (witness) | 223 distinct (new) |
| `AnchorLandingReachable` | `OffChainNeverLands` violated (witness) | 243 distinct (new) |
| `AnchorStackReachable` | `NoStackOnPendingFinal` violated (witness) | 88 distinct (new) |
| `AnchorBurstReachable` | `OneConfirmationPerBlock` violated (witness) | 14 distinct (new) |
| `NonceSchedule.lean` | 4 theorems, 0 axioms | exit 0 |
| `Pulse.lean` | 6 declarations, no `sorryAx` | exit 0 |

For a configuration that is expected to fail, the count is the number of distinct
states TLC had found when it stopped at the violation, with one worker. It is not
the length of the counterexample, which the trace table above gives.

`Pulse.lean` is unchanged. Its SHA-256,
`014d13e4cf279a3e8ddc01b8e7f7ba53d565e4db37d58078f9311f19d5865eb8`, is the one both
earlier records give. It was re-verified in this pass with `lake env lean` from a
checkout of the pinned mathlib: exit status 0, six declarations reported, no
`sorryAx`. Its output is line for line the one [`Verification.md`](Verification.md)
preserves from the 2.1 pass; the axioms listed are `propext`, `Classical.choice`
and `Quot.sound`. The file formalizes §9.2 and the restricted game of §13.2, and
revision 2.4 changes neither section. The re-run therefore shows that the file
still checks under the pinned toolchain. It covers nothing that revision 2.4 adds.

## What is not formalized

**Not proved or model-checked in this pass:** findings A27–A31, beyond the narrow
projections named above; miner incentives and bribery, including the bound the source
cites from the MAD-HTLC analysis, which is taken from that paper and neither
re-derived nor modeled; fees, TRUC, P2A, package relay and pinning; reorgs;
time-based delays; the exposure cap `v_max`; a chain view that is stale or supplied
by a host; the keep-alive heartbeat; the heartbeat parameter rule; disputes and
notices; the two-tier hot band; and every liveness property.

**Deposit inputs and respend deadlines (A29).** §7.4a puts a second deadline on the
pending chain. A transition that spends a deposit has to confirm below that
deposit's respend height, and its respend deadline can fall before the anchor
deadline and can bind a transition that is not the first pending one. `Anchor.tla`
has no input other than the pool output (decision 13), so there is no model-checked
evidence for how the two deadlines interact, or for the claim that the three duties
serve both. The respend-deadline rule of §7.4a is argued in prose only.

**The fee reserve.** The extension duty needs a holder that can pay, and the source
sizes a reserve for it. The model has no fees and no amounts, and `ExtensionDuty`
simply assumes the broadcast happens. The source is explicit that nothing on-chain
enforces the reserve: a drained fee wallet is not detectable by the protocol. So
this is an assumption twice over, once in the model and once in the design.

**`Exit.tla` and the aged anchor (A31).** `Anchor.tla` is a fourth module. It shares
assumptions with `Ceremony.tla`, `Exit.tla` and `Nonce.tla` by documentation only;
no refinement or composition is checked. `Exit.tla` was written for revision 2.1
and is unchanged. It starts from a notice on a pool output that is confirmed as the
exit begins, with the Operator still able to answer inside Δ. It has no anchor that
is already older than Δ. The case A31 describes, a root that is mature the moment
it is broadcast, with no eviction window, therefore has no model-checked
counterpart for the exit walk. The six `Exit` configurations still produce their
recorded results, and those results say nothing about §7.3 step 2 or §7.5 as
revision 2.4 rewrites them. The only formal trace of A31 is
`AnchorRootReachable.cfg`.

Everything the earlier records list as not formalized remains so. Trust-layer
assumptions remain **assumed** oracles.

## Reproduction

```sh
python3 verify.py --tlc /absolute/path/to/tla2tools.jar --lean /absolute/path/to/lean \
    --mathlib /absolute/path/to/mathlib
```

`--mathlib` may be left out, and `Pulse.lean` is then skipped. With it, `lake` has
to be on `PATH` and the checkout is prepared as the 2.1 record describes. The runner
checks each TLC configuration for its expected exit code and its **named** result,
so a negative case that fails for a syntax or runtime error is rejected. It uses
temporary state directories and leaves no trace files.

## Artifact SHA-256

New and changed files of this pass. Every other model, configuration and proof file
in this directory matches the hash given in the 2.2 record. The `verify.py` hash in
that record is the earlier version of the file.

```text
93f77290e49f90fafdc257acb8e87119eb36ec1d9f67ee1e4a08c939336c18a3  Anchor.tla
4d1edc6949e9ccf78399422fb0a005fbcb79ee39e7d828d05b962cee642f7491  Anchor.cfg
31d88ebb5bc7b37c812045d20c4dcafd3c56774321b89f1cfc1eff85ffbfea56  AnchorBurstReachable.cfg
deb2549e34efe359a726ff1b8f7fdf7f43fd610ecb49ce7dc44e9870527c2b3f  AnchorCensored.cfg
0f13e1e7b7b3c405ba1b2090806d179d9866196e42c821f0e795a93cedfb0674  AnchorLandingReachable.cfg
c353663aa476f0e4a322190f180fbba4aab810d9b0ba557bf5e8814dd8a047c3  AnchorNearMaturityReachable.cfg
e83af78aba9cd956d22cd2e7e50a7f07d2c33c2bd3c2ec268985eb03a8b8d70e  AnchorNoAdmission.cfg
9b05094ad943886acf6e52bdfa37dfc0319123826717d1e6cda361daaf9fc6f6  AnchorNoDuty.cfg
01e58403d6449ce491110afad672e80dc1949595dd814d053776a1a4d203fb3e  AnchorRootReachable.cfg
66e9f89361463752632e1d49d2d7a21fe5b99bda98657d2307d50a78b22470c6  AnchorSlowWatch.cfg
4accd9043a58b04fa4ba2390b29ed1b49244f66c331deae1f95dc313655c7cf3  AnchorStackReachable.cfg
377a7c341577cd8b225fb458facb5ea56a58cb274fb5cc95c93835e50c3c0912  AnchorThinMargin.cfg
7a0e6adf2b515d0b2214fe45806938a390aa21a0626afb87aa1b164099dc7e16  AnchorWide.cfg
3e7096aed8f409b3dd7793021f147e78ef2035a4e43e06e83e09ca6f5daa35ce  verify.py
```
