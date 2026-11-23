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
re-runs every TLC configuration of the earlier records and `NonceSchedule.lean`.

**Result:** two finite configurations of the new module are **model-checked** by TLC.
Four negative configurations and three reachability witnesses produce their intended
counterexamples. Nothing in this pass is **proved**. The two facts the result depends
on most are **assumed**: that some holder of the pending transitions broadcasts by
the deadline, and that miners include a broadcast transition within a bounded number
of blocks.

Source: [`research/pulse/recurrent-exit-pulse.md`](../recurrent-exit-pulse.md),
revision 2.4, SHA-256
`f821a1a8162e18eb2bd4cc630fc8fb966d7b9e9bc25e804cc34be57d53c749ad` — the file as
committed together with this version of the record. Section and finding numbers
below refer to that revision.

Tool identities, stated rather than assumed: `TLC2 Version 2026.11.19.180144 (rev:
bc1b506)` from the v1.8.0 release asset, jar SHA-256
`fdffef247f563ef6edbfd44958d2a82db79e7564e07cb673262d896353fa6713`. This is a third
build of TLC: neither the `957b23b2...` jar of the 2.1 record nor the `20322939...`
jar of the 2.2 record. OpenJDK 21.0.13, Linux x86_64. Lean 4.22.0 (commit
`ba2cbbf0`), the version both earlier records pinned.

The fifteen TLC configurations of the 2.2 record reproduce their distinct-state
counts exactly on this build. Their files, the three older modules and
`NonceSchedule.lean` are byte-identical to the hashes that record lists. `verify.py`
is the one inherited file that changed: it gained the nine `Anchor` cases.

## What this pass added

**New module `Anchor.tla` — finding A26.** The module models the race in the first
row of §8: a pending transition against the lattice of the pool output it spends,
once that output is confirmed. It has one pool, up to `MaxPulse` pulses, and abstract
blocks. There are four actions:

- `SealOff`: an off-chain pulse is signed and becomes final on its seal;
- `SealOn`: an on-chain pulse is signed and broadcast, and is final only when its
  transition confirms;
- `Broadcast`: anyone broadcasts the next pending transition;
- `Block`: the chain grows by one block, which holds the next pending transition, a
  mature lattice root, or neither. The adversary chooses which.

A root needs no broadcast and no fee to enter a block, so nothing in the model
depends on relay policy.

Three constants switch the defences of §7.4a on and off:

| Constant | `TRUE` means | Source |
|---|---|---|
| `Admission` | no off-chain pulse becomes final on an anchor at or past its deadline | §7.4a duty 2 |
| `ExtensionDuty` | a pending final transition is broadcast no later than the deadline height | §7.4a duty 3 |
| `BoundedInclusion` | a broadcast transition confirms within `Incl` blocks unless a conflicting spend confirms first | §7.4a non-inclusion allowance; §8 |

With all three on and `Margin > Incl`, `AnchorAge` and `NoStaleWin` hold in
`Anchor.cfg` and `AnchorWide.cfg` (**model-checked**). With any one of them off, or
with `Margin = Incl`, TLC reaches a confirmed stale root in at most eight states.

`AnchorNoDuty.cfg` is the shortest statement of A26, and it is the protocol as
revisions up to 2.3 specified it. One off-chain pulse is sealed, nobody lands it, and
the block at height Δ confirms the root of epoch 0. The only adversarial step in that
trace is the content of one block. On Bitcoin that step is a pre-signed root
broadcast with a fee-paying child.

**Three witnesses guard against a vacuous result.** "A stale root never confirms"
would also hold in a model where no root can confirm, where no pulse is ever pending
close to maturity, or where off-chain pulses never reach the chain.
`AnchorRootReachable.cfg`, `AnchorNearMaturityReachable.cfg` and
`AnchorLandingReachable.cfg` each assert one of those three under the parameters of
`Anchor.cfg`, and each is expected to fail. All three fail.

## Property ledger

"Model-checked" means the exact finite abstraction and bounds below. It is not a
proof for a larger Δ, more pulses, longer runs, or real Bitcoin executions.

| Property | Label and method | Source and assumptions |
|---|---|---|
| `Anchor.TypeOK` | **model-checked**, TLC, `Anchor.cfg` and `AnchorWide.cfg` | §7.4a; representation invariants, including `anchor ≤ final ≤ signed ≤ final + 1` |
| `AnchorAge` | **model-checked**, TLC, the same two configurations | §7.4a, the invariant: no final pulse is still pending when the lattice of the output under it can be mined in the next block. Holds under `Admission`, `ExtensionDuty`, `BoundedInclusion` and `Margin > Incl` |
| `NoStaleWin` | **model-checked**, TLC, the same two configurations | §8 first row, A26: the lattice of a superseded epoch never confirms. Same assumptions |

### Assumption ledger

- **Assumed — §6, BIP 68/112:** the root of `L_j` can be included in the block of height `anchorAt + Delta` and in no earlier block. Consensus enforces this on Bitcoin. Here it is the model's definition of maturity.
- **Assumed — §7.4a duty 3, §8 conditions 1–3:** at least one party holds the pending transitions, looks at the chain by the deadline height, and can pay to broadcast. Modeled as `ExtensionDuty`. Which party that is, how it got the data, and its funds are not modeled.
- **Assumed — §7.4a, §8 condition 4:** a broadcast transition that is still valid confirms within `Incl` blocks. Modeled as `BoundedInclusion`. This is an assumption about miners, not a Bitcoin guarantee. Miners with most of the hash power, or miners paid to wait, break it, and `AnchorCensored.cfg` shows what follows.
- **Assumed — §7.4a duty 2, §9:** no off-chain pulse is treated as final on an anchor at or past its deadline. Modeled as `Admission`, one guard that stands for the signing threshold, the seal set and every client. The trust-layer caveats of the earlier records apply unchanged: nothing about TEE attestation, enclave code or committee honesty is derived.
- **Assumed — §7.1 step 5:** at most one pending transition confirms per block.
- **Assumed:** signatures bind, a confirmed transaction is never reorganised out, and time is the block height.

## Bounds and adversary

`Anchor.cfg` explores Δ = 5, `Margin` = 3, `Incl` = 2, at most 3 pulses and 17
blocks. The anchor deadline falls two blocks after each anchor. The graph has 5,571
distinct states (7,696 generated, depth 24).

`AnchorWide.cfg` explores Δ = 9, `Margin` = 5, `Incl` = 4, at most 4 pulses and 32
blocks: 69,081 distinct states (108,423 generated, depth 41).

Heights are abstract block counts. The model has no amounts, so the exposure cap
`v_max` has no counterpart in it. Both configurations sit at `Margin = Incl + 1`. One
block less and the properties fail: `AnchorThinMargin.cfg` shows it for the first
set of bounds, and a run by hand with `Margin` = 4 shows it for the second.

The adversary chooses the content of every block, when pulses are sealed, whether
each is off-chain or on-chain, and when anything is broadcast. It cannot include a
root before maturity, confirm a transition that was never signed, or confirm more
than one transition per block. When the matching switch is on it also cannot make a
late off-chain pulse final, prevent the broadcast at the deadline, or keep a
broadcast transition out of more than `Incl − 1` consecutive blocks without
confirming a conflicting spend. Honest parties are not separate processes. Their
obligations appear as the guard on `SealOff` and the `DutyDue` guard on `Block`.

## Counterexamples and witnesses

Each row is a **model-checked counterexample at the stated bounds**, not an exploit
in shipped software. All seven use Δ = 5, so the root of epoch 0 is valid from block
5, and all but `AnchorThinMargin.cfg` have the first anchor deadline at height 2.

| Configuration | Expected violated property | Trace |
|---|---|---|
| `AnchorNoDuty.cfg` | `NoStaleWin` | Pulse 1 is sealed off-chain at height 0. Nobody broadcasts `T_1`. Block 5 confirms the root of epoch 0. 7 states. This is A26 as revisions up to 2.3 left it |
| `AnchorNoAdmission.cfg` | `NoStaleWin` | The pool idles to height 3, past the deadline. Pulse 1 is sealed off-chain there and broadcast at once. Block 4 leaves it out, which `Incl = 2` permits. Block 5 confirms the root of epoch 0. 8 states |
| `AnchorCensored.cfg` | `NoStaleWin` | Pulse 1 is sealed and broadcast at height 0. Blocks 1–4 leave it out. Block 5 confirms the root. 8 states. With no bound on inclusion, broadcasting early does not help (§8, A27) |
| `AnchorThinMargin.cfg` | `NoStaleWin` | `Margin = Incl = 2`, so the deadline is height 3. Pulse 1 is sealed at height 0 and broadcast at the deadline. Block 4 leaves it out. Block 5 confirms the root. 8 states. The margin has to exceed the inclusion bound |
| `AnchorRootReachable.cfg` | `RootNeverConfirms` (witness) | Nothing is sealed. Block 5 confirms the root of epoch 0, which is the current state. 6 states. A root can confirm in this model, and on an idle anchor nothing answers it (A31) |
| `AnchorNearMaturityReachable.cfg` | `PendingNeverNearMaturity` (witness) | Pulse 1 is sealed at height 0 and broadcast at the deadline. Block 3 leaves it out. At height 3 the transition is still pending and block 4 is the last block in which the root is invalid. 6 states |
| `AnchorLandingReachable.cfg` | `OffChainNeverLands` (witness) | Three off-chain pulses are sealed at height 0. Blocks 1, 2 and 3 confirm one transition each. 10 states |

Two further parameter sets were run by hand against the same module. They are not
part of `verify.py`, and can be repeated by editing the constants of `Anchor.cfg`.

- Δ = 12, `Incl` = 3, 5 pulses, 40 blocks: the three invariants hold with `Margin` = 7
  (127,369 distinct states) and with `Margin` = 4 (146,707). `AnchorAge` is violated
  with `Margin` = 3.
- Δ = 4, `Incl` = 1, 4 pulses, 20 blocks: they hold with `Margin` = 2 (6,966 distinct
  states). `AnchorAge` is violated with `Margin` = 1.

## Formalization decisions

1. **§6, §7.4a — the maturity height.** The source says a pool output that is "Δ blocks old" has a valid lattice. The model fixes the off-by-one from BIP 68: with the output confirmed in block `anchorAt`, the root can be included in block `anchorAt + Delta` and in none below (`RootValidNext`). Time-based delays are not modeled; revision 2.4 rejects them (A30).
2. **§7.4a, §7.1 step 3 — one output chain, no reorgs.** One pool and one chain of pool outputs; the hot-band sub-pool of the two-tier sharding is not modeled. `U_0` is confirmed at height 0 before the model starts. A confirmed transition or root is never undone, so the reorg term of `margin_a` has no counterpart.
3. **§7.1 step 5 — one transition per block, for everyone.** The source derives "about one per block" from relay policy, which does not bind a miner. The model applies the limit to the adversary too. A miner that confirmed several pending transitions in one block would start the race on a later output some blocks sooner. Every guard in the model compares heights relative to the anchor's own confirmation, so that race is expected to be the one already explored, shifted in time. That argument is not checked.
4. **§7.4a — `margin_a` as one number, and the watcher's timing.** `Margin` stands for the whole of `margin_a`; its components are not separate. The watcher acts at the deadline height itself, that is, with a watch interval of zero: the chain does not grow past a tip at or beyond the deadline until a pending final transition is broadcast. A broadcast at height `d` can confirm in block `d + 1` at the earliest, and the root is valid from block `d + Margin`. The relation the model checks is therefore `Margin > Incl`. A deployment's watch interval and ancestry depth come on top of that.
5. **§7.4a, §8 — `BoundedInclusion` in place of a probability.** The source's non-inclusion allowance is probabilistic (`q^n ≤ ε`). The model uses a deterministic bound: a broadcast transition that is still valid is in a block no later than `Incl` blocks after its broadcast, unless a conflicting spend confirms first. The exception matters. The block in which inclusion is due may hold a mature root instead, so the adversary keeps the transition out of `Incl − 1` blocks and still chooses the content of the next one. This is an environmental assumption of the same kind as the `Tick` deadline of `Exit.tla` (2.1 record, decision 7).
6. **§8 — the adversary owns block contents; there is no mempool.** The model has no mempool, fee, relay rule or bribe. A mature root can enter a block without ever being broadcast, which is the point of A27. A transition has to be broadcast before it can be included, and `Broadcast` is open to anyone at any time, so this restricts nobody. Findings A27 and A28 are not formalized; their only trace here is that nothing depends on relay behaviour.
7. **§7.4a duty 3 — the extension duty as a deadline.** `DutyDue` disables `Block` while a final pulse is pending, its first transition is not broadcast, and the tip is at or past the deadline. A mandatory deadline is stronger than weak fairness. It assumes that some holder exists, looks, and can pay (§8, conditions 1–3). No fairness is assumed of the Operator: its heartbeat is an early `Broadcast` and is never forced.
8. **§7.1a, §7.4a duty 2 — what "final" means, and one admission guard.** `final` counts the pulses a conforming client treats as final. An off-chain pulse becomes final when sealed; an on-chain pulse becomes final when its transition confirms. A single guard on `SealOff` stands for the three enforcers the source names (signing threshold, seal set, clients). The model does not separate a compromised enforcer from an honest one, so it says nothing about which of them is sufficient. `Admission = FALSE` is the protocol of revisions up to 2.3. The exposure cap `v_max` is not modeled.
9. **§7.4a duty 2, §7.1 step 4f — on-chain pulses only on an empty pending chain.** The source lets an on-chain pulse be proposed on an anchor at or past its deadline, whether or not other pulses are pending. `SealOn` is enabled only when nothing is pending, so at most one signed pulse is ever non-final (`signed ≤ final + 1`). A non-final pulse stacked on pending final ones adds no final pulse and cannot confirm before them, so it is expected to add nothing to these invariants. That expectation is not checked.
10. **§7.2, §7.4a duty 1 — the heartbeat and its parameter rule.** The Operator's heartbeat is not a separate action. It is `Broadcast` before the deadline. The rule `heartbeatInterval + margin_a ≤ Δ` is not checked, because the model has no `heartbeatInterval`. What is checked is the deadline that rule is meant to meet.
11. **§7.5, §7.6 — disputes and notices.** Not modeled. The duty's restriction to "sealed, undisputed pulses" has no counterpart: every final pulse is treated as undisputed. A31 appears only as the `AnchorRootReachable` witness, where a current root confirms on an idle anchor. The eviction window is not modeled.
12. **§8 first row — what counts as a stale win.** A confirmed root sets `staleWon` only if a final pulse is unconfirmed at that moment (`anchor < final`). A root that beats a non-final on-chain pulse is not a violation, following §7.4a ("the pulse did not happen"). A root on an idle anchor is the exit of the current state.
13. **§7.4a, A29 — non-pool inputs.** A transition spends only the pool output. Deposit inputs, respend heights and the ancestry term of `margin_a` are left out.
14. **Safety only.** No liveness or fairness property is checked. `CHECK_DEADLOCK` is off because the bounded horizon ends every behaviour. Nothing here shows that a pool makes progress under the admission rule.
15. **A history variable.** `landed` counts off-chain pulses that became final and later confirmed. No action reads it. It exists for the `AnchorLandingReachable` witness.

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
| `Anchor` | holds | 7,696 / 5,571, depth 24 (new) |
| `AnchorWide` | holds | 108,423 / 69,081, depth 41 (new) |
| `AnchorNoDuty` | `NoStaleWin` violated | 151 distinct (new) |
| `AnchorNoAdmission` | `NoStaleWin` violated | 325 distinct (new) |
| `AnchorCensored` | `NoStaleWin` violated | 308 distinct (new) |
| `AnchorThinMargin` | `NoStaleWin` violated | 259 distinct (new) |
| `AnchorRootReachable` | `RootNeverConfirms` violated (witness) | 107 distinct (new) |
| `AnchorNearMaturityReachable` | `PendingNeverNearMaturity` violated (witness) | 75 distinct (new) |
| `AnchorLandingReachable` | `OffChainNeverLands` violated (witness) | 479 distinct (new) |
| `NonceSchedule.lean` | 4 theorems, 0 axioms | exit 0 |
| `Pulse.lean` | 6 declarations, no `sorryAx` | not re-run this pass (needs mathlib) |

For a configuration that is expected to fail, the count is the number of distinct
states TLC had found when it stopped at the violation, with one worker.

`Pulse.lean` is unchanged and was **not** re-verified here. This environment has
Lean but no mathlib checkout, so `verify.py` skips it unless `--mathlib` is given.
Its result stands on the run recorded in the 2.1 record, not on this one.

## What is not formalized

**Not proved or model-checked in this pass:** findings A27–A31, beyond the narrow
projections named above; miner incentives and bribery, including the bound the source
cites from the MAD-HTLC analysis, which is taken from that paper and neither
re-derived nor modeled; fees, TRUC, P2A, package relay and pinning; reorgs;
time-based delays; the exposure cap `v_max` and the fee reserve; deposit inputs and
their respend heights; the keep-alive heartbeat; the heartbeat parameter rule;
disputes and notices; the two-tier hot band; and every liveness property.

`Anchor.tla` is a fourth module. It shares assumptions with `Ceremony.tla`,
`Exit.tla` and `Nonce.tla` by documentation only; no refinement or composition is
checked. In particular `Exit.tla` was written for revision 2.1 and has not been
revised against the corrected §7.5 of revision 2.4. It starts from a notice on a pool
output that is confirmed as the exit begins, and does not model an anchor that is
already older than Δ.

Everything the earlier records list as not formalized remains so. Trust-layer
assumptions remain **assumed** oracles.

## Reproduction

```sh
python3 verify.py --tlc /absolute/path/to/tla2tools.jar --lean /absolute/path/to/lean
```

Add `--mathlib /absolute/path/to/mathlib` to include `Pulse.lean`, as described in
the 2.1 record. The runner checks each TLC configuration for its expected exit code
and its **named** result, so a negative case that fails for a syntax or runtime
error is rejected. It uses temporary state directories and leaves no trace files.

## Artifact SHA-256

New and changed files of this pass. Every other model, configuration and proof file
in this directory matches the hash given in the 2.2 record. The `verify.py` hash in
that record is the earlier version of the file.

```text
a2962a45c07f08741b25038215c373e133864fbb20654aa2475a1548657742d3  Anchor.tla
cb3bbed71ae039cfb18495a10788b19cf966f7024087b0c0bdda3d9a6160d880  Anchor.cfg
3bcfd3a0e45b0a4c3ce3a49145820f9bea8ebf06d0e09ab460ba983623561540  AnchorCensored.cfg
c1aa14a945e054c34ad5eb99a8466ec017466780b31daf179c4989aeaf4ba644  AnchorLandingReachable.cfg
9d832402e53a38c40a059216a402a3c8b0fe7f50724aeec0f33830f526d07bda  AnchorNearMaturityReachable.cfg
16f7bff061ad0d6ae69d09b146b7d31e398188adf1d078152ad79d80064b2b16  AnchorNoAdmission.cfg
bf2375f1708d8343a69ac2ab258cb406918b9fc1b64171ef3a55a0b7164a5d88  AnchorNoDuty.cfg
644f0d7a9031d177d9186640c9647b1c058b4106815c9149a8ba9875355ad7ac  AnchorRootReachable.cfg
dee8f057086c1c1f9fc75dccd235e755c10c21556066b614a8e3c360296e5011  AnchorThinMargin.cfg
17662f6a690ded31cba3dcd5460b72a64d7261d540de623ddfdea61e32f35b9e  AnchorWide.cfg
e645571b6a6c46103fa074c42b8d62f84a54ba72964e986b357e74cc695b67f1  verify.py
```
