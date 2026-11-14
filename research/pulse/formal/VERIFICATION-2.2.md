1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.

# Verification record — expansion pass, revision 2.2

Extends the revision-2.1 record. Every result below was produced in this pass; the
five configurations inherited from that record reproduce their published state
counts exactly (1,124 / 1,632 / 176 / 349 / 246 / 303 / 3 / 99 / 176) on a
**different TLC build**, which independently corroborates them.

Tool identities differ from the earlier record and are stated rather than assumed:
`TLC2 Version 2026.09.15.164612 (rev: 8585374)` from the v1.8.0 release asset,
jar SHA-256 `20322939d1b55bb0a3f674ab34bb69b87c711a6b35559d32445cb7d7f6d3bb58` —
**not** the `957b23b2...` jar of the earlier record, so the two runs used different
bytes of TLC. Java 21.0.10, Linux x86_64. Lean 4.22.0 (commit `ba2cbbf0`), the
same version the earlier record pinned.

## What this pass added

**New module `Nonce.tla` — the A24 finding, previously unmodeled.** Signatures and
the group are black boxes; the module tracks only which (nonce, message) pairs a
signer emits, and flags the `Pulse.eots_extract` hypothesis being met. `Nonce.cfg`
(per-(epoch,role) indexing, durable sign-once log) holds `NoKeyLeak`.
`NoncePerEpoch.cfg` violates it in **three states with no adversary and no crash** —
sign `A_0`, sign `h_0`, one shared nonce, two messages — which is the
honest-operation self-slash. `NonceCrash.cfg` violates it via the A18 crash/restart
re-sign. This is the first executable evidence for the revision-2.2 nonce rule.

**New module `NonceSchedule.lean` — the A24 side condition, mathlib-free.** Four
theorems, each compiling with **no axioms at all** (not `propext`, not
`Classical.choice`): an injective nonce commitment plus one-message-per-slot rules
out self-extraction; the revision-2.1 per-epoch schedule provably cannot discharge
the one-message-per-slot obligation and provably self-extracts; the revision-2.2
per-(epoch,role) schedule provably does not. It states formally that
`eots_extract` is an asset against an equivocator and a liability against your own
schedule, and names the condition separating the two.

**`CeremonyBadOrder.cfg` — closes a vacuity in the earlier record.**
`LatticeBeforeTransition` was previously enforced by the model's own construction:
`badOrder` was unreachable and no configuration could falsify it, so checking it
confirmed self-consistency rather than the A4 property. A `TrustedOrder` constant
now admits an implementation that releases a signed `T` from the `attested` phase,
before the lattice exists; the mutant reaches `transitions = {1}` with
`lattice = {0}` and violates the invariant. With `TrustedOrder = TRUE` the model is
unchanged, reproducing 1,124 distinct states exactly.

**`TimelockOrdering` demoted to `ASSUME`.** TLC's own constant-level warning applied:
it contains no variables and evaluates to TRUE, so it tested the chosen parameters,
not the protocol. It is now an `ASSUME`, per that warning, and is no longer listed
as a checked invariant. The genuinely checked timelock property is
`NoSweepUnderExit`.

**`sealers` in `Exit.tla` made load-bearing — and it found something.** The variable
was dead: `Stall` mutated it and no guard read it. Modeling the notice-sealing step
instead (`SealNotice`, requiring a 2-of-3 quorum, gated by `NoticePreSealed`)
exposed **A25**, a new safety finding: §7.5 keys the payout obligation to the moment
a notice **is sealed**, so between filing and sealing the Operator owes nothing, and
`ExitUnsealedNotice.cfg` reaches `paid = 0, status = "lost"` with an intact payout
policy and a fully healthy seal set. `ExitFiledNoticeFix.cfg` verifies the fix: when
the signing policy refuses a short payout against the member's **own signed notice**
rather than waiting for the seal set's receipt, `NoTheft` holds again. The enclave
can check that signature itself; the seal governs third-party adjudication, not the
enclave's refusal.

## Full results

| Configuration | Expected | Result |
|---|---|---|
| `Ceremony` | holds | 4,126 states / 1,124 distinct, depth 20 |
| `CeremonyFaults` | holds | 5,865 / 1,632 |
| `Exit` | holds | 457 / 176 |
| `Nonce` | holds | 15 / 12 |
| `ExitFiledNoticeFix` | holds (A25 fix) | 352 distinct |
| `CeremonyNoFinalityGate` | `FinalitySound` violated | 349 distinct |
| `CeremonyLastSealed` | `LastSealedSpendable` violated | 246 distinct |
| `CeremonySealOnly` | `NoTheft` violated | 303 distinct |
| `CeremonyBadOrder` | `LatticeBeforeTransition` violated | 40 distinct (new) |
| `ExitSealOnly` | `NoTheft` violated | 3 distinct |
| `ExitUnboundedMining` | `NoSweepUnderExit` violated | 99 distinct |
| `ExitUnsealedNotice` | `NoTheft` violated | 3 distinct (new, A25) |
| `ExitNoFairness` | `ExitOrPayout` violated | 176 distinct |
| `NoncePerEpoch` | `NoKeyLeak` violated | 4 distinct (new, A24) |
| `NonceCrash` | `NoKeyLeak` violated | 9 distinct (new, A18) |
| `NonceSchedule.lean` | 4 theorems, 0 axioms | exit 0 |
| `Pulse.lean` | 6 declarations, no `sorryAx` | not re-run this pass (needs mathlib) |

`Pulse.lean` is unchanged and was **not** re-verified here — this environment has
Lean but not a mathlib checkout, so `verify.py` skips it unless `--mathlib` is
given. Its earlier record stands on its own run, not on this one.

## Standing limits, unchanged by this pass

The two modules still share assumptions by documentation, not by a machine-checked
refinement relation, and `Nonce.tla` is a third unrelated module. Everything the
earlier record listed as not formalized remains so: dynamic membership, general-N
trees, heartbeat/virtual-chain construction, multiple simultaneous notices, bond
construction and compensation, DA sampling, log gossip, proactive resharing,
capital adequacy, and the GSR annex. §13.2's trilemma is still statement-only; what
`restricted_trilemma` proves is a game whose theft-authorization is an explicit
premise, not an impossibility result. Trust-layer assumptions (`TrustedGate`,
`TrustedPayout`, `EnclaveHonorsFiled`, honest sealers) remain **assumed oracles** —
no TEE, attestation, hardware or committee-honesty claim is proved anywhere here.

## Artifact SHA-256

Covers what this pass ran. `Pulse.lean` sits in the same directory,
unchanged and not re-run here; its hash is `014d13e4cf279a3e8ddc01b8e7f7ba53d565e4db37d58078f9311f19d5865eb8`, matching the
earlier record.

```text
370e5f23f199d6d45d6ed183a4216e28306f64abc7df6b187a993c5b411e37c7  Ceremony.cfg
3c17a3bf93091bb7d0c7065629c7f2ffcadea6becbaa802367678709bcddf7e3  Ceremony.tla
59aa9c97e66d64f34a08068a88fe8036d51cff83f50713d0b4acdb2ac68c0fbe  CeremonyBadOrder.cfg
a1afffb201560955714daf37f785ac9255ec5809376667254eb816065f35877e  CeremonyFaults.cfg
ccfab9b5f035e648874842d9f2e1fbe50a0dc0b6ef997efc9b329403409f047e  CeremonyLastSealed.cfg
0d3574566c2758cd657ddffcaeda430bbbfe3e6220ad1cde897e3e4e869c88d2  CeremonyNoFinalityGate.cfg
e3df6609d969846d287f8560dbed43119e9fcc49e24d3eff1b00a46e6f7a426c  CeremonySealOnly.cfg
f3a679f8d851ce3bff7eb62eec3da24e517449d990cb54efeabe4cd8b61ae2c4  Exit.cfg
0f770843cce520d6b8d30227adc48cfb7e5c7586000d8ea9ba2cf6e022f18456  Exit.tla
a4c8ffe73045f85b2b936097118b83a1547ef5b8f8988154f5853cb8b976add5  ExitFiledNoticeFix.cfg
012900b2890acf7927084c8552e9e0a4648e5befc47f34d389997a3446013f1a  ExitNoFairness.cfg
8eb4c459650bf1139e47903ecee43febb3059df400cfd9868f3e467396b3a1c6  ExitSealOnly.cfg
a67f71a60f3607c21f3732cf67e79f851ba9ef082ae1639e082fba2394483ca6  ExitUnboundedMining.cfg
76121b4ce0b326ec67f6ececa34b001144aa414ffee12509ee7391f132c3d669  ExitUnsealedNotice.cfg
60ee629a4f9b3866bafd48edcac7ad3e91170627c892a3b635753aec3e8a9d1c  Nonce.cfg
56efe2615b676d5d1ce7f46cbbc0662624da788f7b054702ef5b37b544440922  Nonce.tla
30a3f64c18c7d5f38876e9516cccbbddf761770de9aeb73a68fc83818cc6beb4  NonceCrash.cfg
0a6679d5feeebc1133f3caef9df7039579f22a8436f91f99412f38856a46f8cb  NoncePerEpoch.cfg
d5d8ed10b606731a3824437b031ea07acee0c2a68a540b25f4271c96644cc200  NonceSchedule.lean
0af109960a3843176a4e200c0724970f613450f1ea8aa553d2d5bc9095ea71a3  verify.py
```
