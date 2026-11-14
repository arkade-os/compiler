1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.

# PULSE revision 2.1 — draft formalization

> **Superseded in part by [`VERIFICATION-2.2.md`](VERIFICATION-2.2.md).** An expansion
> pass re-ran every configuration here, added the `Nonce` module and
> `NonceSchedule.lean`, corrected two ledger rows below, and surfaced finding A25.
> Where the two records disagree, the 2.2 record governs. Run [`verify.py`](verify.py)
> for the current expected results; this file's own reproduction section describes the
> earlier run and its different TLC jar.

Target: [`research/pulse/recurrent-exit-pulse.md`](https://github.com/arkade-os/compiler/blob/ab36e380e3cb7e9f47668a6451b2e30817c667da/research/pulse/recurrent-exit-pulse.md), commit `ab36e380e3cb7e9f47668a6451b2e30817c667da`, branch `claude/pulse-pr-review-qd8sj3`. The entire document, including §§0 and 13, was read. At retrieval on 2026-09-11 that branch still pointed to this commit. Source SHA-256: `3c5007e768e64e03aef6346e15f3d8786571228ec95ff5a7e5f63bd36cac856f`. The source is linked, not copied or modified here. These are research artifacts, with no compiler changes.

**Result:** six conditional algebraic theorems are **proved** by Lean; three finite protocol configurations are **model-checked** by TLC. Six negative configurations produce the intended counterexamples. No end-to-end refinement, protocol security theorem, implementation correspondence, or universal trilemma proof is claimed. **Trust-layer assumptions remain assumed.**

Two separate TLA+ modules keep the small ceremony graph and the timed exit race independently inspectable. Their composition is **not proved**. `Pulse.lean` is a single file using pinned mathlib; it needs no new Lean project. `verify.py` reruns the checks and rejects unexpected failures. [Verification.md](Verification.md) preserves tool identities, complete successful proof output and counterexample logs with these disclaimers.

## Property ledger

All source references below refer only to revision 2.1. “Model-checked” means the exact finite abstraction and bounds below, including infinite stuttering/fair executions over that finite graph; it is not a proof for larger pools, longer epoch histories, or real Bitcoin executions.

| Property / theorem | Label and method | Source and assumptions |
|---|---|---|
| `Ceremony.TypeOK` | **model-checked**, TLC | §§4,7.1; representation invariants, both positive ceremony configurations |
| `LatticeBeforeTransition` | **model-checked**, TLC | §7.1 steps 3–5, A4; lattice-first action order and black-box signatures. **Correction (2.2):** as first written this was enforced by the model's construction and no configuration could falsify it; `CeremonyBadOrder.cfg` now does |
| `AbandonProtected` | **model-checked**, TLC | §7.1, A4; abort before transition release; old lattice remains signed, old epoch not consumed by this attempt |
| `FinalitySound` | **model-checked**, TLC | §7.1a, A14; accepted epochs satisfy independently computed conservation and consistency; passes even with faulty signing gate |
| `FallbackSelectsGood` | **model-checked**, TLC | §§7.1a,7.3, A14; detection selects an accepted, predicate-passing epoch, **not a claim of unspent input or recoverable funds** |
| `Ceremony.NoTheft` | **model-checked**, TLC in `Ceremony.cfg` only | §§9,13.1,13.4; `TrustedGate=TRUE`; specifically no confirmed transition shorts the modeled passive slot |
| `StallDetected` | **model-checked**, TLC | §§9,13.4; 2-of-3 seal set, any seats can stop forever; weak fairness of detection, no fairness of sealing |
| `Exit.TypeOK` | **model-checked**, TLC | §§7.3–7.5; one victim's timed race abstraction |
| `TimelockOrdering` | **assumed**, `ASSUME` | §7.4, A9; a parameter inequality, not a protocol property. **Correction (2.2):** TLC's constant-level warning applied, so it is no longer checked as an invariant; the checked timelock property is `NoSweepUnderExit` |
| `NoSweepUnderExit` | **model-checked**, TLC | §§7.3–7.4, A9; latest auto-exit start, bounded miner inclusion, retained branch, all listed time budgets |
| `Exit.NoTheft` | **model-checked**, TLC | §§7.5,9,13.1; `TrustedPayout=TRUE`, bounded inclusion; excludes sub-dust members |
| `ExitOrPayout` | **model-checked**, TLC | §7.5, A16 and the noticed-member payout part of A17; already-sealed notice; adversarial Operator, honest sealers may all stop; intact signing-policy oracle and fair clock |
| `eots_extract` | **proved**, Lean, unbounded | §9.2; field, faithful scalar-to-group map, same nonce point/key, valid signatures, **unequal challenges** |
| `eots_mod_prime` | **proved**, Lean, unbounded | §9.2; specializes extraction to `ZMod n`, prime `n`, explicit tagged challenge definition; distinct messages **and** unequal reduced challenges |
| `adaptor_complete` | **proved**, Lean, unbounded | §9.2; additive Schnorr adaptor convention; valid pre-signature and correct secret for adaptor point; fixed final-nonce challenge |
| `extracted_key_completes` | **proved**, Lean, unbounded | §9.2; composition of the two preceding algebraic mechanisms under their assumptions |
| `equal_challenges_do_not_extract` | **proved**, Lean, unbounded | §9.2 boundary case; equal scalars/challenges give zero extraction, not a nonzero secret |
| `restricted_trilemma` | **proved**, Lean, unbounded conditional lemma | §§2,13.1–13.2; attacker controls online signers and **output-redirection ability is an explicit premise** |
| `BroadTrilemmaStatement` | **assumed conjecture / statement only**, not a Lean axiom | §13.2; no proof and no downstream use. Generic predicate schema awaits a justified protocol class and communication/authorization semantics |

### Assumption ledger

- **Assumed — §§9,9.1,13.1,13.5:** intact threshold signing policy, honest attestation, correct enclave code and hardware, and genuine independence when interpreting `TrustedGate` / `TrustedPayout` as FROST-in-TEE. These Boolean oracles do not prove hardware security. For a threshold `t` of `n`, preventing an all-corrupt signing quorum requires fewer than `t` corrupt shares, equivalently at least `n-t+1` honest shares; “at least t honest” alone is not sufficient for arbitrary parameters. Referee honesty is not used in any algebraic proof; compensation is outside the executable models.
- **Assumed — §§7.1,7.1a,8,9:** signatures and content-addressed roots behave as validity/binding predicates. Table equality abstracts a collision-free commitment. Initial epoch and retained artifacts are valid; no global data loss. Sealers are honest, may permanently withhold service, and never act as consensus validators. Honest seals do not block Bitcoin from accepting an unsealed signed transaction.
- **Assumed — §§7.3–7.5,13.1:** an eligible above-dust victim has already sealed a notice and has a complete branch. Detection and the block clock have the specified fairness; the mining environment meets an explicit deadline. No fairness is assumed for Operator action or seal availability.
- **Assumed — §9.2:** field/group laws, prime order, faithful generator, canonical point interpretation, correct SHA256/serialization instantiation and different reduced challenges for extraction. The proofs establish deterministic Schnorr algebra. They do not establish discrete-log hardness, unforgeability, collision resistance, random-oracle bounds, or concrete BIP340 verification.
- **Assumed — §9.2:** a valid, fixed-message burn pre-signature already exists with no alternate unauthorized spend path. Algebraic completion is separate from bond construction, irreversible burn, timelocked reclaim, fee bumping, or transaction confirmation.

## Bounds and adversary

`Ceremony.cfg` explores epochs 0–2, two slots (`active`, `passive`), initial balance 1 each, and three sealers with quorum 2. Values are abstract accounting units, not satoshis. Five proposal classes independently exercise a correct candidate, conservation error, consistency error, conserving passive shorting, and withheld publication. No honest progress by Operator or sealers is required. `CeremonyFaults.cfg` additionally lets malformed/shorting candidates pass the signing gate while keeping honest finality checking. Successful graphs have 1,124 and 1,632 distinct states respectively.

`Exit.cfg` explores one victim with balance 2, a fixed sealed notice at height 6, Δ=2, margin=4, sweepDelay=6, renew=12, virtual-chain depth=1, tree depth=1, slot CSV=1, fee buffer=1. Root inclusion deadline is height 10, full maturity height 12, sweep earliest height 13, and clock horizon 16. The graph has 176 distinct states. The finite clock stops **after** the relevant deadlines; weak fairness makes earlier permanent stuttering inadmissible. The Operator can choose a displacement or remain inactive; the honest signing-policy oracle restricts which payouts it can actually sign. Sealers can all stop after the initial notice.

The timed model starts with the notice already sealed: it does not prove that an unsealed notice will eventually obtain a receipt from a stalled seal set. The two modules share assumptions by documentation, not a machine-checked refinement relation.

## Counterexamples and unresolved limits

All following observations are **model-checked counterexamples at the stated bounds**, not exploits in shipped software.

| Configuration | Expected violated property | Interpretation and source |
|---|---|---|
| `CeremonyNoFinalityGate.cfg` | `FinalitySound` | Removing the public finality gate permits acceptance of a malformed pulse (§7.1a, A14) |
| `CeremonyLastSealed.cfg` | `LastSealedSpendable` | `propose → attest → lattice → verify → sign T → broadcast T`, before seal: input of last sealed epoch can already be consumed (§7.1 steps 5–6, §8a) |
| `CeremonySealOnly.cfg` | `NoTheft` | A conserving shorting transition can broadcast before an honest seal set rejects it, if signing enforcement is broken (§§2,8a,9,13.1) |
| `ExitSealOnly.cfg` | `NoTheft` | A payout-less displacement spends the noticed input if signing policy is compromised; honest sealers cannot veto consensus (§§7.5,13.1) |
| `ExitUnboundedMining.cfg` | `NoSweepUnderExit` | The numerical timelock inequality remains true, but a censored lattice can lose its input at expiry (§§7.3–7.4, A9) |
| `ExitNoFairness.cfg` | `ExitOrPayout` | Permanent pre-maturity stuttering defeats eventual exit when the clock has no fairness (§§7.3–7.5) |

**Editorial questions, not protocol fixes:** reconcile the introductory atomic-abandonment claim in §7.1 with a broadcastable `T` released before sealing; specify recovery of the valid successor lattice after its predecessor is spent; distinguish “last-good selection” from “last-good remains spendable” (§8a). Specify the physical CLTV/CSV reference points (§§7.4,11). State exactly which signing threshold prevents unlawful displacement; honest seal refusal alone is insufficient (§§7.5,9,13.1). The artifacts do not silently add a consensus seal gate or covenant to fix these issues.

## Formalization decisions

1. **§§4,7.1:** `T_(k+1)` consumes `U_k`; follow §7.1's indexing where vocabulary shorthand differs. One in-flight proposal; sequential accepted epochs; aborted unsigned attempts may retry the same next epoch. No future key deletion is inferred.
2. **§7.1, A4:** abandonment is allowed only before transition signing. After a fully signed transaction is released, it cannot be recalled merely by calling the ceremony abandoned. Retaining a lattice is modeled separately from input spendability.
3. **§§7.1,7.1a:** proposal templates replace arbitrary transactions. Conservation sums the two explicit slots; dust and path fees are zero in this subsystem. Attestation binds the table; exact table/slot identity replaces Merkle construction. The `consistency` template conserves value but swaps allocation. The `carry` template conserves and matches its attestation but shorts the passive member. Template coverage is not exhaustive transaction enumeration.
4. **§§7.1a,7.5:** public arithmetic consistency and passive carry-forward are separate predicates. The seal action combines honest sealer validation and conforming acceptance. Exit policy is checked in the separate timed module. Withheld data yields no seal. Detection selects the last accepted epoch and is not a guaranteed recovery transaction.
5. **§§7.1,9,13.4:** 2-of-3 explicit sealer identities may fail permanently. Thresholds are fixed, not generic quantified theorems. A sealer component controls finality, never the physical broadcast action. A signer policy oracle is distinct from sealer honesty.
6. **§§7.3,13.4:** timeout is an abstract detection action with weak fairness, not a specified number of batch intervals. `Detect` records fallback atomically, modeling a client decision, not completed on-chain exit. Client state progression halts on detection; an already released transaction may still broadcast.
7. **§§7.3–7.4,11:** choose `Start=renew−Δ−margin`, conservatively charge virtual-chain depth, Δ and fee buffer before root inclusion, then tree confirmations and slot CSV. In the checked bounds `margin=ChainDepth+TreeDepth+SlotCSV+FeeBuffer`. `Tick` enforces root inclusion by its deadline: this is an explicit environmental assumption, not a Bitcoin guarantee. Chain reorgs and unbounded congestion are excluded.
8. **§§7.4,11:** use `max(renew, anchorHeight+sweepDelay)` for the conjunction of absolute CLTV and relative CSV, rather than assume that they add to `renew+sweepDelay`. Fix the modeled anchor height to `Start+ChainDepth`. This exposes the prose's clock-reference ambiguity. No compiler validation is tested.
9. **§7.5, A16–A17:** project onto one already-sealed, above-dust victim; notice identity, epoch reference and full balance are fixed by initial state. A displacement is terminal only for this victim and pays an on-chain output under its fixed key. Other members' successor epochs are outside this module. Notices are abstract signed records, not a proposed ABI. No mempool observation is treated as a signed notice; third-party root broadcasting alone does not forge the member's signature. Full mass-exit/griefing dynamics and automatic claimant attribution remain unformalized.
10. **§§9,9.1,13.1,13.5:** replace trusted signers with named refusal oracles. Intact mode blocks bad signatures; compromised mode permits them and retains honest sealers. No claimed proof of TEE attestation, secure deletion, independent operators, or committee honesty. No bond is credited as recovered funds.
11. **§9.2:** field abstraction specialized to prime `ZMod n`; faithful map `a ↦ a•g`; no discrete-log algorithm required for the witness `x`. Extraction takes only public `s₁,s₂,e₁,e₂`. Same normalized full nonce point and unequal field challenges are necessary premises. Message inequality alone is not substituted for challenge inequality.
12. **§9.2; §11 ABI deferral:** choose the BIP340-style tagged SHA256 challenge over `enc(R)||enc(X)||m`, big-endian integer reduced modulo `n`. The exact tag bytes and concatenation are executable Lean definitions. SHA and point encoding are oracles, not verified implementations. Intended `m` is an injective encoding of version, pool, artifact role, signer, epoch and artifact contents; wire encoding remains deliberately unimplemented. BIP340's [key prefixing and tagged hashing](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) guide this explicit choice, not a claim that the source pinned that ABI.
13. **§9.2, A18–A19:** nonce scheduling, Merkle inclusion and FROST preprocessing are not proved. Honest signing of `A_k` and `h_k` with the same key and nonce would also extract the key; role domain separation in the message alone does not prevent that. A concrete schedule must distinguish signing slots by role or use separate keys/nonces; this model assumes one slot for the extraction pair and does not silently implement that missing policy.
14. **§9.2, A20:** choose plus-adaptor convention with final nonce `Rhat+X`; use the challenge of that final nonce and fixed burn digest even in pre-verification. Assume normalized signs appropriate to BIP340. Prove completion of the verified pre-signature equation only, not exclusive burn spendability, correct Taproot construction, signing-key erasure, or timely burn before reclaim.
15. **§13.2:** the proved restricted game has an adversary controlling all online signers, a silent passive victim, one synchronous sign/inclusion step, and explicit arbitrary-output redirection. That premise is stronger than “no covenant opcode.” The broad claim is a separate proposition schema, with no `sorry`, asserted axiom, or fabricated proof.
16. **§§9.3–9.4,12.1:** no economics or share-refresh model. Treat the explicit revision-2.1 correction in §§0,9.4 as controlling over older cadence/coverage wording remaining in §§7.2,7.4,10(A10),12.1. No theorem states cadence caps lie-once theft. No capital-sizing or fee recommendation is derived.

## What is not formalized

**Not proved or model-checked:** arbitrary dynamic membership, general-N trees, full heartbeat/virtual-chain construction, MuSig2/FROST protocol security, signature serialization, fee markets/TRUC/P2A pinning, reorgs, dusty/cooperative-only exits, multiple simultaneous notices, A17's economic damage, bond construction or compensation, nonce-commitment schedules and crash recovery, log gossip/fork-linearizability, DA sampling, proactive resharing, capital adequacy and cross-pool correlation, compiler/SDK/ABI code, and the GSR annex (§§5–12, A1–A3,A6–A8,A10–A13,A15,A17–A23 beyond the narrow projections listed above). These require additional models and/or code not specified by this draft. The wide trilemma is statement-only because §13.2 does not delimit all possible protocols or supply a reduction establishing redirection from its three English clauses.

## Reproduction

Use Lean **4.22.0** and mathlib commit **79e94a093aff4a60fb1b1f92d9681e407124c2ca** (tag `v4.22.0`), with its pinned dependencies. From that mathlib checkout, obtain its cache with `lake exe cache get Mathlib/Algebra/Field/Basic.lean Mathlib/Algebra/Module/Basic.lean Mathlib/Algebra/Field/ZMod.lean`. This uses mathlib's cache utility; downloads are external dependencies, not included deliverables.

The downloaded [TLC release asset](https://github.com/tlaplus/tlaplus/releases/tag/v1.8.0) identifies itself as `TLC2 Version 2026.09.10.191157 (rev: c3af5e2)`; pin **the actual jar SHA-256**, `957b23b2bb31d08f19346e105e23585f93fea9a139a712b0ac347eedaf26afea`, because a release URL alone is insufficient to identify its bytes. Tested with Java 17.0.2 on macOS arm64.

With `lake` on PATH, run:

```sh
python3 verify.py --mathlib /absolute/path/to/mathlib --tlc /absolute/path/to/tla2tools.jar
```

Run from any directory; paths to these artifacts are resolved relative to the script. The runner uses temporary state directories, checks Lean's return status and axiom output, checks each expected TLC result, and removes temporary traces. Negative cases must fail for their **named** property, not for a syntax or runtime error. The toolchain is not installed system-wide by these artifacts.
