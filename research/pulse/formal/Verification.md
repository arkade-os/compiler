1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.

# Verification record — draft, 2026-09-11
Source: revision 2.1, commit `ab36e380e3cb7e9f47668a6451b2e30817c667da`; see README for source links and assumptions. Labels below apply only to the precise models, not deployed code. The named branch was checked again after verification and still pointed to this commit.

**Proved:** the six conditional Lean declarations for §9.2 and the restricted §13.2 game. Lean 4.22.0, mathlib 79e94a093aff4a60fb1b1f92d9681e407124c2ca; exit status 0, no errors, no `sorryAx`. `propext`, `Classical.choice`, and `Quot.sound` in the output are ordinary Lean foundations, not trust-layer proofs. Cryptographic/environmental assumptions are theorem hypotheses and model parameters; the axioms report does not remove them.

**Model-checked:** the positive configurations below completed exhaustive finite-state exploration and temporal checking. Negative configurations returned code 12 for the named invariant or code 13 for the named temporal property. A counterexample is a reachable behavior in this abstraction; no security claim beyond README's assumptions follows.

Tool: `TLC2 Version 2026.09.10.191157 (rev: c3af5e2)`, Java 17.0.2. Jar SHA-256: `957b23b2bb31d08f19346e105e23585f93fea9a139a712b0ac347eedaf26afea`. Each TLC run used one worker and no trace-spec generation. Deadlock checking is disabled: terminal/stalled states are intentional; liveness uses explicit temporal properties and fairness.

| Positive configuration | Generated states | Distinct states | Graph depth | Source |
|---|---:|---:|---:|---|
| Ceremony | 4,126 | 1,124 | 20 | §§7.1,7.1a,9,13.4 |
| CeremonyFaults | 5,865 | 1,632 | 20 | §§7.1a,8a,9,13.1 |
| Exit | 457 | 176 | 15 | §§7.3–7.5,9,13.1 |

`CeremonyFaults` deliberately does not check `NoTheft`: it checks finality rejection and fallback selection in the presence of faulty signers. A separate negative case demonstrates the lost safety property. `Exit` assumes the notice is already sealed, so this result is not liveness of obtaining a seal.

## Artifact SHA-256 values

These identify the exact checked source/configuration files and runner. Documentation is excluded to avoid recursive hashes.

```text
4633fafe6756fc1cede5cc86f9b325e924553f38152725df383fd07fd75e175a  Ceremony.cfg
cecdace8d11850e1a2d3ee896c65b2a10e4e564138125b0638f954cd89e74a44  Ceremony.tla
6405863976266cbf0a43ca6fe99feb36780396b3d085188afc9eb324cf87e9df  CeremonyFaults.cfg
c2e5f8f922fb19186f29aba53387a4caf5c719138baf4e74e1a7d687722262b8  CeremonyLastSealed.cfg
11009a5e47f69c7da84fea4167a6a5fb713e98373bd6671bc5054c276f7d101d  CeremonyNoFinalityGate.cfg
cc43bac9e602fe11d3f6b4769aa3e5afc5338a371df85a3fea66a2e8cb6bd343  CeremonySealOnly.cfg
f07d6369a91c80ce48fc8283c19eefdac925468834bf29dc2741619151a8ca65  Exit.cfg
54bb083ce0eca80f19525d1930f6b4c54e5b740e4a69633a4f6c47e9f1b9d097  Exit.tla
6b0b64eb7d011c2bd2378acd515b44e3d6246e9919a73d39111036957b5cc014  ExitNoFairness.cfg
2db429f20b7d328fbe074effa7707dad2ca0ce0a84ac6ce25c6bb629597d358a  ExitSealOnly.cfg
798952cda81ba4608057ba1c77ad8611d0ef41434ac3910488d7b819c31c017c  ExitUnboundedMining.cfg
014d13e4cf279a3e8ddc01b8e7f7ba53d565e4db37d58078f9311f19d5865eb8  Pulse.lean
4c1091a777aa604a6bc8ce20c8faf369aa773e80a7fd8912b3d0e0145bf80e13  verify.py
```

## Lean

Proved conditional algebra, §9.2, and restricted game, §13.2

```text
'Pulse.eots_extract' depends on axioms: [propext, Classical.choice, Quot.sound]
'Pulse.adaptor_complete' depends on axioms: [propext]
'Pulse.extracted_key_completes' depends on axioms: [propext, Classical.choice, Quot.sound]
'Pulse.eots_mod_prime' depends on axioms: [propext, Classical.choice, Quot.sound]
'Pulse.equal_challenges_do_not_extract' depends on axioms: [propext]
'Pulse.restricted_trilemma' does not depend on any axioms
```

## Runner

Successful reproducibility runner

```text
Lean: six proved declarations; no sorryAx in axiom reports
Ceremony: model-checked
CeremonyFaults: model-checked
Exit: model-checked
CeremonyNoFinalityGate: expected counterexample
CeremonyLastSealed: expected counterexample
CeremonySealOnly: expected counterexample
ExitSealOnly: expected counterexample
ExitUnboundedMining: expected counterexample
ExitNoFairness: expected counterexample
```

## Ceremony

Model-checked: §§7.1,7.1a,9,13.4

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 86 and seed 6366449951719883728 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50033] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Ceremony.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-15847113058525855369/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-15847113058525855369/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-15847113058525855369/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Ceremony
Linting of module Ceremony
Starting... (2026-09-11 14:51:08)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:08.
Progress(20) at 2026-09-11 14:51:08: 4,126 states generated, 1,124 distinct states found, 0 states left on queue.
Checking temporal properties for the complete state space with 1124 total distinct states at (2026-09-11 14:51:08)
Finished checking temporal properties in 00s at 2026-09-11 14:51:08
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = 1.8E-13
4126 states generated, 1124 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 20.
The average outdegree of the complete state graph is 1 (minimum is 0, the maximum 8 and the 95th percentile is 4).
Finished in 00s at (2026-09-11 14:51:08)
```

## CeremonyFaults

Model-checked: §7.1a and §8a finality versus spendability

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 74 and seed -8143861893238808107 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50052] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Ceremony.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-4492885344224384645/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-4492885344224384645/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-4492885344224384645/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Ceremony
Linting of module Ceremony
Starting... (2026-09-11 14:51:08)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:08.
Progress(20) at 2026-09-11 14:51:08: 5,865 states generated, 1,632 distinct states found, 0 states left on queue.
Checking temporal properties for the complete state space with 1632 total distinct states at (2026-09-11 14:51:08)
Finished checking temporal properties in 00s at 2026-09-11 14:51:08
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = 3.7E-13
5865 states generated, 1632 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 20.
The average outdegree of the complete state graph is 1 (minimum is 0, the maximum 8 and the 95th percentile is 4).
Finished in 00s at (2026-09-11 14:51:08)
```

## Exit

Model-checked: §§7.3–7.5 under trusted payout and bounded inclusion

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 91 and seed -4038585294080513594 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50343] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Exit.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-607568858677577062/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-607568858677577062/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-607568858677577062/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Exit
Linting of module Exit
Starting... (2026-09-11 14:51:10)
Warning: The invariant TimelockOrdering is a constant-level formula (i.e., it contains no variables, primes, or temporal operators) and evaluates to TRUE. To assert constant-level formulas in your spec, use ASSUME ConstInv. If you optionally want to give the assumption a name, write ASSUME YourAssumption == ConstInv instead. See https://explain.tlapl.us/assumptions-and-invariants for additional details.
(Use the -nowarning option to disable this warning.)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:10.
Progress(15) at 2026-09-11 14:51:10: 457 states generated, 176 distinct states found, 0 states left on queue.
Checking temporal properties for the complete state space with 176 total distinct states at (2026-09-11 14:51:10)
Finished checking temporal properties in 00s at 2026-09-11 14:51:10
Model checking completed. No error has been found.
  Estimates of the probability that TLC did not check all reachable states
  because two distinct states had the same fingerprint:
  calculated (optimistic):  val = 2.7E-15
457 states generated, 176 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 15.
The average outdegree of the complete state graph is 1 (minimum is 0, the maximum 5 and the 95th percentile is 4).
Finished in 00s at (2026-09-11 14:51:10)
```

## CeremonyNoFinalityGate

Model-checked counterexample: §7.1a/A14 finality guard removed

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 46 and seed 6694385069647584431 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50053] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Ceremony.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-16808573633632881854/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-16808573633632881854/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-16808573633632881854/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Ceremony
Linting of module Ceremony
Starting... (2026-09-11 14:51:09)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:09.
Error: Invariant FinalitySound is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "ready"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "good"
/\ badOrder = FALSE

State 2: <Propose line 39, col 12 to line 43, col 60 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "proposed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "conservation"
/\ badOrder = FALSE

State 3: <Attest line 44, col 11 to line 46, col 67 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "attested"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "conservation"
/\ badOrder = FALSE

State 4: <SignLattice line 47, col 16 to line 50, col 71 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "lattice"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "conservation"
/\ badOrder = FALSE

State 5: <Verify line 51, col 11 to line 55, col 67 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "verified"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "conservation"
/\ badOrder = FALSE

State 6: <SignTransition line 56, col 19 to line 60, col 66 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "signed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "conservation"
/\ badOrder = FALSE

State 7: <Publish line 61, col 12 to line 63, col 68 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "published"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "conservation"
/\ badOrder = FALSE

State 8: <Seal line 64, col 9 to line 70, col 48 of module Ceremony>
/\ epoch = 1
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "ready"
/\ accepted = {0, 1}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "conservation"
/\ badOrder = FALSE

1201 states generated, 349 distinct states found, 74 states left on queue.
The depth of the complete state graph search is 8.
Finished in 00s at (2026-09-11 14:51:09)
```

## CeremonyLastSealed

Model-checked counterexample: §7.1 steps 5–6 / §8a unspent-input assumption

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 60 and seed -8221949129198833913 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50143] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Ceremony.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-16579332987862760866/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-16579332987862760866/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-16579332987862760866/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Ceremony
Linting of module Ceremony
Starting... (2026-09-11 14:51:09)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:09.
Error: Invariant LastSealedSpendable is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "ready"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "good"
/\ badOrder = FALSE

State 2: <Propose line 39, col 12 to line 43, col 60 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "proposed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "good"
/\ badOrder = FALSE

State 3: <Attest line 44, col 11 to line 46, col 67 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "attested"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "good"
/\ badOrder = FALSE

State 4: <SignLattice line 47, col 16 to line 50, col 71 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "lattice"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "good"
/\ badOrder = FALSE

State 5: <Verify line 51, col 11 to line 55, col 67 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "verified"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "good"
/\ badOrder = FALSE

State 6: <SignTransition line 56, col 19 to line 60, col 66 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "signed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "good"
/\ badOrder = FALSE

State 7: <Broadcast line 73, col 14 to line 77, col 63 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = FALSE
/\ chainTip = 1
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "signed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "good"
/\ badOrder = FALSE

820 states generated, 246 distinct states found, 72 states left on queue.
The depth of the complete state graph search is 7.
Finished in 00s at (2026-09-11 14:51:09)
```

## CeremonySealOnly

Model-checked counterexample: §§9,13.1 signing threshold compromised

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 66 and seed -3772194774165034943 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50325] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Ceremony.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-12415688416905138255/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-12415688416905138255/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-12415688416905138255/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Ceremony
Linting of module Ceremony
Starting... (2026-09-11 14:51:09)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:09.
Error: Invariant NoTheft is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "ready"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "good"
/\ badOrder = FALSE

State 2: <Propose line 39, col 12 to line 43, col 60 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "proposed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "carry"
/\ badOrder = FALSE

State 3: <Attest line 44, col 11 to line 46, col 67 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "attested"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0}
/\ kind = "carry"
/\ badOrder = FALSE

State 4: <SignLattice line 47, col 16 to line 50, col 71 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "lattice"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "carry"
/\ badOrder = FALSE

State 5: <Verify line 51, col 11 to line 55, col 67 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "verified"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "carry"
/\ badOrder = FALSE

State 6: <SignTransition line 56, col 19 to line 60, col 66 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = FALSE
/\ chainTip = 0
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "signed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "carry"
/\ badOrder = FALSE

State 7: <Broadcast line 73, col 14 to line 77, col 63 of module Ceremony>
/\ epoch = 0
/\ good = {0}
/\ fallback = 0
/\ transitions = {1}
/\ stolen = TRUE
/\ chainTip = 1
/\ sealers = {1, 2, 3}
/\ aborted = FALSE
/\ phase = "signed"
/\ accepted = {0}
/\ halted = FALSE
/\ lattice = {0, 1}
/\ kind = "carry"
/\ badOrder = FALSE

1015 states generated, 303 distinct states found, 78 states left on queue.
The depth of the complete state graph search is 7.
Finished in 00s at (2026-09-11 14:51:10)
```

## ExitSealOnly

Model-checked counterexample: §§7.5,13.1 payout policy compromised

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 114 and seed 1563738644484942835 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50362] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Exit.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-5871019708743489291/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-5871019708743489291/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-5871019708743489291/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Exit
Linting of module Exit
Starting... (2026-09-11 14:51:10)
Warning: The invariant TimelockOrdering is a constant-level formula (i.e., it contains no variables, primes, or temporal operators) and evaluates to TRUE. To assert constant-level formulas in your spec, use ASSUME ConstInv. If you optionally want to give the assumption a name, write ASSUME YourAssumption == ConstInv instead. See https://explain.tlapl.us/assumptions-and-invariants for additional details.
(Use the -nowarning option to disable this warning.)
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:10.
Error: Invariant NoTheft is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

State 2: <Evict line 44, col 10 to line 50, col 54 of module Exit>
/\ unlawful = TRUE
/\ live = FALSE
/\ sealers = {1, 2, 3}
/\ status = "lost"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

3 states generated, 3 distinct states found, 1 states left on queue.
The depth of the complete state graph search is 2.
Finished in 00s at (2026-09-11 14:51:10)
```

## ExitUnboundedMining

Model-checked counterexample: §7.4/A9 inclusion deadline removed

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 89 and seed 8975128302961114113 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50363] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Exit.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-11032124814280741853/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-11032124814280741853/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-11032124814280741853/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Exit
Linting of module Exit
Starting... (2026-09-11 14:51:10)
Warning: The invariant TimelockOrdering is a constant-level formula (i.e., it contains no variables, primes, or temporal operators) and evaluates to TRUE. To assert constant-level formulas in your spec, use ASSUME ConstInv. If you optionally want to give the assumption a name, write ASSUME YourAssumption == ConstInv instead. See https://explain.tlapl.us/assumptions-and-invariants for additional details.
(Use the -nowarning option to disable this warning.)
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:10.
Error: Invariant NoSweepUnderExit is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

State 2: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 7
/\ sweepConflict = FALSE

State 3: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 8
/\ sweepConflict = FALSE

State 4: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 9
/\ sweepConflict = FALSE

State 5: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 10
/\ sweepConflict = FALSE

State 6: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 11
/\ sweepConflict = FALSE

State 7: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 12
/\ sweepConflict = FALSE

State 8: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 13
/\ sweepConflict = FALSE

State 9: <Sweep line 51, col 10 to line 53, col 54 of module Exit>
/\ unlawful = FALSE
/\ live = FALSE
/\ sealers = {1, 2, 3}
/\ status = "lost"
/\ paid = 0
/\ height = 13
/\ sweepConflict = TRUE

260 states generated, 99 distinct states found, 17 states left on queue.
The depth of the complete state graph search is 9.
Finished in 00s at (2026-09-11 14:51:10)
```

## ExitNoFairness

Model-checked counterexample: §§7.3–7.5 clock fairness removed

```text
TLC2 Version 2026.09.10.191157 (rev: c3af5e2)
Running breadth-first search Model-Checking with fp 58 and seed -2087247041636514683 with 1 worker on 10 cores with 14564MB heap and 64MB offheap memory [pid: 50364] (Mac OS X 15.5 aarch64, Oracle Corporation 17.0.2 64bit, MSBDiskFPSet, DiskStateQueue).
Parsing file /Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/outputs/pulse-formalization/Exit.tla
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-3430465782510239260/Naturals.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Naturals.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-3430465782510239260/FiniteSets.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/FiniteSets.tla)
Parsing file /private/var/folders/98/zgs49t8s2w3gv4vm0j5hr0mw0000gn/T/tlc-3430465782510239260/Sequences.tla (jar:file:/Users/tiero/Documents/Codex/2026-09-11/files-pasted-by-the-user-here/work/tools/tla2tools.jar!/tla2sany/StandardModules/Sequences.tla)
Semantic processing of module Naturals
Semantic processing of module Sequences
Semantic processing of module FiniteSets
Semantic processing of module Exit
Linting of module Exit
Starting... (2026-09-11 14:51:11)
Warning: The invariant TimelockOrdering is a constant-level formula (i.e., it contains no variables, primes, or temporal operators) and evaluates to TRUE. To assert constant-level formulas in your spec, use ASSUME ConstInv. If you optionally want to give the assumption a name, write ASSUME YourAssumption == ConstInv instead. See https://explain.tlapl.us/assumptions-and-invariants for additional details.
(Use the -nowarning option to disable this warning.)
Implied-temporal checking--satisfiability problem has 1 branches.
Computing initial states...
Finished computing initial states: 1 distinct state generated at 2026-09-11 14:51:11.
Progress(15) at 2026-09-11 14:51:11: 457 states generated, 176 distinct states found, 0 states left on queue.
Checking temporal properties for the complete state space with 176 total distinct states at (2026-09-11 14:51:11)
Error: Temporal property ExitOrPayout was violated.

Error: The following behavior constitutes a counter-example:

State 1: <Initial predicate>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {1, 2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

State 2: <Stall line 29, col 10 to line 31, col 67 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {2, 3}
/\ status = "sealed"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

State 3: <Stall line 29, col 10 to line 31, col 67 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {2}
/\ status = "sealed"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

State 4: <Stall line 29, col 10 to line 31, col 67 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {}
/\ status = "sealed"
/\ paid = 0
/\ height = 6
/\ sweepConflict = FALSE

State 5: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {}
/\ status = "sealed"
/\ paid = 0
/\ height = 7
/\ sweepConflict = FALSE

State 6: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {}
/\ status = "sealed"
/\ paid = 0
/\ height = 8
/\ sweepConflict = FALSE

State 7: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = TRUE
/\ sealers = {}
/\ status = "sealed"
/\ paid = 0
/\ height = 9
/\ sweepConflict = FALSE

State 8: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = FALSE
/\ sealers = {}
/\ status = "root"
/\ paid = 0
/\ height = 10
/\ sweepConflict = FALSE

State 9: <Tick line 34, col 9 to line 40, col 60 of module Exit>
/\ unlawful = FALSE
/\ live = FALSE
/\ sealers = {}
/\ status = "root"
/\ paid = 0
/\ height = 11
/\ sweepConflict = FALSE

State 10: Stuttering
Warning: The stuttering counterexample above may be caused by the absence of a fairness constraint in the behavior specification SpecUnfair defined at line 56, col 1 to line 56, col 35 of module Exit. To rule out such counterexamples, conjoin a suitable fairness constraint to SpecUnfair (compare Chapter 8, page 87ff of Specifying Systems at https://lamport.azurewebsites.net/tla/book.html).
Finished checking temporal properties in 00s at 2026-09-11 14:51:11
457 states generated, 176 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 15.
Finished in 00s at (2026-09-11 14:51:11)
```
