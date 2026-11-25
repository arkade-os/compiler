(*
1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.
*)
----------------------------- MODULE Exit -----------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Delta, Margin, SweepDelay, Renew, ChainDepth, TreeDepth, SlotCSV,
          FeeBuffer, TrustedPayout, BoundedInclusion, NoticePreSealed,
          EnclaveHonorsFiled
(* assumed environment, §§7.3-7.5: one above-dust victim, a sealed notice and
   retained lattice at the latest auto-exit start. Units are abstract blocks.
   RootDue includes virtual-chain confirmation, CSV and fee-delay budget.
   The physical sweep rule follows §11: CLTV AND relative CSV, not renew+CSV. *)
Start == Renew - Delta - Margin
RootDue == Start + ChainDepth + Delta + FeeBuffer
CompleteDue == RootDue + TreeDepth + SlotCSV
Anchor == Start + ChainDepth
SweepAt == IF Renew >= Anchor+SweepDelay THEN Renew ELSE Anchor+SweepDelay
Horizon == SweepAt + TreeDepth + SlotCSV + 1
Balance == 2
VARIABLES height, status, live, paid, sealers, sweepConflict, unlawful, noticeSealed
vars == <<height,status,live,paid,sealers,sweepConflict,unlawful,noticeSealed>>
Init == /\ height = Start /\ status = "sealed" /\ live = TRUE /\ paid = 0
        /\ sealers = {1,2,3} /\ sweepConflict = FALSE /\ unlawful = FALSE
        /\ noticeSealed = NoticePreSealed
Stall == \E s \in sealers:
    /\ sealers' = sealers \ {s}
    /\ UNCHANGED <<height,status,live,paid,sweepConflict,unlawful,noticeSealed>>
(* §7.5: the notice becomes objective evidence only once the seal set receipts it.
   NoticePreSealed=FALSE starts before that receipt, so a seal-set stall can
   precede sealing -- the gap the revision-2.1 record listed as unmodeled. *)
SealNotice == /\ ~noticeSealed /\ Cardinality(sealers) >= 2
              /\ noticeSealed' = TRUE
              /\ UNCHANGED <<height,status,live,paid,sealers,sweepConflict,unlawful>>
(* assumed timely miner inclusion, §§7.3,7.4. No fairness of Operator or sealers.
   Each Tick is a block. A mandatory deadline is stronger than weak fairness. *)
Tick == /\ height < Horizon /\ height' = height+1
        /\ IF BoundedInclusion /\ live /\ height+1 >= RootDue
           THEN /\ live' = FALSE /\ status' = "root"
           ELSE /\ live' = live
                /\ status' = IF status = "root" /\ height+1 >= CompleteDue
                             THEN "mature" ELSE status
        /\ UNCHANGED <<paid,sealers,sweepConflict,unlawful,noticeSealed>>
(* Operator chooses payout amount; an intact signing-policy oracle refuses
   a short payout BEFORE a spend can be signed, §§7.5,9,13.1. Seal refusal alone
   is not a consensus guard; Evict does not require a fresh epoch seal. *)
Evict == /\ live /\ status = "sealed"
         /\ \E amount \in 0..Balance:
             (* The member has filed by construction (Init). EnclaveHonorsFiled
                =TRUE: the signing policy refuses a short payout against the
                member's OWN signed notice, without waiting for the seal set --
                the enclave can verify that signature itself; the seal exists to
                make the case adjudicable by third parties, not to gate refusal. *)
             /\ (~TrustedPayout \/ (~noticeSealed /\ ~EnclaveHonorsFiled)
                  \/ amount = Balance)
             /\ paid' = amount /\ live' = FALSE
             /\ status' = IF amount = Balance THEN "paid" ELSE "lost"
             /\ unlawful' = (amount # Balance)
         /\ UNCHANGED <<height,sealers,sweepConflict,noticeSealed>>
Sweep == /\ live /\ height >= SweepAt
         /\ live' = FALSE /\ status' = "lost" /\ sweepConflict' = TRUE
         /\ UNCHANGED <<height,paid,sealers,unlawful,noticeSealed>>
Next == Tick \/ Evict \/ Sweep \/ Stall \/ SealNotice
Spec == Init /\ [][Next]_vars /\ WF_vars(Tick)
SpecUnfair == Init /\ [][Next]_vars
(* §7.4/A9 is a property of the chosen parameters, not of the protocol: TLC's own
   constant-level warning applies, so it is an ASSUME, not a checked invariant. *)
TimelockOrdering == SweepDelay >= Delta + Margin
ASSUME TimelockOrdering
(* model-checked only at the stated bounds; parameter inequalities are assumed. *)
TypeOK == /\ height \in Start..Horizon /\ status \in {"sealed","root","mature","paid","lost"}
          /\ paid \in 0..Balance /\ sealers \subseteq {1,2,3}
          /\ <<live,sweepConflict,unlawful,noticeSealed>>
             \in BOOLEAN \X BOOLEAN \X BOOLEAN \X BOOLEAN
NoSweepUnderExit == ~sweepConflict
NoTheft == status # "lost"
ExitOrPayout == (status = "sealed") ~> (status = "mature" \/ (status = "paid" /\ paid = Balance))
=============================================================================
