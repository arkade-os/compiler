(*
1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.
*)
--------------------------- MODULE Ceremony ---------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS MaxEpoch, TrustedGate, CheckBeforeSeal, TrustedOrder
Members == {"active", "passive"}
Epochs == 0..MaxEpoch
Base == [m \in Members |-> 1]
Kinds == {"good", "conservation", "consistency", "carry", "withheld"}
Table(q) == IF q = "carry" THEN [m \in Members |-> IF m = "active" THEN 2 ELSE 0] ELSE Base
Slots(q) == IF q = "consistency" THEN [m \in Members |-> IF m = "active" THEN 0 ELSE 2] ELSE Table(q)
Value(q) == IF q = "conservation" THEN 3 ELSE 2
(* assumed abstraction, §§7.1a, 9: exact table identity stands for a binding root;
   zero dust/path fees in this subsystem. Attestation always matches Table(q). *)
Conservation(q) == Slots(q)["active"] + Slots(q)["passive"] = Value(q)
Consistency(q) == Slots(q) = Table(q)
PublicPredicate(q) == Conservation(q) /\ Consistency(q)
Carry(q) == Table(q)["passive"] = Base["passive"]
VARIABLES epoch, phase, kind, lattice, transitions, accepted, good,
          sealers, chainTip, aborted, badOrder, fallback, halted, stolen
vars == <<epoch, phase, kind, lattice, transitions, accepted, good,
          sealers, chainTip, aborted, badOrder, fallback, halted, stolen>>
Init == /\ epoch = 0 /\ phase = "ready" /\ kind = "good"
        /\ lattice = {0} /\ transitions = {} /\ accepted = {0} /\ good = {0}
        /\ sealers = {1,2,3} /\ chainTip = 0 /\ aborted = FALSE
        /\ badOrder = FALSE /\ fallback = 0 /\ halted = FALSE /\ stolen = FALSE
(* assumed: a 2-of-3 honest seal set, each seat may stop permanently, §§9,13.4. *)
Stall == \E s \in sealers:
    /\ sealers' = sealers \ {s}
    /\ UNCHANGED <<epoch,phase,kind,lattice,transitions,accepted,good,chainTip,
                    aborted,badOrder,fallback,halted,stolen>>
Propose == /\ phase = "ready" /\ ~halted /\ epoch < MaxEpoch
           /\ \E q \in Kinds: kind' = q
           /\ phase' = "proposed" /\ aborted' = FALSE
           /\ UNCHANGED <<epoch,lattice,transitions,accepted,good,sealers,chainTip,
                           badOrder,fallback,halted,stolen>>
Attest == /\ phase = "proposed" /\ phase' = "attested"
          /\ UNCHANGED <<epoch,kind,lattice,transitions,accepted,good,sealers,chainTip,
                          aborted,badOrder,fallback,halted,stolen>>
SignLattice == /\ phase = "attested" /\ phase' = "lattice"
              /\ lattice' = lattice \cup {epoch+1}
              /\ UNCHANGED <<epoch,kind,transitions,accepted,good,sealers,chainTip,
                              aborted,badOrder,fallback,halted,stolen>>
Verify == /\ phase = "lattice"
          /\ (~TrustedGate \/ (PublicPredicate(kind) /\ Carry(kind)))
          /\ phase' = "verified"
          /\ UNCHANGED <<epoch,kind,lattice,transitions,accepted,good,sealers,chainTip,
                          aborted,badOrder,fallback,halted,stolen>>
(* §7.1 steps 3-5, A4: lattice BEFORE transition. TrustedOrder=FALSE models an
   implementation that releases a signed T while the lattice is still unsigned,
   which is the hazard the step order exists to prevent. *)
SignTransition == /\ \/ (phase = "verified" /\ epoch+1 \in lattice)
                     \/ (~TrustedOrder /\ phase = "attested")
                  /\ phase' = "signed" /\ transitions' = transitions \cup {epoch+1}
                  /\ badOrder' = (badOrder \/ epoch+1 \notin lattice)
                  /\ UNCHANGED <<epoch,kind,lattice,accepted,good,sealers,chainTip,
                                  aborted,fallback,halted,stolen>>
Publish == /\ phase = "signed" /\ kind # "withheld" /\ phase' = "published"
           /\ UNCHANGED <<epoch,kind,lattice,transitions,accepted,good,sealers,chainTip,
                           aborted,badOrder,fallback,halted,stolen>>
Seal == /\ phase = "published" /\ Cardinality(sealers) >= 2 /\ ~halted
        /\ (~CheckBeforeSeal \/ PublicPredicate(kind)) /\ Carry(kind)
        /\ accepted' = accepted \cup {epoch+1}
        /\ good' = IF PublicPredicate(kind) THEN good \cup {epoch+1} ELSE good
        /\ epoch' = epoch+1 /\ phase' = "ready"
        /\ UNCHANGED <<kind,lattice,transitions,sealers,chainTip,aborted,badOrder,
                        fallback,halted,stolen>>
(* §§2,7.1 step 5,8a: a signed T is broadcastable even BEFORE the seal.
   chainTip abstracts sequential confirmation of all missing ancestors. *)
Broadcast == /\ phase \in {"signed","published"} /\ chainTip <= epoch
             /\ chainTip' = epoch+1
             /\ stolen' = (stolen \/ ~Carry(kind))
             /\ UNCHANGED <<epoch,phase,kind,lattice,transitions,accepted,good,sealers,
                             aborted,badOrder,fallback,halted>>
Abort == /\ phase \in {"proposed","attested","lattice","verified"}
         /\ phase' = "ready" /\ aborted' = TRUE
         /\ lattice' = lattice \ {epoch+1}
         /\ UNCHANGED <<epoch,kind,transitions,accepted,good,sealers,chainTip,
                         badOrder,fallback,halted,stolen>>
(* §§7.1a,7.3: timeout/detection is an abstract observable event. A fallback
   selects an epoch; this DOES NOT assert its input is still unspent (§8a). *)
Detect == /\ ~halted
          /\ (Cardinality(sealers) < 2 \/ kind = "withheld" \/
               (phase = "published" /\ ~PublicPredicate(kind)))
          /\ halted' = TRUE /\ fallback' = epoch
          /\ UNCHANGED <<epoch,phase,kind,lattice,transitions,accepted,good,sealers,
                          chainTip,aborted,badOrder,stolen>>
Next == Propose \/ Attest \/ SignLattice \/ Verify \/ SignTransition \/ Publish
        \/ Seal \/ Broadcast \/ Abort \/ Stall \/ Detect
Spec == Init /\ [][Next]_vars /\ WF_vars(Detect)
(* model-checked properties: see README for exact configurations and bounds. *)
TypeOK == /\ epoch \in Epochs /\ chainTip \in Epochs
          /\ lattice \subseteq Epochs /\ transitions \subseteq 1..MaxEpoch
          /\ accepted \subseteq Epochs /\ good \subseteq Epochs
          /\ sealers \subseteq {1,2,3}
          /\ phase \in {"ready","proposed","attested","lattice","verified","signed","published"}
          /\ kind \in Kinds /\ fallback \in Epochs
          /\ <<aborted,badOrder,halted,stolen>> \in BOOLEAN \X BOOLEAN \X BOOLEAN \X BOOLEAN
LatticeBeforeTransition == ~badOrder /\ transitions \subseteq lattice
AbandonProtected == aborted => (epoch \in lattice /\ chainTip <= epoch)
FinalitySound == accepted \subseteq good
FallbackSelectsGood == halted => fallback \in good
NoTheft == ~stolen
StallDetected == (Cardinality(sealers) < 2) ~> halted
(* deliberately stronger hypotheses to falsify, NOT properties claimed proved: *)
LastSealedSpendable == chainTip <= epoch
=============================================================================
