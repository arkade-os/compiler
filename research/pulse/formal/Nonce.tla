(*
1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.
*)
--------------------------- MODULE Nonce ---------------------------
(* Draft model for source revision 2.2, §9.2 and findings A18/A24.

   Scope: ONE artifact signer (the operator threshold) across epochs. Signatures,
   hashing and the group are black boxes: this module reasons only about WHICH
   (nonce, message) pairs the signer emits. Whether such a pair actually yields the
   key is the Lean side (`Pulse.eots_extract`); here "extractable" means exactly
   its hypothesis is met — same committed nonce, two distinct messages, hence
   distinct challenges under the collision-resistance premise recorded in §9.2.

   assumed, §9.2: the signer emits one signature per (epoch, role) slot; the
   protocol rejects any artifact not signed under its committed nonce, so a signer
   cannot dodge by choosing a fresh nonce. Roles are the two artifacts the operator
   threshold signs every epoch: the continuity attestation A_k and the commitment
   h_k. Sealer artifacts are the same shape and are not modeled separately. *)
EXTENDS Naturals, FiniteSets
CONSTANTS MaxEpoch, PerRoleNonce, DurableLog
Roles == {"A", "h"}
Epochs == 0..MaxEpoch
(* PerRoleNonce = the revision-2.2 rule: index the commitment by (epoch, role).
   FALSE reproduces the revision-2.1 schedule, indexed by epoch alone. *)
Nonce(k, r) == IF PerRoleNonce THEN <<k, r>> ELSE <<k, "shared">>
(* A re-signed artifact after state loss carries different content: version 1. *)
Msg(k, r, v) == <<k, r, v>>
VARIABLES epoch, sigs, done, version, leaked
vars == <<epoch, sigs, done, version, leaked>>
Init == /\ epoch = 0 /\ sigs = {} /\ done = {}
        /\ version = [r \in Roles |-> 0] /\ leaked = FALSE
(* the §9.2 extraction hypothesis, as a predicate on emitted pairs *)
Extractable(S) == \E p \in S, q \in S : p[1] = q[1] /\ p[2] # q[2]
Sign(r) == /\ r \notin done /\ epoch \in Epochs
           /\ LET s == sigs \cup {<<Nonce(epoch, r), Msg(epoch, r, version[r])>>}
              IN /\ sigs' = s
                 /\ leaked' = (leaked \/ Extractable(s))
           /\ done' = done \cup {r}
           /\ UNCHANGED <<epoch, version>>
(* A18: crash/restart loses the sign-once record, so already-signed slots are
   re-signed with different content. DurableLog = attested sign-once state. *)
Crash == /\ ~DurableLog /\ done # {}
         /\ done' = {}
         /\ version' = [r \in Roles |-> IF r \in done THEN 1 ELSE version[r]]
         /\ UNCHANGED <<epoch, sigs, leaked>>
Advance == /\ done = Roles /\ epoch < MaxEpoch
           /\ epoch' = epoch + 1 /\ done' = {}
           /\ version' = [r \in Roles |-> 0]
           /\ UNCHANGED <<sigs, leaked>>
Next == (\E r \in Roles : Sign(r)) \/ Crash \/ Advance
Spec == Init /\ [][Next]_vars
TypeOK == /\ epoch \in Epochs /\ done \subseteq Roles
          /\ version \in [Roles -> 0..1] /\ leaked \in BOOLEAN
(* model-checked at the stated bounds; see README for configurations. *)
NoKeyLeak == ~leaked
(* stronger witness: the schedule never reuses a nonce across distinct slots *)
OneMessagePerNonce == \A p \in sigs, q \in sigs : p[1] = q[1] => p[2] = q[2]
=============================================================================
