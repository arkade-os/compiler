(*
1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.
*)
---------------------------- MODULE Anchor ----------------------------
(* Draft model for source revision 2.4, §7.4a and finding A26.

   Scope: the race between a pending transition and the lattice of the pool
   output it spends, when that output is already confirmed. One pool, a chain
   of up to MaxPulse pulses, abstract blocks. Signatures, fees, the mempool and
   the seal set are black boxes; "final" is what a conforming client accepts.

   assumed, §6 and BIP 68: the root of L_j can be included in a block of height
   >= (height of the block that confirmed U_j) + Delta, and in no earlier one.
   assumed, §7.1 step 5: at most one pending transition confirms per block.
   assumed adversary: block contents. Any block may include a mature root, with
   no broadcast step and no fee, so relay policy protects nothing here. Honest
   inclusion is the BoundedInclusion assumption, not a Bitcoin guarantee.
   Reorgs and non-pool inputs of transitions (A29) are excluded. *)
EXTENDS Naturals
CONSTANTS Delta, Margin, Incl, MaxPulse, Horizon,
          Admission, ExtensionDuty, BoundedInclusion
ASSUME /\ Delta \in Nat /\ Margin \in Nat /\ Incl \in Nat /\ Incl >= 1
       /\ MaxPulse \in Nat /\ Horizon \in Nat
VARIABLES height,     (* chain height *)
          anchor,     (* index a of the pool output U_a currently on-chain *)
          anchorAt,   (* height of the block that confirmed it *)
          signed,     (* T_1 .. T_signed exist *)
          final,      (* pulses 1 .. final are treated as final by clients *)
          inPool,     (* T_(anchor+1) is broadcast and unconfirmed *)
          poolSince,  (* height at which it was broadcast *)
          ended,      (* a lattice root has spent the anchor *)
          staleWon,   (* ... and it was the root of a superseded epoch *)
          landed      (* history only: off-chain pulses that reached the chain *)
vars == <<height, anchor, anchorAt, signed, final, inPool, poolSince, ended, staleWon, landed>>
Init == /\ height = 0 /\ anchor = 0 /\ anchorAt = 0 /\ signed = 0 /\ final = 0
        /\ inPool = FALSE /\ poolSince = 0 /\ ended = FALSE /\ staleWon = FALSE
        /\ landed = 0
(* §7.4a, written additively because Naturals has no negative results.
   The anchor deadline is anchorAt + Delta - Margin. *)
BeforeDeadline == height + Margin < anchorAt + Delta
RootValidNext == height + 1 >= anchorAt + Delta
(* §7.4a admission: an off-chain pulse is final on its seal, so it is only
   admitted while the anchor is before its deadline. Admission=FALSE is the
   protocol of revisions <= 2.3, which had no such rule. *)
SealOff == /\ ~ended /\ signed < MaxPulse /\ signed = final
           /\ (Admission => BeforeDeadline)
           /\ signed' = signed + 1 /\ final' = final + 1
           /\ UNCHANGED <<height, anchor, anchorAt, inPool, poolSince, ended, staleWon, landed>>
(* §7.4a on-chain pulse: signed and broadcast at once, final only when it
   confirms. Modeled only when nothing else is pending. *)
SealOn == /\ ~ended /\ signed < MaxPulse /\ signed = anchor /\ ~inPool
          /\ signed' = signed + 1 /\ inPool' = TRUE /\ poolSince' = height
          /\ UNCHANGED <<height, anchor, anchorAt, final, ended, staleWon, landed>>
(* Any holder may broadcast the next pending transition at any time: the
   Operator's heartbeat, a watcher, or an adversary moving the anchor. *)
Broadcast == /\ ~ended /\ anchor < signed /\ ~inPool
             /\ inPool' = TRUE /\ poolSince' = height
             /\ UNCHANGED <<height, anchor, anchorAt, signed, final, ended, staleWon, landed>>
(* §7.4a extension duty, as a mandatory deadline (stronger than weak fairness):
   no block is produced past the deadline while a final pulse is pending and
   unbroadcast. No fairness is assumed of the Operator. *)
DutyDue == ExtensionDuty /\ anchor < final /\ ~inPool /\ ~BeforeDeadline
(* assumed environment: a broadcast transition that is still valid confirms
   within Incl blocks unless a conflicting spend confirms first. *)
InclDue == BoundedInclusion /\ inPool /\ height + 1 >= poolSince + Incl
MineNext == /\ inPool
            /\ anchor' = anchor + 1 /\ anchorAt' = height + 1 /\ inPool' = FALSE
            /\ final' = IF final < anchor + 1 THEN anchor + 1 ELSE final
            /\ landed' = IF final < anchor + 1 THEN landed ELSE landed + 1
            /\ UNCHANGED <<signed, poolSince, ended, staleWon>>
MineRoot == /\ RootValidNext
            /\ ended' = TRUE /\ staleWon' = (anchor < final) /\ inPool' = FALSE
            /\ UNCHANGED <<anchor, anchorAt, signed, final, poolSince, landed>>
MineNone == /\ ~InclDue
            /\ UNCHANGED <<anchor, anchorAt, signed, final, inPool, poolSince, ended, staleWon, landed>>
Block == /\ ~ended /\ height < Horizon /\ ~DutyDue
         /\ height' = height + 1
         /\ (MineNext \/ MineRoot \/ MineNone)
Next == SealOff \/ SealOn \/ Broadcast \/ Block
Spec == Init /\ [][Next]_vars
(* model-checked only at the stated bounds; safety only, no liveness. *)
TypeOK == /\ height \in 0..Horizon /\ anchorAt \in 0..Horizon /\ poolSince \in 0..Horizon
          /\ anchor \in 0..MaxPulse /\ signed \in 0..MaxPulse /\ final \in 0..MaxPulse
          /\ anchor <= final /\ final <= signed /\ signed <= final + 1
          /\ landed \in 0..MaxPulse /\ landed <= anchor
          /\ <<inPool, ended, staleWon>> \in BOOLEAN \X BOOLEAN \X BOOLEAN
(* §7.4a: no pulse treated as final is still pending when the lattice of the
   output under it can be mined in the next block. *)
AnchorAge == ended \/ ~(RootValidNext /\ anchor < final)
(* §8, first row: the lattice of a superseded epoch never confirms. *)
NoStaleWin == ~staleWon
(* Witnesses, each expected to FAIL under the holding parameters. They show
   that NoStaleWin is not satisfied vacuously there: a root can confirm; a
   final pulse can still be unconfirmed when the next block is the last one in
   which the root under it is invalid; and MaxPulse off-chain pulses can each
   become final and then reach the chain. *)
RootNeverConfirms == ~ended
PendingNeverNearMaturity == ~(inPool /\ anchor < final /\ height + 2 = anchorAt + Delta)
OffChainNeverLands == landed < MaxPulse
=============================================================================
