/-
1. **This formalizes a design document, not shipped code.** No claim here says anything about the actual Arkade compiler, emulator, or any deployed implementation. A gap between this formal model and running code is not covered and must not be implied to be covered.
2. **This is not a security audit and confers no security guarantee.** Passing model-checking or completing a proof means only that the *specific stated properties* hold under the *specific stated adversary model* — nothing broader. Do not use language like "PULSE is proven secure"; use "property P holds under assumptions A, checked/proved by method M."
3. **Trust-layer assumptions are modeled as assumptions, not derived.** The source document is explicit (§9, §9.1, §13.1) that TEE attestation, federation honesty thresholds, and enclave/committee trust are *not* cryptographically eliminated — they are the trilemma's third corner (§13.2). Model them as named axioms/oracles (e.g. `Assume: at least t of n enclaves are honest and attested`) and never attempt to prove them; flag prominently anywhere a proof's soundness rests on one.
4. **Every claim must be labeled** as one of: **proved** (machine-checked, unbounded), **model-checked** (bounded state space, e.g. TLC with a stated parameter bound — absence of a counterexample at that bound is not a proof for larger N), or **assumed** (an axiom taken from the source spec, not derived here). Do not let a model-checked or assumed claim read like a proved one anywhere in the output, including summaries and comments.
5. **Formalization requires resolving informalities the source document left as prose.** Every place you had to make a choice the `.md` did not pin down precisely (e.g., exact message formats in §7.5's exit notices, the wire serialization deferred to the ABI in §13.4, the exact adversary model for §9.4's capital sizing) must be listed explicitly in a "Formalization decisions" section, with the section number of the ambiguity and the choice made. Do not silently disambiguate.
6. **Do not present this as peer-reviewed or final.** It is a draft input to a whitepaper and is explicitly intended for a human researcher/editor to review, correct, and take ownership of before any publication or citation.
7. **No production or financial guidance.** Nothing in the formal artifacts should be read as advice to deploy, invest in, or rely on PULSE-secured funds; note this plainly if the work is shared outside the immediate research/editorial team.
-/
import Mathlib.Algebra.Field.Basic
import Mathlib.Algebra.Module.Basic
import Mathlib.Algebra.Field.ZMod

/- Draft model for source revision 2.1, §9.2.
   assumed: prime-order additive group with faithful scalar action; SHA256 and
   point/message encoding are parameters, not implementations or hardness proofs.
   No random-oracle or discrete-log hardness theorem is claimed. The deterministic
   identities below need neither assumption; they need unequal scalar challenges.
   A random-oracle security interpretation would additionally need an explicit
   probabilistic experiment and collision bound, which are not formalized here. -/
namespace Pulse

abbrev Bytes := List (Fin 256)
def os2ip (bs : Bytes) : Nat := bs.foldl (fun a b => 256 * a + b.val) 0

/- assumed choice, §9.2: BIP340-style key-prefixed tagged challenge.
   sha is SHA256 returning 32 bytes in the intended instantiation; enc encodes a
   canonical even-Y point as its 32-byte big-endian x coordinate. The message m is
   an injectively encoded ("PULSE/2.1", pool, role, signer, epoch, artifact) tuple.
   This abstract model does not verify lengths, point lifting, SHA256, or the ABI.
   tag bytes below are ASCII "BIP0340/challenge". Point equality means the same
   normalized point, not two opposite points with an ambiguous x coordinate. -/
def challenge {G : Type*} (n : Nat) (sha : Bytes → Bytes) (enc : G → Bytes)
    (R X : G) (m : Bytes) : ZMod n :=
  let tag : Bytes := [66, 73, 80, 48, 51, 52, 48, 47, 99, 104, 97, 108, 108, 101, 110, 103, 101]
  let t := sha tag
  (os2ip (sha (t ++ t ++ enc R ++ enc X ++ m)) : ZMod n)

section Algebra
variable {F G : Type*} [Field F] [AddCommGroup G] [Module F G]

def Valid (g X R : G) (e s : F) : Prop := s • g = R + e • X

def extract (s₁ s₂ e₁ e₂ : F) : F := (s₁ - s₂) / (e₁ - e₂)

/- proved (unbounded, Lean); source §9.2 extraction, assumption set:
   field scalars; faithful generator; X=x•g; same full R; valid signatures;
   e₁≠e₂. The output uses PUBLIC scalars only; x is a correctness witness.
   Distinct messages alone do not imply this nonzero denominator. -/
theorem eots_extract (g X R : G) (x s₁ s₂ e₁ e₂ : F)
    (faithful : Function.Injective (fun a : F => a • g))
    (key : X = x • g)
    (v₁ : Valid g X R e₁ s₁) (v₂ : Valid g X R e₂ s₂)
    (hne : e₁ ≠ e₂) : extract s₁ s₂ e₁ e₂ = x := by
  have diff : (s₁ - s₂) • g = (e₁ - e₂) • X := by
    simp only [sub_smul, Valid] at *
    rw [v₁, v₂]
    simp
  rw [key, smul_smul] at diff
  have scalar := faithful diff
  unfold extract
  apply (div_eq_iff (sub_ne_zero.mpr hne)).2
  rw [scalar]
  exact mul_comm _ _

/- proved (unbounded, Lean); §9.2 adaptor completion.
   assumed: an already verified pre-signature for the FIXED burn transaction,
   with challenge e computed from FINAL nonce Rhat+X, bond key B, and burn digest.
   Scheme: shat•g = Rhat + e•B; completed s=shat+x, R=Rhat+X.
   This is the plus-adaptor convention. For BIP340 the final nonce must have the
   canonical even-Y sign; opposite parity needs consistently adjusted signs.
   No claim about constructing this pre-signature, Taproot paths, deleted keys,
   burn-output binding, fees, relay, or eventual confirmation (A20) is proved. -/
theorem adaptor_complete (g B Rhat X : G) (shat x e : F)
    (pre : shat • g = Rhat + e • B) (key : X = x • g) :
    Valid g B (Rhat + X) e (shat + x) := by
  unfold Valid
  rw [add_smul, pre, ← key]
  simp only [add_assoc, add_comm, add_left_comm]

/- proved (unbounded, Lean); §9.2 composed public extraction → completion.
   Assumptions are exactly eots_extract and adaptor_complete above. -/
theorem extracted_key_completes (g X R B Rhat : G)
    (x s₁ s₂ e₁ e₂ shat burnChallenge : F)
    (faithful : Function.Injective (fun a : F => a • g)) (key : X = x • g)
    (v₁ : Valid g X R e₁ s₁) (v₂ : Valid g X R e₂ s₂) (hne : e₁ ≠ e₂)
    (pre : shat • g = Rhat + burnChallenge • B) :
    Valid g B (Rhat + X) burnChallenge (shat + extract s₁ s₂ e₁ e₂) := by
  rw [eots_extract g X R x s₁ s₂ e₁ e₂ faithful key v₁ v₂ hne]
  exact adaptor_complete g B Rhat X shat x burnChallenge pre key
end Algebra

/- proved (unbounded, Lean); §9.2 specialized to modular arithmetic modulo prime n.
   assumed: n prime, SHA/encoding oracles, faithful prime-order group, X=x•g,
   m₁≠m₂ AND different reduced challenges. Pre-committed nonce membership is a
   protocol premise; both signatures here use that same supplied R.
   This proves no collision-resistance claim and no concrete curve implementation. -/
theorem eots_mod_prime {n : Nat} [Fact n.Prime]
    {G : Type*} [AddCommGroup G] [Module (ZMod n) G]
    (sha : Bytes → Bytes) (enc : G → Bytes) (g X R : G)
    (m₁ m₂ : Bytes) (_messagesDistinct : m₁ ≠ m₂) (x s₁ s₂ : ZMod n)
    (faithful : Function.Injective (fun a : ZMod n => a • g)) (key : X = x • g)
    (v₁ : Valid g X R (challenge n sha enc R X m₁) s₁)
    (v₂ : Valid g X R (challenge n sha enc R X m₂) s₂)
    (differentChallenges : challenge n sha enc R X m₁ ≠ challenge n sha enc R X m₂) :
    extract s₁ s₂ (challenge n sha enc R X m₁) (challenge n sha enc R X m₂) = x := by
  exact eots_extract g X R x s₁ s₂ _ _ faithful key v₁ v₂ differentChallenges

/- proved (unbounded, Lean); §9.2 boundary witness: a zero denominator cannot
   recover a nonzero secret. This explains why the source's distinct-message prose
   needs the extra challenge inequality. No collision probability is proved. -/
theorem equal_challenges_do_not_extract {F : Type*} [Field F] (s e x : F)
    (hx : x ≠ 0) : extract s s e e ≠ x := by
  simp [extract, Ne.symm hx]

/- assumed MODEL CHOICE, §§2,13.1-13.2: a narrow one-step shared-UTXO game.
   Adversary controls every online signer; victim sends no post-deposit messages.
   Inputs/traces below describe a tx paying victim `paid`, attacker `stolen`.
   NoCovenant requires that an admissible output-redirection exists under the
   same authorization set. That is an EXTRA scope assumption: it is not derived
   from the mere absence of a named opcode. Time/communication is one synchronous
   proposal/sign/inclusion step, no honest online co-signer, no enclave oracle.
   No claim is made about ALL Bitcoin protocols (e.g. segregated outputs). -/
structure SharedPoolGame where
  owed : Nat
  positive : 0 < owed
  authorized : Nat → Nat → Prop
  passive : Prop
  noCovenant : Prop
  redirect : passive → noCovenant → authorized 0 owed

def CryptographicAmountSafety (p : SharedPoolGame) : Prop :=
  ∀ paid stolen, p.authorized paid stolen → p.owed ≤ paid

/- proved (unbounded, Lean); §13.2 CONDITIONAL restricted impossibility.
   Load-bearing assumed premise: p.redirect. This theorem DOES NOT establish the
   broad trilemma from (a)+(b) alone, or a cryptographic impossibility reduction. -/
theorem restricted_trilemma (p : SharedPoolGame) (hp : p.passive) (hn : p.noCovenant) :
    ¬ CryptographicAmountSafety p := by
  intro safe
  have bad := safe 0 p.owed (p.redirect hp hn)
  exact Nat.not_le_of_gt p.positive bad

/- assumed conjecture (STATEMENT ONLY), §13.2; not an axiom or sorry theorem.
   To interpret it, provide a protocol class and semantics for each predicate.
   The broad source lacks that class/semantics and exclusions such as immutable
   segregated reserves. No result depends on this definition and it is NOT proved. -/
def BroadTrilemmaStatement (Protocol : Type*)
    (passive noCovenant amountSafe openSharedPool : Protocol → Prop) : Prop :=
  ∀ p, openSharedPool p → passive p → noCovenant p → ¬ amountSafe p

#print axioms eots_extract
#print axioms adaptor_complete
#print axioms extracted_key_completes
#print axioms eots_mod_prime
#print axioms equal_challenges_do_not_extract
#print axioms restricted_trilemma
end Pulse
