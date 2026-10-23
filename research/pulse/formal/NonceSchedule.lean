/- Draft model for source revision 2.2, §9.2 and finding A24. Mathlib-free: these
   are side conditions on a signing SCHEDULE, not facts about any group.

   `Pulse.eots_extract` (Pulse.lean) proves extraction is possible when one nonce
   carries two distinct challenges. That theorem is an asset when an equivocator
   triggers it and a LIABILITY when the protocol's own schedule does. This file
   states the side condition separating the two cases, and shows the revision-2.1
   per-epoch schedule fails it while the revision-2.2 per-(epoch, role) schedule
   satisfies it. Distinct challenges are assumed to follow from distinct messages
   under the collision-resistance premise recorded in §9.2. -/
namespace Pulse.Schedule

/-- A signing schedule: every artifact is assigned a slot, every slot a committed
    nonce, and every artifact the message actually signed. -/
structure Schedule (Artifact Slot Nonce Msg : Type) where
  slot  : Artifact → Slot
  nonce : Slot → Nonce
  msg   : Artifact → Msg

variable {A Sl N M : Type}

/-- Stated inline to keep this file free of any dependency: distinct slots get
    distinct committed nonces. -/
def Injective {X Y : Type} (f : X → Y) : Prop := ∀ a b, f a = f b → a = b

/-- The §9.2 extraction hypothesis lifted to a whole schedule: two artifacts
    emitted under one committed nonce carrying distinct messages. When this holds
    of a signer's OWN schedule, honest operation leaks the signer's key (A24). -/
def SelfExtracting (S : Schedule A Sl N M) : Prop :=
  ∃ a b, S.nonce (S.slot a) = S.nonce (S.slot b) ∧ S.msg a ≠ S.msg b

/-- The obligation a sound schedule must discharge: a slot signs one message. -/
def OneMessagePerSlot (S : Schedule A Sl N M) : Prop :=
  ∀ a b, S.slot a = S.slot b → S.msg a = S.msg b

/-- proved (unbounded, Lean); §9.2/A24 safety condition. An injective nonce
    commitment plus one message per slot rules out self-extraction. Neither
    hypothesis alone suffices: `perEpoch` below is injective yet unsafe. -/
theorem no_self_extraction (S : Schedule A Sl N M)
    (hinj : Injective S.nonce) (hone : OneMessagePerSlot S) :
    ¬ SelfExtracting S := by
  rintro ⟨a, b, hn, hm⟩
  exact hm (hone a b (hinj _ _ hn))

/-- Artifacts the operator threshold signs each epoch: `false` = attestation A_k,
    `true` = commitment h_k. Messages are distinct per (epoch, role) by
    construction, which is exactly the situation §9.2 describes. -/
abbrev Role := Bool
abbrev Artifact := Nat × Role

/-- revision 2.1: the commitment is indexed by epoch alone. -/
def perEpoch : Schedule Artifact Nat Nat Artifact :=
  { slot := Prod.fst, nonce := id, msg := id }

/-- revision 2.2: the commitment is indexed by (epoch, role). -/
def perRole : Schedule Artifact Artifact Artifact Artifact :=
  { slot := id, nonce := id, msg := id }

/-- proved (unbounded, Lean); A24. The per-epoch schedule cannot discharge the
    one-message-per-slot obligation: both roles of one epoch share a slot. -/
theorem perEpoch_not_oneMessagePerSlot : ¬ OneMessagePerSlot perEpoch := by
  intro h
  exact absurd (h (0, false) (0, true) rfl) (by decide)

/-- proved (unbounded, Lean); A24, the honest-operation self-slash itself. No
    adversary, no crash: signing A_k then h_k in one epoch meets the extraction
    hypothesis, so the signer's own key is recoverable from its own artifacts. -/
theorem perEpoch_selfExtracting : SelfExtracting perEpoch :=
  ⟨(0, false), (0, true), rfl, by decide⟩

/-- proved (unbounded, Lean); the revision-2.2 fix. Indexing by (epoch, role)
    discharges both hypotheses, so no honest schedule self-extracts. -/
theorem perRole_no_self_extraction : ¬ SelfExtracting perRole :=
  no_self_extraction perRole (fun _ _ h => h) (fun _ _ h => h)

#print axioms no_self_extraction
#print axioms perEpoch_not_oneMessagePerSlot
#print axioms perEpoch_selfExtracting
#print axioms perRole_no_self_extraction

end Pulse.Schedule
