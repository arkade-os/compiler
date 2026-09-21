# Escrow — How It Works

A marketplace escrow with three spending paths, upgraded from the signature-only
2-of-3 construction so that no path depends on a counterparty signing the
settlement transaction.

---

## What changed

The escrow documented at
[docs.arkadeos.com/contracts/escrow](https://docs.arkadeos.com/contracts/escrow)
is three tapscript leaves built by hand from SDK helpers:

| Path | Old condition |
|---|---|
| Collaborative | buyer + seller + server signatures |
| Arbiter | arbiter + server signatures |
| Refund | buyer + server signatures, after 30 days |

Nothing in those scripts says where the money goes. The leaf authorizes a
spend; the destination is whatever the transaction happens to pay. That is why
every path needs a counterparty: the seller signs the release because their
signature is the only thing standing between the buyer and a transaction that
pays the buyer instead. The arbiter has to see and sign each settlement
transaction for the same reason.

`escrow.ark` keeps the same three paths and moves the destination into the
covenant:

| Path | New condition | Payout enforced by |
|---|---|---|
| `release` | buyer signature | covenant → seller |
| `refund` | absolute locktime, no key | covenant → buyer |
| `resolve` | oracle attestation over a verdict | covenant → attested split |

Three signatures disappear, and each one was a liveness requirement:

**The seller's.** `release` pins output 0 to `new SingleSig(sellerPk, exit)`, so
the only transaction the buyer can get co-signed is the one that pays the
seller. A seller who is offline, or who simply stops answering, can no longer
stall their own payment.

**Everyone's, on the refund.** `refund` collects no witness at all. Past
`refundLocktime` the transaction is fully determined — full value, to the buyer
— so the operator, a watchtower, or the seller can push it, and it can only
land on the buyer.

**The mediator's.** `resolve` verifies a signed verdict instead of a
transaction signature. The mediator signs one 32-byte message off-line and is
done; they never see the transaction, never hold a co-signing key that has to
be online at settlement, and never learn who the parties are or how much is at
stake. `dealId` is an opaque handle, so a single blinded key can arbitrate many
deals without learning any of them. The verdict names a *share*, not a
destination, and the covenant turns it into outputs.

---

## Attestation format

The mediator's signer builds the message and nothing else:

```
msg = sha256(dealId || num2bin(sellerShareBps, 8) || num2bin(attestedAt, 8))
sig = schnorr_sign(oracleKey, msg)
```

- `dealId` — the 32 bytes committed in the constructor. It is part of the
  scriptPubKey, so a verdict issued for one deal is worthless against another.
- `sellerShareBps` — the seller's share in basis points, `0` to `10000`,
  little-endian in 8 bytes (`OP_NUM2BIN`).
- `attestedAt` — Unix seconds, same encoding. The covenant requires
  `checkTime(attestedAt)`, so a post-dated verdict is not yet a verdict.

The covenant recomputes the hash from the constructor's `dealId` and the two
values the spender presents, then checks the signature with
`OP_CHECKSIGFROMSTACK` against the committed `oraclePk`. Presenting a different
share than the one that was signed changes the hash and fails the check.

---

## Transaction layouts

Payouts are `new SingleSig(pk, exit)` — real Arkade VTXOs with their own
unilateral exit, resolved by the runtime from the committed key.

```
release (buyer signs)
  input[0]:  Escrow VTXO
  output[0]: SingleSig(sellerPk)     full escrow value

refund (no witness, nLockTime >= refundLocktime)
  input[0]:  Escrow VTXO
  output[0]: SingleSig(buyerPk)      full escrow value

resolve (oracle verdict)                       net = value − mediationFee
  sellerShareBps == 10000
    output[0]: SingleSig(sellerPk)   net
    output[1]: SingleSig(mediatorPk) mediationFee
  sellerShareBps == 0
    output[0]: SingleSig(buyerPk)    net
    output[1]: SingleSig(mediatorPk) mediationFee
  otherwise
    output[0]: SingleSig(sellerPk)   net × sellerShareBps / 10000
    output[1]: SingleSig(buyerPk)    the remainder
    output[2]: SingleSig(mediatorPk) mediationFee
```

The branch is selected by the attested share, not by a derived amount, so a
client can lay out the transaction from the verdict alone before doing any
arithmetic. Amounts are checked with `>=`: the three shares re-add to the input
value, so paying one party more necessarily shorts another and fails.

`oraclePk` and `mediatorPk` are separate on purpose. The first verifies the
attestation and may be blinded per deal; the second receives the fee and has to
be a key someone can actually spend from.

Truncating division puts the remainder on the buyer's side, so nothing is
stranded. A split verdict must leave both parties above the 330-sat dust
threshold — the mediator rounds to `0` or `10000` rather than stranding a
party — and `mediationFee` must itself be above dust, since a mediator cannot
be paid a sub-dust output.

---

## Unilateral exit

Any two of buyer, seller and mediator, after the CSV delay:

```ark
function exitBuyerSeller(signature buyerSig, signature sellerSig) tapscript {
  require(older(exit));
  require(checkMultisig([buyerPk, sellerPk], [buyerSig, sellerSig], 2));
}
// ...and exitBuyerMediator, exitSellerMediator
```

Three leaves rather than one, because arkd recognizes only N-of-N closures, so
a 2-of-3 is enumerated as its pairs. Clients build the taproot tree from
artifact order, which is the order these are declared.

This is the same 2-of-3 the escrow always was, kept for exactly one case: the
emulator stops co-signing. Every covenant path is then unreachable, and the
contract needs some way out that does not depend on it.

The obvious choice — buyer and seller together — is wrong here. It strands the
funds precisely when the two disagree, which is when an escrow matters.
Including the mediator gives a disputed deal a way out. A single-key exit is
wrong for the opposite reason: it hands that party the escrow outright once the
delay elapses.

State the trade plainly rather than claiming the contract is trustless. While
the emulator is alive, nothing moves except as the covenants allow and no two
parties can collude. Once these leaves mature, any two of the three can move
the funds anywhere. That is a liveness requirement and a trust assumption,
accepted in exchange for never freezing the escrow. The mediator is already
trusted to arbitrate; this widens that to "can move funds with one party's
help, but only after the operator has gone away and the delay has run".

The covenant paths get the synthesized collaborative leaf — `server` plus the
emulator key tweaked by that covenant's hash — so the introspection rules above
are what the emulator co-signs against.

---

## Known ceiling

`release` and `refund` race after `refundLocktime`, exactly as an HTLC's claim
and refund do. A verdict stays spendable past the deadline, so a mediation that
runs long can be beaten by the buyer's refund. Set `refundLocktime` beyond the
mediation SLA and have the winning party broadcast on receipt.

Closing the race needs contract state that records an open dispute, which costs
a state-transition spend and a second VTXO round trip. Add it when mediation
routinely outruns the refund window.

---

## Verification

`tests/examples/escrow.rs` locks the artifact shape: the spend groups, that
`release` checks exactly one transaction signature, that `refund` has no
covenant inputs and no signature check at all, that `resolve` has zero
`OP_CHECKSIG` and exactly one `OP_CHECKSIGFROMSTACK`, and that every payout is
a `<VTXO:...>` placeholder rather than a spender-supplied script.

`tests/e2e/escrow_test.go` runs the compiled artifact through the Arkade VM and
the Bitcoin script engine: each path settles, and the VM rejects a redirected
payout, a shorted seller, a release signed by the wrong party, a refund before
its locktime, a forged verdict, a verdict whose share was changed after
signing, a verdict issued for another deal, a post-dated verdict, a shorted
mediator, and a split whose party outputs were swapped.
