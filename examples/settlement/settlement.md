# Settlement — Porting a Liquid/SimplicityHL Contract

`settlement.ark` is an Arkade port of a production Liquid contract: a
two-party settlement where an oracle attests that a real-world event happened,
and a timeout returns the funds if it never does. The original is written in
SimplicityHL and compiles to a Liquid Taproot address.

This page is the mapping. It exists so that someone holding the SimplicityHL
source can see what each construct becomes, what stops being necessary, and
what the port changes on purpose.

---

## The two paths

| Path | Original | Port |
|---|---|---|
| complete | oracle attestation **+ party B signature** → funds to party B | oracle attestation → funds to party B, surplus to party A |
| cancel | timeout, no signature → funds to party A | timeout, no signature → funds to party A |

`cancel` is a straight translation. `complete` loses party B's signature; see
[What the port changes](#what-the-port-changes).

---

## Construct by construct

| SimplicityHL | Arkade | Note |
|---|---|---|
| `param::X` baked into the CMR | constructor parameter | Same idea: different arguments produce a different program and a different address. |
| `witness::COMPLETE_OR_CANCEL` as `Either`, dispatched in `main` | one named spend function per path | The path is chosen by which tapleaf is spent, not by a witness tag. |
| `jet::sha_256_ctx_8_init` → `_add_32` → `_finalize` | `sha256(x)` | The three-step context is the built-in. |
| `jet::bip_0340_verify((pk, msg), sig)` | `checkSigFromStack(sig, pk, msg)` | Signature over a message. |
| `jet::sig_all_hash()` + `jet::bip_0340_verify` (the `checksig` helper) | `checkSig(sig, pk)` | Signature over the spending transaction. The port uses neither. |
| `jet::check_lock_height(h)` | `require(tx.time >= h)` | In a covenant this reads the locktime with `OP_INSPECTLOCKTIME`. `after(h)` is the tapscript form. |
| `jet::output_script_hash(i)` compared to `param::PARTY_*_SCRIPT_HASH` | `tx.outputs[i].scriptPubKey == partyAScript` | See [Destination scripts](#destination-scripts). |
| `jet::output_is_fee(i)`, `jet::total_fee`, `param::MAX_FEE`, `param::LBTC_ASSET` | — | No counterpart; see below. |
| `unwrap(...)` on optional jets, `match None => {}` | — | Out-of-range output indices are not a case the contract handles. |
| — | `function unilateral(...) tapscript` | New. An Arkade VTXO needs a way out if the operator stops responding; a Liquid UTXO is already on chain. |

---

## What stops being necessary

**The fee cap.** The original spends four of its parameters and two helpers on
one problem: `cancel` is permissionless, so whoever broadcasts it could dump
the locked balance into Liquid's explicit fee output instead of paying party A.
`check_fee` bounds that with `MAX_FEE` against `LBTC_ASSET`.

An Arkade transaction has no value-bearing fee output — the only outputs the
SDK appends are a zero-value P2A anchor and a zero-value extension
`OP_RETURN` — and the port pins the payout amount rather than only its
destination. There is nowhere for a griefer to put the money. The
`the refund cannot be skimmed` case in `tests/e2e/settlement_test.go` is that
attempt, rejected.

**The output-count guard.** `bind_outputs` checks outputs 0, 1 and 2 against a
whitelist and then rejects a fourth, because an unchecked output could carry
value away. The port asserts an amount on every output it names, and those
amounts account for the whole input, so a further output has to be funded by
another input — someone else's money, not the settlement's.

**The script whitelist itself.** `check_output(idx, allow_b)` is a nested match
that accepts any of {out of range, fee output, party A, party B} at every
index. It has to be permissive because the original does not pin amounts: the
split between A and B is whatever party B signed for. Pinning the amounts makes
each output index a single specific payout, so the check collapses to two
`require`s.

---

## What the port changes

**Party B no longer signs.** In the original, B's signature is not what
authorizes the settlement — the oracle attestation is. B signs because
`bind_outputs(true)` allows any split between A and B, so B's signature over
the whole transaction is what fixes the amounts. Once the covenant fixes them,
that signature carries no information, and dropping it removes a liveness
requirement: an agent, a keeper, or either party can broadcast the settlement
and it still can only pay the committed destinations.

The trade is real and worth stating: the amount is committed at funding time as
`settlementAmount` instead of being negotiated when the settlement is claimed.
For a settlement whose figure is agreed up front this is the better shape. For
one where the final figure is discovered later, keep a party signature and
leave the amount free — that is the original's design, and it ports directly.

**A sub-dust surplus is refused rather than absorbed.** The original allows any
split, so an awkward remainder is party B's problem to accept. The port will
not fold party A's surplus into party B's output, because it is party A's
money: fund exactly, or fund more than dust above `settlementAmount`.

---

## What stays the same on purpose

The oracle attests **one pre-agreed message**, committed as
`oracleMessageHash`:

```
oracleMsg         = sha256(<agreed settlement statement>)
oracleMessageHash = sha256(oracleMsg)      // committed in the contract
oracleSig         = schnorr_sign(oracleKey, oracleMsg)
```

This is the strongest property in the original and the port keeps it exactly.
An oracle key can only assert that this one event happened. It cannot name a
different outcome, a different amount, or a different payee, so a compromised
oracle key is not a way to move money — only a way to trigger, or withhold, the
one settlement the parties already agreed to. Committing the hash rather than
the message also keeps the statement private until the settlement is claimed.

`examples/escrow` makes the opposite trade: its oracle signs a settlement
*share*, which buys partial and disputed outcomes at the cost of having to
trust the oracle with the split. Neither is strictly better. Pick the one whose
failure mode you can live with.

---

## Destination scripts

`partyAScript` and `partyBScript` are compared against
`tx.outputs[i].scriptPubKey`, which `OP_INSPECTOUTPUTSCRIPTPUBKEY` reports as
the 32-byte witness program with the witness version dropped. For a Taproot
destination, commit the output key. This lets a party be paid to a wallet it
already has, rather than to a contract-shaped VTXO — `examples/escrow` takes
the other route and pins payouts to `new SingleSig(pk, exit)`, which produces
an Arkade VTXO carrying its own unilateral exit.

---

## Client side

The compiled artifact converts to the TypeScript SDK's Program JSON with
`cargo run -p arkade-bindgen -- settlement.json --lang sdk-program`. This
contract instantiates no child contracts, so the only values a client binds are
the nine constructor parameters plus `server`.

---

## Verification

`tests/e2e/settlement_test.go` runs the compiled artifact through the Arkade VM
and the Bitcoin script engine. Both paths settle, and the VM rejects a
settlement attested by the wrong key, an attestation of a different message, a
redirected payout, a shorted party B, a surplus folded into party B's output, a
sub-dust surplus, a refund before the timeout, a refund sent to party B, a
refund skimmed into a third output, and a unilateral exit by one party alone.
