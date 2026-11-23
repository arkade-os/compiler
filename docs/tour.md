# A tour by example

Each section shows a short contract and explains what it compiles to. The [language reference](../README.md#language-reference) covers every rule in full.

> [!NOTE]
> The snippets are trimmed to one feature each. `Splitter` and `StructVault` compile with security [lint](lints.md) warnings that a real contract must address. The [`examples/`](#more-in-examples) directory holds complete contracts.

## One key, one exit

```solidity
contract SingleSig(pubkey user) {
  function spend(signature userSig) {
    require(checkSig(userSig, user));
  }

  function unilateral(signature userSig) tapscript {
    require(older(operatorExitDelay));
    require(checkSig(userSig, user));
  }
}
```

- `spend` has no modifier, so it is an Arkade Script function. Its body compiles to Arkade Script that the operator runs before it cosigns.
- `spend` declares no tapscript of its own, so the compiler synthesizes the collaborative L1 leaf `<OPERATOR_KEY:spend> OP_CHECKSIG` for it: the operator key tweaked by `spend`'s Arkade Script hash.
- `unilateral` is marked `tapscript`, so it is a pure L1 leaf: a CSV delay followed by the user's key.
- `operatorExitDelay` is the operator's unilateral exit delay. It lowers to `<OPERATOR_EXIT_DELAY>`, which the SDK fills from the operator's config, so it is not a constructor input.

## Hash and time locks

```solidity
import "single_sig.ark";

contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes20 preimageHash,
  int refundTime
) {
  @allow(unsigned-spend-path, "the claim leaf needs the preimage, and the output pays the receiver")
  function claim() {
    require(tx.outputs[this.activeInputIndex].script == new SingleSig(receiver));
    require(tx.outputs[this.activeInputIndex].value >= tx.input.current.value);
  }
  @allow(unsigned-spend-path, "the refund leaf needs the timeout, and the output pays the sender")
  function refund() {
    require(tx.outputs[this.activeInputIndex].script == new SingleSig(sender));
    require(tx.outputs[this.activeInputIndex].value >= tx.input.current.value);
  }

  function claim(bytes preimage, signature operatorSig) tapscript {
    require(hash160(preimage) == preimageHash);
    require(checkSig(operatorSig, tweak(operator, claim)));
  }
  function refund(signature operatorSig) tapscript {
    require(after(refundTime));
    require(checkSig(operatorSig, tweak(operator, refund)));
  }

  function unilateral(signature senderSig) tapscript {
    require(older(operatorExitDelay));
    require(checkSig(senderSig, sender));
  }
}
```

- An Arkade Script function and a tapscript function with the same name form one [spend group](language/functions.md#spend-groups).
- Here each Arkade Script function is a covenant: it pays at least the input's value to the receiver on `claim` or the sender on `refund`, at the output with the input's own index. The leaf with the same name is the L1 shape for that path.
- Each leaf signs with `tweak(operator, fn)`, the operator key tweaked by its function's Arkade Script hash, so the operator cosigns only once that Arkade Script passes.
- `operator` is the reserved key role the Arkade operator signs for, so its signatures, bare or tweaked, are marked `injected` in the artifact.
- Neither covenant checks a signature, so each allows the `unsigned-spend-path` [lint](lints.md) with a reason: the leaf supplies the preimage or the timeout, and the output is pinned. `new SingleSig(...)` is explained [next](#recursive-vtxos-with-new).

## Recursive VTXOs with `new`

```solidity
import "single_sig.ark";

contract Splitter(pubkey alicePk, pubkey bobPk) {
  function split() {
    require(tx.outputs[0].script == new SingleSig(alicePk));
    require(tx.outputs[1].script == new SingleSig(bobPk));
  }
}
```

- `new SingleSig(alicePk)` returns a `ScriptPubKey` with the child's 32-byte Taproot witness program and version `1`.
- The program uses the opaque placeholder `<CONTRACT:SingleSig(<alicePk>)>`, which the Arkade runtime resolves at instantiation.
- Whole-script equality checks both the program and version.
- Arguments are constructor parameters or literals, resolved when the contract is instantiated.
- The artifact pins the build of each instantiated contract in its [`contracts`](artifact.md#fields) field.

A contract cannot instantiate itself, directly or through other contracts, since its address would depend on itself. To keep funds in the same contract, compare against the input's own script with `tx.outputs[0].script == tx.input.current.script` (see [`examples/threshold_oracle`](../examples/threshold_oracle)).

The check goes by name, so it also rejects a `static` helper in `B` that returns `new B(...)`, which forms no loop.

## Assets

```solidity
contract TokenVault(
  pubkey ownerPk,
  AssetId tokenAssetId,
  AssetId ctrlAssetId
) {
  function deposit(signature ownerSig) {
    require(tx.inputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl in input");
    require(tx.outputs[0].assets.lookup(ctrlAssetId) > 0, "no ctrl in output");
    require(
      tx.outputs[0].assets.lookup(tokenAssetId) >=
        tx.inputs[0].assets.lookup(tokenAssetId),
      "token balance decreased"
    );
    require(checkSig(ownerSig, ownerPk), "invalid owner signature");
  }

  function unilateral(signature ownerSig) tapscript {
    require(older(operatorExitDelay));
    require(checkSig(ownerSig, ownerPk));
  }
}
```

- An Asset ID is an `AssetId` struct `{txid, gidx}`; write one as `AssetId { txid: t, gidx: 0 }`.
- `assets.lookup` asserts the asset is present on that input or output and yields its amount; `assets.has` is the boolean form.
- For supply accounting across the whole transaction, `tx.assetGroups.lookup(id)` returns an `AssetGroup` with `sumInputs`, `sumOutputs`, `delta`, `controlIs(id)`, and friends (see [`examples/controlled_mint`](../examples/controlled_mint)).

[Assets](language/builtins.md#assets) lists every member.

## Arrays, structs, loops

```solidity
struct Signer {
  pubkey key;
  int weight;
}

struct Policy {
  Signer primary;
  int[2] limits;
  int exitDelay;
}

contract StructVault(Policy policy) {
  function update(Policy next, signature sig, bytes32 message) {
    require(checkSigFromStack(sig, policy.primary.key, message));

    int total = 0;
    for (i, limit) in next.limits {
      total = total + limit;
    }
    require(total >= policy.primary.weight);

    Policy local = {
      primary: Signer { key: next.primary.key, weight: total },
      limits: [next.limits[0], next.limits[1]],
      exitDelay: policy.exitDelay
    };
    require(local.primary.weight == total);
  }

  function unilateral(signature sig) tapscript {
    require(older(policy.exitDelay));
    require(checkSig(sig, policy.primary.key));
  }
}
```

- Arrays are fixed-size and part of the type.
- Loops unroll at compile time, one copy per element, so script size grows with the declared size. A loop that runs zero times is a compile error. A loop may unroll at most 10,000 iterations, counting the loops nested in it.
- Structs flatten to their scalar leaves. The artifact keeps the declaration so clients can flatten the same way.
- A struct literal names its type, as in `Signer { key: k, weight: 1 }`, or leaves it to its position, as `local` and its `limits` do.

[`examples/threshold_oracle`](../examples/threshold_oracle) shows the same machinery counting `checkSigFromStack` successes over `pubkey[3] oracles` to enforce a quorum.

## More in `examples/`

| Directory | Shows |
|---|---|
| [`single_sig`](../examples/single_sig), [`htlc`](../examples/htlc) | Minimum viable VTXO and hash/time locks |
| [`escrow`](../examples/escrow) | Oracle release to a committed script, timeout refund, joint CSV exit signed by both parties; `escrow.md` |
| [`non_interactive_swap`](../examples/non_interactive_swap) | Atomic asset swap with `new SingleSig(...)` payout and locktime-gated cancel |
| [`constant_product`](../examples/constant_product) | Shared constant-product pool: one standing swap, deposit, or exit per virtual transaction; `constant_product.md` |
| [`payment_auth`](../examples/payment_auth) | Introspection-driven payout splits with `if`/`else` and `tx.input.current.value` |
| [`controlled_mint`](../examples/controlled_mint), [`nft_mint`](../examples/nft_mint) | Asset lookups, asset groups, control assets |
| [`threshold_oracle`](../examples/threshold_oracle) | Arrays, loops, oracle quorum |
| [`bonds`](../examples/bonds) | Per-issuance collateral vault for a fixed-maturity bond, with repay, liquidate, auction and roll paths |
| [`option`](../examples/option) | Cash-settled covered call and limited put with an on-stack oracle TWAP |
| [`layerzero`](../examples/layerzero) | Packet introspection, `substr`/`cat`/`bytes2uint`, cross-input binding via `arkadeScriptHash` |

The `.md` files next to those contracts explain the economics and transaction layouts.
