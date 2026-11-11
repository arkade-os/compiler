package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	hashpriceBeaconValue = int64(10_000)
	hashpriceCollateral  = int64(50_000)
	hashpriceDust        = int64(330)
	hashpriceStateType   = 16
	// The beacon holds one unit. The minter starts with eight and each mint
	// clones four attestations, leaving the rest for the next header update.
	hashpricePool   = uint64(8)
	hashpriceFanout = uint64(4)
	// 0x1f00ffff is difficulty 2^-16, about 2^16 hashes, so a test can mine
	// the six headers. The covenant applies the same compact-target and
	// hashprice formula it would use for a mainnet epoch.
	hashpriceBits     = uint32(0x1f00ffff)
	checkpointHeight  = int64(100)
	hashpriceHeaderAt = uint32(1_700_000_000)
	hashpriceStep     = uint32(600)
)

// subsidyQuote is the era-0 quote at hashpriceBits for a 3000-second window:
// 2^15 * 3^3 * 5^27 sats per PH/s per day.
func subsidyQuote() *big.Int {
	quote := new(big.Int).Lsh(big.NewInt(1), 15)
	quote.Mul(quote, big.NewInt(27))
	five := big.NewInt(5)
	for range 27 {
		quote.Mul(quote, five)
	}
	return quote
}

func TestHashprice(t *testing.T) {
	beaconContract := compileArtifact(t, filepath.Join("..", "..", "examples", "hashprice", "hashprice_beacon.ark"))
	minterContract := compileArtifact(t, filepath.Join("..", "..", "examples", "hashprice", "hashprice_minter.ark"))
	attestationContract := compileArtifact(t, filepath.Join("..", "..", "examples", "hashprice", "hashprice_attestation.ark"))
	optionContract := compileArtifact(t, filepath.Join("..", "..", "examples", "hashprice", "hashprice_option.ark"))

	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	holderKey := fixedPrivateKey(4)
	writerKey := fixedPrivateKey(5)

	checkpoint := bytes.Repeat([]byte{0xA1}, 32)
	shared := sharedAsset()
	holderProgram := bytes.Repeat([]byte{0x11}, 32)
	writerProgram := bytes.Repeat([]byte{0x22}, 32)
	beaconKey := "CONTRACT:HashpriceBeacon(<checkpoint>,<checkpointHeight>,<bits>,<shared.txid>,<shared.gidx>)"
	attestationKey := "CONTRACT:HashpriceAttestation(<checkpoint>,<checkpointHeight>,<bits>,<shared.txid>,<shared.gidx>)"

	parameters := func(height int64) map[string][]byte {
		return map[string][]byte{
			"checkpoint":       append([]byte{}, checkpoint...),
			"checkpointHeight": scriptInt(t, height),
			"bits":             scriptInt(t, int64(hashpriceBits)),
			"shared.txid":      shared.Txid[:],
			"shared.gidx":      scriptInt(t, int64(shared.Index)),
		}
	}
	deploy := func(height int64) sharedTree {
		t.Helper()
		return instantiateSharedTree(
			t, beaconContract, []string{"update", "passthrough"}, parameters(height),
			serverKey.PubKey(), emulatorKey.PubKey(),
		)
	}
	beacon := deploy(checkpointHeight)
	attestation := instantiateSharedTree(
		t, attestationContract, []string{"copy", "consume"}, parameters(checkpointHeight),
		serverKey.PubKey(), emulatorKey.PubKey(),
	)
	minterValues := parameters(checkpointHeight)
	minterValues[beaconKey] = beacon.pkScript[2:]
	minterValues[attestationKey] = attestation.pkScript[2:]
	minter := instantiateSharedTree(
		t, minterContract, []string{"advance", "mint", "copy"}, minterValues,
		serverKey.PubKey(), emulatorKey.PubKey(),
	)
	chain := mineChain(t, checkpoint, hashpriceHeaderAt, hashpriceStep)
	price := hashpriceQuote(checkpointHeight+6, int64(5*hashpriceStep), hashpriceBits)
	if price.Cmp(subsidyQuote()) != 0 {
		t.Fatalf("ten-minute window quotes %s, closed form is %s", price, subsidyQuote())
	}
	fast := mineChain(t, checkpoint, hashpriceHeaderAt, hashpriceStep/2)
	fastPrice := hashpriceQuote(checkpointHeight+6, int64(5*hashpriceStep/2), hashpriceBits)
	if fastPrice.Cmp(new(big.Int).Rsh(price, 1)) != 0 {
		t.Fatalf("faster window %s is not half of %s", fastPrice, price)
	}

	noteBase := parameters(checkpointHeight)
	noteBase["holderPk"] = schnorr.SerializePubKey(holderKey.PubKey())
	noteBase["writerPk"] = schnorr.SerializePubKey(writerKey.PubKey())
	noteBase["holderScript.program"] = holderProgram
	noteBase["holderScript.version"] = scriptInt(t, 1)
	noteBase["writerScript.program"] = writerProgram
	noteBase["writerScript.version"] = scriptInt(t, 1)
	noteBase["SERVER_EXIT_DELAY"] = scriptInt(t, 144)
	noteBase[attestationKey] = attestation.pkScript[2:]

	genesis := fundBeacon(t, beacon.pkScript, beaconState(t, checkpoint, checkpointHeight, big.NewInt(0)))
	continued := beaconOut(hashpriceBeaconValue, beacon.pkScript)
	attestationOut := beaconOut(hashpriceBeaconValue, attestation.pkScript)
	minterOut := beaconOut(hashpriceBeaconValue, minter.pkScript)
	published := beaconState(t, chain.tip, checkpointHeight+6, price)
	held := assetMovement(
		[]asset.AssetInput{assetIn(0, 1)},
		[]asset.AssetOutput{assetOut(0, 1)},
	)
	pair := assetMovement(
		[]asset.AssetInput{assetIn(0, 1), assetIn(1, hashpricePool)},
		[]asset.AssetOutput{assetOut(0, 1), assetOut(1, hashpricePool)},
	)
	cloned := assetMovement(
		[]asset.AssetInput{assetIn(0, hashpricePool)},
		[]asset.AssetOutput{
			assetOut(0, hashpricePool-hashpriceFanout),
			assetOut(1, 1), assetOut(2, 1), assetOut(3, 1), assetOut(4, 1),
		},
	)
	burned := assetMovement([]asset.AssetInput{assetIn(0, 1)}, nil)
	clones := []*wire.TxOut{minterOut, attestationOut, attestationOut, attestationOut, attestationOut}

	update := func(prev *wire.MsgTx, headers [][]byte, output *wire.TxOut, state []byte, packet asset.Packet) *psbt.Packet {
		t.Helper()
		group := covenantGroup(t, beaconContract, "update")
		witness := covenantWitness(t, beaconContract, group, headerWitness(headers))
		return hashpriceTx(t, []covenantInput{
			{prev: prev, path: beacon.paths["update"], witness: witness},
			{prev: fundingTx(minter.pkScript, hashpriceBeaconValue), path: minter.paths["advance"]},
		}, []*wire.TxOut{output, minterOut}, packet, state)
	}
	mint := func(prev *wire.MsgTx, vout uint32, state []byte, outs []*wire.TxOut, packet asset.Packet) *psbt.Packet {
		t.Helper()
		return hashpriceTx(t, []covenantInput{{
			prev: prev, vout: vout, path: minter.paths["mint"],
		}}, outs, packet, state)
	}
	optionOf := func(collateral int64, strike *big.Int) instantiatedGroup {
		t.Helper()
		values := map[string][]byte{}
		for key, value := range noteBase {
			values[key] = value
		}
		values["collateral"] = scriptInt(t, collateral)
		values["strike"] = scriptBigInt(t, strike)
		return instantiateGroup(
			t, optionContract, "settle", values, serverKey.PubKey(), emulatorKey.PubKey(),
		)
	}
	strike := new(big.Int).Rsh(new(big.Int).Set(price), 1)
	standard := optionOf(hashpriceCollateral, strike)
	passthroughOf := func(prev *wire.MsgTx) covenantInput {
		return covenantInput{prev: prev, path: beacon.paths["passthrough"]}
	}
	settle := func(prev *wire.MsgTx, vout uint32, option instantiatedGroup, locked int64, outputs []*wire.TxOut) *psbt.Packet {
		t.Helper()
		return hashpriceTx(t, []covenantInput{
			{prev: prev, vout: vout, path: attestation.paths["consume"]},
			{prev: fundingTx(option.pkScript, locked), path: scriptPath{covenant: option.covenant, leaf: option.tapLeafScript}},
		}, outputs, burned, published)
	}
	pay := func(value int64, program []byte) *wire.TxOut {
		return &wire.TxOut{Value: value, PkScript: p2trTo(program)}
	}
	holderAmt := holderPayoff(t, hashpriceCollateral, price, strike)
	writerAmt := hashpriceCollateral - holderAmt

	t.Run("update", func(t *testing.T) {
		t.Run("six headers publish the extrapolated hashprice", func(t *testing.T) {
			requireVMResult(t, update(genesis, chain.headers, continued, published, pair), emulatorKey.PubKey(), "")
		})
		t.Run("a faster window extrapolates a lower hashprice", func(t *testing.T) {
			state := beaconState(t, fast.tip, checkpointHeight+6, fastPrice)
			requireVMResult(t, update(genesis, fast.headers, continued, state, pair), emulatorKey.PubKey(), "")
		})
		t.Run("passthrough copies the checkpoint packet", func(t *testing.T) {
			requireVMResult(t, hashpriceTx(t, []covenantInput{
				passthroughOf(genesis),
			}, []*wire.TxOut{continued}, held, beaconState(t, checkpoint, checkpointHeight, big.NewInt(0))), emulatorKey.PubKey(), "")
		})
		t.Run("the height must advance in steps of six", func(t *testing.T) {
			prev := fundBeacon(t, beacon.pkScript, beaconState(t, checkpoint, checkpointHeight+3, big.NewInt(0)))
			requireVMResult(t, update(prev, chain.headers, continued, published, held), emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("the genesis packet must be the checkpoint", func(t *testing.T) {
			prev := fundBeacon(t, beacon.pkScript, beaconState(t, bytes.Repeat([]byte{0xB2}, 32), checkpointHeight, big.NewInt(0)))
			requireVMResult(t, update(prev, chain.headers, continued, published, held), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("a window that crosses a retarget is rejected", func(t *testing.T) {
			retarget := deploy(2010)
			prev := fundBeacon(t, retarget.pkScript, beaconState(t, checkpoint, 2010, big.NewInt(0)))
			group := covenantGroup(t, beaconContract, "update")
			witness := covenantWitness(t, beaconContract, group, headerWitness(chain.headers))
			spent := hashpriceTx(t, []covenantInput{{
				prev: prev, path: retarget.paths["update"], witness: witness,
			}}, []*wire.TxOut{beaconOut(hashpriceBeaconValue, retarget.pkScript)}, held, published)
			requireVMResult(t, spent, emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("a window that crosses a halving is rejected", func(t *testing.T) {
			halving := deploy(209994)
			prev := fundBeacon(t, halving.pkScript, beaconState(t, checkpoint, 209994, big.NewInt(0)))
			group := covenantGroup(t, beaconContract, "update")
			witness := covenantWitness(t, beaconContract, group, headerWitness(chain.headers))
			spent := hashpriceTx(t, []covenantInput{{
				prev: prev, path: halving.paths["update"], witness: witness,
			}}, []*wire.TxOut{beaconOut(hashpriceBeaconValue, halving.pkScript)}, held, published)
			requireVMResult(t, spent, emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("a future tip is rejected", func(t *testing.T) {
			future := mineChain(t, checkpoint, 4_102_444_800, hashpriceStep)
			state := beaconState(t, future.tip, checkpointHeight+6, hashpriceQuote(checkpointHeight+6, int64(5*hashpriceStep), hashpriceBits))
			requireVMResult(t, update(genesis, future.headers, continued, state, held), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("a header that does not link is rejected", func(t *testing.T) {
			headers := cloneHeaders(chain.headers)
			headers[1][4] ^= 0xff
			requireVMResult(t, update(genesis, headers, continued, published, held), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("a header with different nBits is rejected", func(t *testing.T) {
			headers := cloneHeaders(chain.headers)
			binary.LittleEndian.PutUint32(headers[0][72:76], hashpriceBits^1)
			requireVMResult(t, update(genesis, headers, continued, published, held), emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("a header that misses its target is rejected", func(t *testing.T) {
			headers := cloneHeaders(chain.headers)
			nonce := binary.LittleEndian.Uint32(headers[0][76:80])
			binary.LittleEndian.PutUint32(headers[0][76:80], nonce+1)
			requireVMResult(t, update(genesis, headers, continued, published, held), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("the output hashprice must be the one the headers imply", func(t *testing.T) {
			wrong := beaconState(t, chain.tip, checkpointHeight+6, new(big.Int).Add(price, big.NewInt(1)))
			requireVMResult(t, update(genesis, chain.headers, continued, wrong, held), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("the beacon value cannot be skimmed", func(t *testing.T) {
			requireVMResult(
				t, update(genesis, chain.headers, beaconOut(hashpriceBeaconValue-1, beacon.pkScript), published, held),
				emulatorKey.PubKey(), "does not preserve source value",
			)
		})
		t.Run("the asset cannot be inflated", func(t *testing.T) {
			inflated := assetMovement(
				[]asset.AssetInput{assetIn(0, 1), assetIn(1, hashpricePool)},
				[]asset.AssetOutput{assetOut(0, 1), assetOut(1, hashpricePool+1)},
			)
			requireVMResult(t, update(genesis, chain.headers, continued, published, inflated), emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("the minter cannot move to another script", func(t *testing.T) {
			spent := hashpriceTx(t, []covenantInput{
				{prev: genesis, path: beacon.paths["update"], witness: covenantWitness(t, beaconContract, covenantGroup(t, beaconContract, "update"), headerWitness(chain.headers))},
				{prev: fundingTx(minter.pkScript, hashpriceBeaconValue), path: minter.paths["advance"]},
			}, []*wire.TxOut{continued, pay(hashpriceBeaconValue, writerProgram)}, pair, published)
			requireVMResult(t, spent, emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
	})

	t.Run("mint", func(t *testing.T) {
		updated := update(genesis, chain.headers, continued, published, pair)
		requireVMResult(t, updated, emulatorKey.PubKey(), "")

		t.Run("the minter clones four attestations and keeps the rest", func(t *testing.T) {
			requireVMResult(t, mint(updated.UnsignedTx, 1, published, clones, cloned), emulatorKey.PubKey(), "")
		})
		t.Run("the published packet has to be the minter's packet", func(t *testing.T) {
			moved := append([]byte{}, published...)
			moved[55] ^= 0xff
			requireVMResult(t, mint(updated.UnsignedTx, 1, moved, clones, cloned), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("the genesis packet cannot be attested", func(t *testing.T) {
			seeded := fundBeacon(t, minter.pkScript, beaconState(t, checkpoint, checkpointHeight, big.NewInt(0)))
			requireVMResult(t, mint(
				seeded, 0, beaconState(t, checkpoint, checkpointHeight, big.NewInt(0)), clones, cloned,
			), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("a clone cannot use another script", func(t *testing.T) {
			hijacked := []*wire.TxOut{minterOut, attestationOut, pay(hashpriceBeaconValue, writerProgram), attestationOut, attestationOut}
			requireVMResult(t, mint(updated.UnsignedTx, 1, published, hijacked, cloned), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("the pool cannot move to another script", func(t *testing.T) {
			hijacked := []*wire.TxOut{pay(hashpriceBeaconValue, writerProgram), attestationOut, attestationOut, attestationOut, attestationOut}
			requireVMResult(t, mint(updated.UnsignedTx, 1, published, hijacked, cloned), emulatorKey.PubKey(), "does not preserve source script")
		})
		t.Run("a positive delta is rejected", func(t *testing.T) {
			inflated := assetMovement(
				[]asset.AssetInput{assetIn(0, hashpricePool)},
				[]asset.AssetOutput{
					assetOut(0, hashpricePool),
					assetOut(1, 1), assetOut(2, 1), assetOut(3, 1), assetOut(4, 1),
				},
			)
			requireVMResult(t, mint(updated.UnsignedTx, 1, published, clones, inflated), emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("the remainder cannot mint again", func(t *testing.T) {
			created := mint(updated.UnsignedTx, 1, published, clones, cloned)
			requireVMResult(t, created, emulatorKey.PubKey(), "")
			rest := hashpricePool - hashpriceFanout
			again := assetMovement(
				[]asset.AssetInput{assetIn(0, rest)},
				[]asset.AssetOutput{
					assetOut(0, rest),
					assetOut(1, 1), assetOut(2, 1), assetOut(3, 1), assetOut(4, 1),
				},
			)
			requireVMResult(t, mint(created.UnsignedTx, 0, published, clones, again), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("a different verifier cannot advance the minter", func(t *testing.T) {
			foreign := fundBeacon(t, p2trScript(t, []byte{0x51}), beaconState(t, checkpoint, checkpointHeight, big.NewInt(0)))
			witness := covenantWitness(t, beaconContract, covenantGroup(t, beaconContract, "update"), headerWitness(chain.headers))
			spent := hashpriceTx(t, []covenantInput{
				{prev: foreign, path: beacon.paths["update"], witness: witness},
				{prev: fundingTx(minter.pkScript, hashpriceBeaconValue), path: minter.paths["advance"]},
			}, []*wire.TxOut{
				beaconOut(hashpriceBeaconValue, foreign.TxOut[0].PkScript),
				minterOut,
			}, pair, published)
			requireVMResult(t, spent, emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("the pool copies its packet onto the minter", func(t *testing.T) {
			seeded := fundBeacon(t, minter.pkScript, published)
			pool := assetMovement(
				[]asset.AssetInput{assetIn(0, hashpricePool)},
				[]asset.AssetOutput{assetOut(0, hashpricePool)},
			)
			requireVMResult(t, hashpriceTx(t, []covenantInput{{
				prev: seeded, path: minter.paths["copy"],
			}}, []*wire.TxOut{minterOut}, pool, published), emulatorKey.PubKey(), "")
		})
		t.Run("a pool copy cannot change the packet", func(t *testing.T) {
			seeded := fundBeacon(t, minter.pkScript, published)
			moved := append([]byte{}, published...)
			moved[55] ^= 0xff
			pool := assetMovement(
				[]asset.AssetInput{assetIn(0, hashpricePool)},
				[]asset.AssetOutput{assetOut(0, hashpricePool)},
			)
			requireVMResult(t, hashpriceTx(t, []covenantInput{{
				prev: seeded, path: minter.paths["copy"],
			}}, []*wire.TxOut{minterOut}, pool, moved), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("an attestation copies its packet and its script", func(t *testing.T) {
			created := mint(updated.UnsignedTx, 1, published, clones, cloned)
			requireVMResult(t, created, emulatorKey.PubKey(), "")
			requireVMResult(t, hashpriceTx(t, []covenantInput{{
				prev: created.UnsignedTx, vout: 1, path: attestation.paths["copy"],
			}}, []*wire.TxOut{attestationOut}, held, published), emulatorKey.PubKey(), "")
		})
		t.Run("an attestation copy cannot change the packet", func(t *testing.T) {
			created := mint(updated.UnsignedTx, 1, published, clones, cloned)
			requireVMResult(t, created, emulatorKey.PubKey(), "")
			moved := append([]byte{}, published...)
			moved[55] ^= 0xff
			requireVMResult(t, hashpriceTx(t, []covenantInput{{
				prev: created.UnsignedTx, vout: 1, path: attestation.paths["copy"],
			}}, []*wire.TxOut{attestationOut}, held, moved), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("an attestation cannot be paid to another script", func(t *testing.T) {
			created := mint(updated.UnsignedTx, 1, published, clones, cloned)
			requireVMResult(t, created, emulatorKey.PubKey(), "")
			requireVMResult(t, hashpriceTx(t, []covenantInput{{
				prev: created.UnsignedTx, vout: 1, path: attestation.paths["copy"],
			}}, []*wire.TxOut{pay(hashpriceBeaconValue, writerProgram)}, held, published), emulatorKey.PubKey(), "does not preserve source script")
		})
	})

	t.Run("settle", func(t *testing.T) {
		updated := update(genesis, chain.headers, continued, published, pair)
		requireVMResult(t, updated, emulatorKey.PubKey(), "")
		created := mint(updated.UnsignedTx, 1, published, clones, cloned)
		requireVMResult(t, created, emulatorKey.PubKey(), "")

		t.Run("an in-the-money note pays the holder and the writer", func(t *testing.T) {
			carried := hashpriceTx(t, []covenantInput{{
				prev: created.UnsignedTx, vout: 1, path: attestation.paths["copy"],
			}}, []*wire.TxOut{attestationOut}, held, published)
			requireVMResult(t, carried, emulatorKey.PubKey(), "")
			requireVMResult(t, settle(carried.UnsignedTx, 0, standard, hashpriceCollateral, []*wire.TxOut{
				pay(holderAmt, holderProgram),
				pay(writerAmt, writerProgram),
			}), emulatorKey.PubKey(), "")
		})
		t.Run("out of the money the writer keeps the collateral", func(t *testing.T) {
			requireVMResult(t, settle(
				created.UnsignedTx, 1, optionOf(hashpriceCollateral, price), hashpriceCollateral,
				[]*wire.TxOut{pay(hashpriceCollateral, writerProgram)},
			), emulatorKey.PubKey(), "")
		})
		t.Run("a dust leg folds into the writer", func(t *testing.T) {
			diff := new(big.Int).Quo(new(big.Int).Set(price), big.NewInt(hashpriceCollateral/100))
			dustStrike := new(big.Int).Sub(new(big.Int).Set(price), diff)
			holder := holderPayoff(t, hashpriceCollateral, price, dustStrike)
			if holder <= 0 || holder > hashpriceDust {
				t.Fatalf("dust fixture holder payout %d is outside 1..%d", holder, hashpriceDust)
			}
			requireVMResult(t, settle(
				created.UnsignedTx, 1, optionOf(hashpriceCollateral, dustStrike), hashpriceCollateral,
				[]*wire.TxOut{pay(hashpriceCollateral, writerProgram)},
			), emulatorKey.PubKey(), "")
		})
		t.Run("the checkpoint packet cannot settle a note", func(t *testing.T) {
			previous := fundBeacon(t, attestation.pkScript, beaconState(t, checkpoint, checkpointHeight, big.NewInt(0)))
			requireVMResult(t, settle(
				previous, 0, standard, hashpriceCollateral,
				[]*wire.TxOut{pay(holderAmt, holderProgram), pay(writerAmt, writerProgram)},
			), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("a different program does not settle", func(t *testing.T) {
			// The foreign coin carries a real packet and the asset is burned,
			// so consume succeeds and the note is what rejects the program.
			other := fundBeacon(t, p2trScript(t, []byte{0x51}), published)
			requireVMResult(t, settle(
				other, 0, standard, hashpriceCollateral,
				[]*wire.TxOut{pay(holderAmt, holderProgram), pay(writerAmt, writerProgram)},
			), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
		t.Run("consuming the attestation cannot leave the asset behind", func(t *testing.T) {
			left := hashpriceTx(t, []covenantInput{
				{prev: created.UnsignedTx, vout: 1, path: attestation.paths["consume"]},
				{prev: fundingTx(standard.pkScript, hashpriceCollateral), path: scriptPath{covenant: standard.covenant, leaf: standard.tapLeafScript}},
			}, []*wire.TxOut{
				pay(holderAmt, holderProgram),
				pay(writerAmt, writerProgram),
			}, held, published)
			requireVMResult(t, left, emulatorKey.PubKey(), "OP_NUMEQUALVERIFY failed")
		})
		t.Run("the holder cannot be shorted", func(t *testing.T) {
			requireVMResult(t, settle(created.UnsignedTx, 1, standard, hashpriceCollateral, []*wire.TxOut{
				pay(holderAmt-1, holderProgram),
				pay(writerAmt+1, writerProgram),
			}), emulatorKey.PubKey(), "OP_VERIFY failed")
		})
		t.Run("the holder payout cannot be redirected", func(t *testing.T) {
			requireVMResult(t, settle(created.UnsignedTx, 1, standard, hashpriceCollateral, []*wire.TxOut{
				pay(holderAmt, writerProgram),
				pay(writerAmt, writerProgram),
			}), emulatorKey.PubKey(), "OP_EQUALVERIFY failed")
		})
	})
}

type minedChain struct {
	headers [][]byte
	tip     []byte
}

func mineChain(t *testing.T, prev []byte, opened, step uint32) minedChain {
	t.Helper()

	headers := make([][]byte, 6)
	cursor := append([]byte{}, prev...)
	for i := range headers {
		headers[i] = mineHeader(t, cursor, opened+uint32(i)*step, hashpriceBits)
		cursor = hash256(headers[i])
	}
	return minedChain{headers: headers, tip: cursor}
}

func mineHeader(t *testing.T, prev []byte, stamp, bits uint32) []byte {
	t.Helper()

	if len(prev) != 32 {
		t.Fatalf("previous hash is %d bytes", len(prev))
	}
	header := make([]byte, 80)
	binary.LittleEndian.PutUint32(header[0:4], 0x20000000)
	copy(header[4:36], prev)
	binary.LittleEndian.PutUint32(header[68:72], stamp)
	binary.LittleEndian.PutUint32(header[72:76], bits)
	target := compactTarget(bits)
	for extra := uint32(0); extra < 8; extra++ {
		binary.LittleEndian.PutUint32(header[36:40], extra)
		for nonce := uint32(0); nonce < 1<<22; nonce++ {
			binary.LittleEndian.PutUint32(header[76:80], nonce)
			if meetsTarget(hash256(header), target) {
				return append([]byte{}, header...)
			}
		}
	}
	t.Fatal("mined no header")
	return nil
}

func cloneHeaders(headers [][]byte) [][]byte {
	out := make([][]byte, len(headers))
	for i, header := range headers {
		out[i] = append([]byte{}, header...)
	}
	return out
}

func headerWitness(headers [][]byte) map[string][]byte {
	values := make(map[string][]byte, len(headers))
	for i, header := range headers {
		values[fmt.Sprintf("headers.%d", i)] = header
	}
	return values
}

func hash256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	out := make([]byte, 32)
	copy(out, second[:])
	return out
}

func compactTarget(bits uint32) *big.Int {
	exponent := int64(bits >> 24)
	mantissa := int64(bits & 0x7fffff)
	if bits&0x00800000 != 0 || mantissa == 0 || exponent < 3 || exponent > 32 {
		return big.NewInt(0)
	}
	return new(big.Int).Lsh(big.NewInt(mantissa), uint(8*(exponent-3)))
}

func meetsTarget(hash []byte, target *big.Int) bool {
	reversed := make([]byte, len(hash))
	for i := range hash {
		reversed[len(hash)-1-i] = hash[i]
	}
	work := new(big.Int).SetBytes(reversed)
	return work.Sign() > 0 && work.Cmp(target) <= 0
}

func hashpriceQuote(height, span int64, bits uint32) *big.Int {
	subsidy := new(big.Int).Rsh(big.NewInt(5_000_000_000), uint(height/210_000))
	if span < 750 {
		span = 750
	}
	if span > 12000 {
		span = 12000
	}
	target := compactTarget(bits)
	maxTarget := new(big.Int).Lsh(big.NewInt(65535), 208)
	numerator := new(big.Int).Mul(subsidy, big.NewInt(86_400))
	numerator.Mul(numerator, big.NewInt(1_000_000_000_000_000))
	numerator.Mul(numerator, big.NewInt(span))
	numerator.Mul(numerator, target)
	denominator := new(big.Int).Mul(maxTarget, big.NewInt(3000))
	denominator.Mul(denominator, new(big.Int).Lsh(big.NewInt(1), 32))
	return numerator.Quo(numerator, denominator)
}

func holderPayoff(t *testing.T, collateral int64, price, strike *big.Int) int64 {
	t.Helper()

	if price.Cmp(strike) <= 0 {
		return 0
	}
	amount := new(big.Int).Sub(new(big.Int).Set(price), strike)
	amount.Mul(amount, big.NewInt(collateral))
	amount.Quo(amount, price)
	if !amount.IsInt64() {
		t.Fatalf("holder payoff %s does not fit a satoshi amount", amount)
	}
	return amount.Int64()
}

func beaconState(t *testing.T, tip []byte, height int64, price *big.Int) []byte {
	t.Helper()

	if len(tip) != 32 {
		t.Fatalf("tip is %d bytes", len(tip))
	}
	state := append([]byte{}, tip...)
	state = append(state, num2bin(t, height, 8)...)
	state = append(state, num2binBig(t, price, 16)...)
	if len(state) != 56 {
		t.Fatalf("state is %d bytes", len(state))
	}
	return state
}

func fundBeacon(t *testing.T, pkScript, state []byte) *wire.MsgTx {
	t.Helper()

	tx := fundingTx(pkScript, hashpriceBeaconValue)
	output, err := extension.Extension{statePacket(state)}.TxOut()
	if err != nil {
		t.Fatalf("state packet: %v", err)
	}
	tx.AddTxOut(output)
	return tx
}

func beaconOut(value int64, script []byte) *wire.TxOut {
	return &wire.TxOut{Value: value, PkScript: script}
}

func statePacket(state []byte) extension.Packet {
	return extension.UnknownPacket{PacketType: hashpriceStateType, Data: state}
}

func sharedAsset() asset.AssetId {
	return asset.AssetId{Txid: chainhash.Hash{0x46}, Index: 1}
}

func assetMovement(inputs []asset.AssetInput, outputs []asset.AssetOutput) asset.Packet {
	id := sharedAsset()
	return asset.Packet{{
		AssetId: &id,
		Inputs:  inputs,
		Outputs: outputs,
	}}
}

func assetIn(vin uint16, amount uint64) asset.AssetInput {
	return asset.AssetInput{Type: asset.AssetInputTypeLocal, Vin: vin, Amount: amount}
}

func assetOut(vout uint16, amount uint64) asset.AssetOutput {
	return asset.AssetOutput{Type: asset.AssetOutputTypeLocal, Vout: vout, Amount: amount}
}

type scriptPath struct {
	covenant []byte
	leaf     *psbt.TaprootTapLeafScript
}

type sharedTree struct {
	pkScript []byte
	paths    map[string]scriptPath
}

type covenantInput struct {
	prev    *wire.MsgTx
	vout    uint32
	path    scriptPath
	witness wire.TxWitness
}

func instantiateSharedTree(
	t *testing.T,
	contract artifact,
	names []string,
	values map[string][]byte,
	serverKey, emulatorKey *btcec.PublicKey,
) sharedTree {
	t.Helper()

	paths := make([]scriptPath, len(names))
	leaves := make([][]byte, len(names))
	for i, name := range names {
		group := covenantGroup(t, contract, name)
		covenant := assemble(t, group.Arkade.ASM, values)
		var leafASM []string
		for _, leaf := range group.Leaves {
			if leaf.Name == name {
				leafASM = leaf.ASM
				break
			}
		}
		if leafASM == nil {
			t.Fatalf("%s.%s leaf not found", contract.Name, name)
		}
		leafValues := map[string][]byte{
			"SERVER_KEY":           schnorr.SerializePubKey(serverKey),
			"EMULATOR_KEY:" + name: schnorr.SerializePubKey(arkade.ComputeArkadeScriptPublicKey(emulatorKey, arkade.ArkadeScriptHash(covenant))),
		}
		leaves[i] = assemble(t, leafASM, leafValues)
		paths[i] = scriptPath{covenant: covenant}
	}

	internalKey := fixedPublicKey(3)
	tapLeaves := make([]txscript.TapLeaf, len(leaves))
	for i, leaf := range leaves {
		tapLeaves[i] = txscript.NewBaseTapLeaf(leaf)
	}
	tree := txscript.AssembleTaprootScriptTree(tapLeaves...)
	root := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, root[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		t.Fatal(err)
	}
	for i, leaf := range leaves {
		controlBlock := tree.LeafMerkleProofs[i].ToControlBlock(internalKey)
		control, err := controlBlock.ToBytes()
		if err != nil {
			t.Fatal(err)
		}
		if err := txscript.VerifyTaprootLeafCommitment(&controlBlock, pkScript[2:], leaf); err != nil {
			t.Fatalf("leaf %d is not committed: %v", i, err)
		}
		paths[i].leaf = &psbt.TaprootTapLeafScript{
			ControlBlock: control,
			Script:       leaf,
			LeafVersion:  txscript.BaseLeafVersion,
		}
	}
	byName := make(map[string]scriptPath, len(names))
	for i, name := range names {
		byName[name] = paths[i]
	}
	return sharedTree{pkScript: pkScript, paths: byName}
}

func hashpriceTx(
	t *testing.T,
	inputs []covenantInput,
	outputs []*wire.TxOut,
	assets asset.Packet,
	state []byte,
) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	entries := make([]arkade.EmulatorEntry, len(inputs))
	for i, input := range inputs {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: input.prev.TxHash(), Index: input.vout},
		})
		entries[i] = arkade.EmulatorEntry{
			Vin:     uint16(i),
			Script:  input.path.covenant,
			Witness: input.witness,
		}
	}
	for _, output := range outputs {
		tx.AddTxOut(output)
	}
	packet, err := arkade.NewPacket(entries...)
	if err != nil {
		t.Fatal(err)
	}
	extensionOutput, err := extension.Extension{extension.Packet(assets), packet, statePacket(state)}.TxOut()
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(extensionOutput)

	ptx, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i, input := range inputs {
		ptx.Inputs[i].WitnessUtxo = input.prev.TxOut[input.vout]
		ptx.Inputs[i].TaprootLeafScript = []*psbt.TaprootTapLeafScript{input.path.leaf}
		if err := txutils.SetArkPsbtField(ptx, i, arkade.PrevArkTxField, *input.prev); err != nil {
			t.Fatal(err)
		}
	}
	return ptx
}

func num2bin(t *testing.T, value int64, size int) []byte {
	t.Helper()

	encoded, err := arkade.BigNumFromInt64(value).FixedBytes(size)
	if err != nil {
		t.Fatalf("num2bin(%d, %d): %v", value, size, err)
	}
	return encoded
}

func num2binBig(t *testing.T, value *big.Int, size int) []byte {
	t.Helper()

	number, err := arkade.BigNumFromBytes(scriptBigInt(t, value))
	if err != nil {
		t.Fatalf("num2bin big: %v", err)
	}
	encoded, err := number.FixedBytes(size)
	if err != nil {
		t.Fatalf("num2bin big size %d: %v", size, err)
	}
	return encoded
}
