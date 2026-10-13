package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
)

func TestTapscriptHashlockPreimageLength(t *testing.T) {
	for _, declaredType := range []string{"bytes", "bytes20", "bytes32"} {
		for _, length := range []int{19, 20, 21, 31, 32, 33} {
			t.Run(fmt.Sprintf("%s/%d", declaredType, length), func(t *testing.T) {
				preimage := bytes.Repeat([]byte{0x42}, length)
				source := fmt.Sprintf(`contract C(pubkey owner, bytes20 digest) {
    function claim(%s preimage, signature serverSig, signature ownerSig) tapscript {
        require(hash160(preimage) == digest);
        require(checkMultisig([server, owner], [serverSig, ownerSig], 2));
    }
}`, declaredType)
				path := filepath.Join(t.TempDir(), "preimage.ark")
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				contract := compileArtifact(t, path)
				serverKey, ownerKey := fixedPrivateKey(1), fixedPrivateKey(2)
				group := instantiateLeaf(t, contract, "claim", map[string][]byte{
					"owner":  schnorr.SerializePubKey(ownerKey.PubKey()),
					"digest": btcutil.Hash160(preimage),
				}, serverKey.PubKey())
				wantError := ""
				if declaredType == "bytes20" && length != 20 || declaredType == "bytes32" && length != 32 {
					wantError = "OP_EQUALVERIFY failed"
				}
				requireTapscriptResult(t, fundingTx(group.pkScript, 10_000), group,
					0, wire.MaxTxInSequenceNum-1,
					[]*btcec.PrivateKey{serverKey, ownerKey}, wire.TxWitness{preimage}, wantError)
			})
		}
	}
}

func TestCovenantHashlockPreimageLength(t *testing.T) {
	for _, declaredType := range []string{"bytes", "bytes20", "bytes32"} {
		// The preimage sits below `n`, so its check reads it by depth.
		source := fmt.Sprintf(`contract C(bytes20 digest) {
    function claim(int n, %s preimage) {
        require(hash160(preimage) == digest);
        require(n == 1);
    }
}`, declaredType)
		path := filepath.Join(t.TempDir(), "preimage.ark")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		contract := compileArtifact(t, path)
		group := covenantGroup(t, contract, "claim")
		serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
		for _, length := range []int{19, 20, 21, 31, 32, 33} {
			t.Run(fmt.Sprintf("%s/%d", declaredType, length), func(t *testing.T) {
				preimage := bytes.Repeat([]byte{0x42}, length)
				instance := instantiateGroup(t, contract, "claim", map[string][]byte{
					"digest": btcutil.Hash160(preimage),
				}, serverKey.PubKey(), emulatorKey.PubKey())
				witness := covenantWitness(t, contract, group, map[string][]byte{"n": {1}, "preimage": preimage})
				spend := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10_000), instance, 10_000, instance.pkScript, witness)
				wantError := ""
				if declaredType == "bytes20" && length != 20 || declaredType == "bytes32" && length != 32 {
					wantError = "OP_EQUALVERIFY failed"
				}
				requireVMResult(t, spend, emulatorKey.PubKey(), wantError)
			})
		}
	}
}
