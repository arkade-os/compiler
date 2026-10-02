package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

func TestBitwiseBuiltins(t *testing.T) {
	source := filepath.Join(t.TempDir(), "bitwise.ark")
	err := os.WriteFile(source, []byte(`
contract Bitwise(bytes zero) {
    function spend(bytes mask) {
        require(bitAnd(0xf0f0, 0xff00) == 0xf000);
        require(bitOr(0xf0f0, 0x0f00) == 0xfff0);
        require(bitXor(0xf0f0, 0xffff) == 0x0f0f);
        require(bitNot(0x00ff) == 0xff00);
        require(bitAnd(mask, 0x00ff) == 0x00cd);
        require(bitXor(mask, mask) == 0x0000);
        require(bitNot(bitNot(mask)) == mask);
        require(zero == 0x00);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := instantiateGroup(t, contract, "spend", map[string][]byte{"zero": {0}}, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(group.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		mask    []byte
		wantErr string
	}{
		{"matching mask", []byte{0xab, 0xcd}, ""},
		{"wrong low byte", []byte{0xab, 0xce}, "OP_EQUALVERIFY failed"},
		{"mismatched length", []byte{0xab, 0xcd, 0xef}, "mismatched operand sizes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, group.pkScript, wire.TxWitness{tc.mask})
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
