package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBitwiseAndShiftOperators(t *testing.T) {
	source := filepath.Join(t.TempDir(), "bitwise.ark")
	err := os.WriteFile(source, []byte(`
contract Bitwise(bytes zero) {
    function spend(bytes mask, int n, int k) {
        require((0xf0f0 & 0xff00) == 0xf000);
        require((0xf0f0 | 0x0f00) == 0xfff0);
        require((0xf0f0 ^ 0xffff) == 0x0f0f);
        require(~0x00ff == 0xff00);
        require(mask & 0x00ff == 0x00cd);
        require(~~mask == mask);
        require(n << 3 == 40);
        require((0 - n) >> 1 == -3);
        require(1 << k == 1);
        require(zero == 0x00);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", map[string][]byte{"zero": {0}}, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		mask    []byte
		n, k    int64
		wantErr string
	}{
		{"matching operands", []byte{0xab, 0xcd}, 5, 0, ""},
		{"wrong low byte", []byte{0xab, 0xce}, 5, 0, "OP_EQUALVERIFY failed"},
		{"mismatched length", []byte{0xab, 0xcd, 0xef}, 5, 0, "mismatched operand sizes"},
		{"wrong shift result", []byte{0xab, 0xcd}, 4, 0, "OP_EQUALVERIFY failed"},
		{"negative shift count", []byte{0xab, 0xcd}, 5, -1, "negative shift count"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"mask": tc.mask, "n": scriptInt(t, tc.n), "k": scriptInt(t, tc.k)}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
