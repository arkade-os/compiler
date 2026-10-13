package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

func TestCheckedCasts(t *testing.T) {
	source := filepath.Join(t.TempDir(), "casts.ark")
	err := os.WriteFile(source, []byte(`
contract Casts() {
    function spend(bytes raw) {
        bytes32 id = bytes32(raw);
        require(id != 0x00);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(group.pkScript, 10_000)
	for _, tc := range []struct {
		name    string
		value   []byte
		wantErr string
	}{
		{"exact length", bytes.Repeat([]byte{7}, 32), ""},
		{"short", bytes.Repeat([]byte{7}, 31), "OP_EQUALVERIFY failed"},
		{"long", bytes.Repeat([]byte{7}, 33), "OP_EQUALVERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spend := spendingPSBTWithWitness(t, deployment, group, 10_000, group.pkScript, wire.TxWitness{tc.value})
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestScalarToBytesCasts(t *testing.T) {
	source := filepath.Join(t.TempDir(), "scalar_bytes.ark")
	err := os.WriteFile(source, []byte(`
contract ScalarBytes() {
    function spend(int value, bytes expected) {
        require(bytes(0) == "");
        require(bytes(128) == 0x8000);
        require(bytes(-128) == 0x8080);
        require(bytes(1 << 64) == 0x000000000000000001);
        require(bytes(value) == expected);
    }
    function boolBytes(bool flag, bytes expected) {
        require(bytes(false) == "");
        require(bytes(true) == 0x01);
        require(bytes(flag) == bytes(int(flag)));
        require(bytes(flag) == expected);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)
	for _, tc := range []struct {
		name            string
		value, expected []byte
		wantErr         string
	}{
		{"zero", nil, nil, ""},
		{"padded zero", []byte{0, 0}, nil, ""},
		{"negative zero", []byte{0, 0x80}, nil, ""},
		{"positive", []byte{1}, []byte{1}, ""},
		{"padded positive", []byte{1, 0}, []byte{1}, ""},
		{"negative", []byte{0x81}, []byte{0x81}, ""},
		{"padded negative", []byte{1, 0x80}, []byte{0x81}, ""},
		{"positive sign byte", []byte{0x80, 0}, []byte{0x80, 0}, ""},
		{"negative sign byte", []byte{0x80, 0x80}, []byte{0x80, 0x80}, ""},
		{"little endian", []byte{0, 1}, []byte{0, 1}, ""},
		{"wide integer", scriptInt(t, 1<<40), []byte{0, 0, 0, 0, 0, 1}, ""},
		{"beyond int64", []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}, ""},
		{"nonminimal expected", []byte{1}, []byte{1, 0}, "false stack entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := map[string][]byte{"value": tc.value, "expected": tc.expected}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
	boolGroup := covenantGroup(t, contract, "boolBytes")
	boolInstance := instantiateGroup(t, contract, "boolBytes", nil, serverKey.PubKey(), emulatorKey.PubKey())
	boolDeployment := fundingTx(boolInstance.pkScript, 10_000)
	for _, tc := range []struct {
		name            string
		value, expected []byte
		wantErr         string
	}{
		{"false", nil, nil, ""},
		{"true", []byte{1}, []byte{1}, ""},
		{"nonzero", []byte{2}, []byte{1}, ""},
		{"negative", []byte{0x81}, []byte{1}, ""},
		{"wide integer", scriptInt(t, 1<<40), []byte{1}, ""},
		{"beyond int64", []byte{0, 0, 0, 0, 0, 0, 0, 0, 1}, []byte{1}, ""},
		{"padded false", []byte{0}, nil, "not minimally encoded"},
		{"negative zero", []byte{0x80}, nil, "not minimally encoded"},
		{"padded true", []byte{1, 0}, []byte{1}, "not minimally encoded"},
		{"incorrect expected", []byte{2}, []byte{2}, "false stack entry"},
	} {
		t.Run("bool/"+tc.name, func(t *testing.T) {
			values := map[string][]byte{"flag": tc.value, "expected": tc.expected}
			spend := spendingPSBTWithWitness(t, boolDeployment, boolInstance, 10_000, boolInstance.pkScript, covenantWitness(t, contract, boolGroup, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
