package e2e

import (
	"bytes"
	"maps"
	"slices"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestStructs(t *testing.T) {
	contract := compileArtifact(t, "contracts/structs.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)
	ownerKey := fixedPrivateKey(4)

	if got := contract.ConstructorInputs; len(got) != 1 || got[0].Name != "account" || got[0].Type != "Account" {
		t.Fatalf("constructor inputs = %+v, want account Account", got)
	}
	if got, want := structNames(contract.Structs), []string{"Inner", "Rules", "Point", "Account"}; !slices.Equal(got, want) {
		t.Fatalf("struct definitions = %v, want %v", got, want)
	}

	accountLeaves := flattenInput("account", "Account", contract.Structs)
	wantAccountLeaves := []string{
		"account.owner",
		"account.rules.a_b",
		"account.rules.a.b",
		"account.rules.weights.0",
		"account.rules.weights.1",
		"account.rules.weights.2",
	}
	if !slices.Equal(accountLeaves, wantAccountLeaves) {
		t.Fatalf("account leaves = %v, want %v", accountLeaves, wantAccountLeaves)
	}

	group := covenantGroup(t, contract, "spend")
	for index, name := range expandInput(contract.ConstructorInputs[0], contract.Structs) {
		if got, want := group.Arkade.ASM[index], "<"+name+">"; got != want {
			t.Fatalf("constructor prologue token %d = %q, want %q", index, got, want)
		}
	}
	if got, want := inputTypes(group.Arkade.Inputs), []string{"Rules", "Point", "int", "int", "signature"}; !slices.Equal(got, want) {
		t.Fatalf("covenant input types = %v, want %v", got, want)
	}

	constructorValues := map[string][]byte{
		"account.owner":           schnorr.SerializePubKey(ownerKey.PubKey()),
		"account.rules.a_b":       scriptInt(t, 11),
		"account.rules.a.b":       scriptInt(t, 17),
		"account.rules.weights.0": scriptInt(t, 19),
		"account.rules.weights.1": scriptInt(t, 21),
		"account.rules.weights.2": scriptInt(t, 23),
	}
	instance := instantiateGroup(
		t, contract, "spend", constructorValues, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	generator := fixedPrivateKey(9).PubKey().SerializeUncompressed()
	baseValues := map[string][]byte{
		"supplied.a_b":       scriptInt(t, 29),
		"supplied.a.b":       scriptInt(t, 37),
		"supplied.weights.0": scriptInt(t, 41),
		"supplied.weights.1": scriptInt(t, 43),
		"supplied.weights.2": scriptInt(t, 47),
		"generator.x":        scriptPositiveBigInt(t, generator[1:33]),
		"generator.y":        scriptPositiveBigInt(t, generator[33:]),
		"index":              scriptInt(t, 1),
		"expected":           scriptInt(t, 393),
		"ownerSig":           nil,
	}

	assetOutput, err := asset.NewAssetOutput(0, 7)
	if err != nil {
		t.Fatal(err)
	}
	assetGroup, err := asset.NewAssetGroup(nil, nil, nil, []asset.AssetOutput{*assetOutput}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assetPacket, err := asset.NewPacket([]asset.AssetGroup{*assetGroup})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		key     string
		value   int64
		wantErr string
	}{
		{name: "valid"},
		{name: "underscore field is distinct from nested path", key: "supplied.a_b", value: 37, wantErr: "OP_VERIFY failed"},
		{name: "nested field is distinct from underscore path", key: "supplied.a.b", value: 29, wantErr: "OP_VERIFY failed"},
		{name: "nested array field", key: "supplied.weights.1", value: 44, wantErr: "OP_VERIFY failed"},
		{name: "runtime array bound", key: "index", value: 3, wantErr: "OP_VERIFY failed"},
		{name: "local struct mutation result", key: "expected", value: 394, wantErr: "OP_VERIFY failed"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			values := maps.Clone(baseValues)
			if testCase.key != "" {
				values[testCase.key] = scriptInt(t, testCase.value)
			}

			deployment := fundingTx(instance.pkScript, 10_000)
			unsigned := spendingPSBTWithWitness(
				t,
				deployment,
				instance,
				10_000,
				instance.pkScript,
				covenantWitness(t, contract, group, values),
				assetPacket,
			)
			values["ownerSig"] = signArkadeSighash(t, unsigned, 0, ownerKey)
			signed := spendingPSBTWithWitness(
				t,
				deployment,
				instance,
				10_000,
				instance.pkScript,
				covenantWitness(t, contract, group, values),
				assetPacket,
			)

			requireVMResult(t, signed, emulatorKey.PubKey(), testCase.wantErr)
		})
	}
}

func structNames(definitions []structDefinition) []string {
	names := make([]string, len(definitions))
	for index, definition := range definitions {
		names[index] = definition.Name
	}
	return names
}

func inputTypes(inputs []abiInput) []string {
	types := make([]string, len(inputs))
	for index, input := range inputs {
		types[index] = input.Type
	}
	return types
}

func scriptPositiveBigInt(t *testing.T, bigEndian []byte) []byte {
	t.Helper()

	encoded := bytes.TrimLeft(bigEndian, "\x00")
	encoded = slices.Clone(encoded)
	slices.Reverse(encoded)
	if len(encoded) > 0 && encoded[len(encoded)-1]&0x80 != 0 {
		encoded = append(encoded, 0)
	}
	number, err := arkade.BigNumFromBytes(encoded)
	if err != nil {
		t.Fatalf("encode positive big integer: %v", err)
	}
	encoded, err = number.Bytes()
	if err != nil {
		t.Fatalf("encode positive big integer: %v", err)
	}
	return encoded
}
