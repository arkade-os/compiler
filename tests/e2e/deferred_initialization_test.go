package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDeferredInitialization(t *testing.T) {
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, tc := range []struct{ name, body, helpers string }{
		{"straight line", `int x; x = input + 1; require(x == 8);`, ""},
		{"branch order", `int x; int y;
            if (choose) { x = 11; int temp = input; y = temp; }
            else { y = input; x = 11; }
            require(x == 11); require(y == input);`, ""},
		{"nested branch", `int x;
            if (choose) { if (input > 0) { x = 11; } else { x = 11; } }
            else { x = 11; }
            x = x + 1; require(x == 12);`, ""},
		{"partial branch discarded", `int x;
            if (choose) { x = 11; int temp = input; require(temp == x - 4); }
            x = input; require(x == input);`, ""},
		{"arrays and structs", `Pair pair; int y; int[2] values;
            require(values.length == 2);
            if (choose) { pair = { a: 7, b: [9, 11] }; y = input; values = [13, 17]; }
            else { values = [13, 17]; y = input; pair = { a: 7, b: [9, 11] }; }
            require(pair.a == input); require(y == input);
            pair.b[index] = pair.a;
            require(pair.b[index] == input);
            values[index] = input; require(values[index] == input);`, ""},
		{"loop", `int x; for (3) { x = input; x = x + 1; } require(x == 8);`, ""},
		{"array loop", `int x; int[2] values = [9, 11];
            for (i, value) in values { x = value; }
            require(x == 11);`, ""},
		{"zero loop", `int x; for (0) { x = 11; } x = input; require(x == input);`, ""},
		{"helper return", `int x; Pair pair;
            x = result(choose, input); pair = make(choose, input);
            require(x == input); require(pair.a == input); require(pair.b[index] > input);`, `
            private function result(bool choose, int input) int {
                int x;
                if (choose) { return input; } else { x = input; }
                return x;
            }
            private function make(bool choose, int input) Pair {
                Pair pair;
                if (choose) { pair = { a: input, b: [9, 11] }; }
                else { pair = { a: input, b: [9, 11] }; }
                return pair;
            }`},
		{"return from loop", `require(result(choose, input) == input);`, `
            private function result(bool choose, int input) int {
                int x;
                for (2) { if (choose) { return input; } else { x = input; } }
                return x;
            }`},
		{"bytes and bool", `bytes data; bool ok;
            if (choose) { data = 0xabcd; ok = input == 7; }
            else { ok = input == 7; data = 0xabcd; }
            require(ok); require(data == 0xabcd);`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "deferred.ark")
			code := fmt.Sprintf(`struct Pair { int a; int[2] b; }
                contract Deferred() {
                    function spend(bool choose, int input, int index) {
                        %s
                        require(choose == true || choose == false);
                        require(input == 7); require(index >= 0);
                    }
                    %s
                }`, tc.body, tc.helpers)
			if err := os.WriteFile(source, []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
			contract := compileArtifact(t, source)
			group := covenantGroup(t, contract, "spend")
			instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			for _, choose := range []int64{0, 1} {
				for _, index := range []int64{0, 1} {
					values := map[string][]byte{"choose": scriptInt(t, choose), "input": scriptInt(t, 7), "index": scriptInt(t, index)}
					spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
					requireVMResult(t, spend, emulatorKey.PubKey(), "")
					values["input"] = scriptInt(t, 6)
					spend = spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
					requireVMResult(t, spend, emulatorKey.PubKey(), "VERIFY failed")
				}
			}
		})
	}
}

func TestDeferredInitializationScriptSize(t *testing.T) {
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, declaration := range []struct{ name, deferred, filled, body string }{
		{"scalar", "int x;", "int x = 0;", "if (choose) { x = 7; } else { x = 9; } require(x > 0);"},
		{"array", "int[2] x;", "int[2] x = [0, 0];", "if (choose) { x = [7, 9]; } else { x = [9, 7]; } require(x[0] > 0);"},
		{"struct", "Pair x;", "Pair x = { a: 0, b: [0, 0] };", "if (choose) { x = { a: 7, b: [9, 11] }; } else { x = { a: 9, b: [11, 13] }; } require(x.a > 0);"},
	} {
		t.Run(declaration.name, func(t *testing.T) {
			sizes := make([]int, 0, 2)
			for _, decl := range []string{declaration.deferred, declaration.filled} {
				source := filepath.Join(t.TempDir(), "size.ark")
				code := fmt.Sprintf("struct Pair { int a; int[2] b; } contract Size() { function spend(bool choose) { %s %s } }", decl, declaration.body)
				if err := os.WriteFile(source, []byte(code), 0600); err != nil {
					t.Fatal(err)
				}
				contract := compileArtifact(t, source)
				instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
				sizes = append(sizes, len(instance.covenant))
			}
			if sizes[0] >= sizes[1] {
				t.Fatalf("deferred script = %d bytes, zero-filled = %d", sizes[0], sizes[1])
			}
			t.Logf("deferred: %d bytes; zero-filled: %d bytes", sizes[0], sizes[1])
		})
	}
}
