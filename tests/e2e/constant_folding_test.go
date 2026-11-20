package e2e

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestConstantFolding(t *testing.T) {
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	q, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	squared := new(big.Int).Exp(big.NewInt(3), big.NewInt(256), q)
	for _, tc := range []struct {
		name, parameters, body, helpers string
		values                          map[string][]byte
		wantErr                         string
	}{
		{"loop indexes and branches", "int[3] rounds, bytes[3] encoded, int expected", `
            ECPoint[4] points = [{x: 0, y: 0}, {x: 1, y: 7}, {x: 2, y: 9}, {x: 3, y: 9}];
            int total = 0;
            for (i, unused) in rounds {
                require(i + 1 < 4);
                total = total + points[i + 1].x;
                require(int2bytes(i + 1, 1) == encoded[i]);
                if (i == 0) { require(points[i + 1].y == 7); }
                else { require(points[i + 1].y == 9); }
            }
            require(total == expected);`, "", map[string][]byte{
			"rounds.0": nil, "rounds.1": nil, "rounds.2": nil,
			"encoded.0": {1}, "encoded.1": {2}, "encoded.2": {3}, "expected": scriptInt(t, 6),
		}, ""},
		{"skipped out of range indexes", "int[2] values, int input", `
            for (i, unused) in values {
                require(i < 2 || values[i + 2] == input);
                require(!(i >= 2 && values[i + 2] == input));
            }`, "", map[string][]byte{"values.0": nil, "values.1": nil, "input": nil}, ""},
		{"false requirement", "", "require(1 + 1 == 3);", "", nil, "false stack entry"},
		{"division failure after unrolling", "int[1] rounds, int expected", `
            for (i, unused) in rounds { require(1 / (i - i) == expected); }`, "",
			map[string][]byte{"rounds.0": nil, "expected": nil}, "division by zero"},
		{"encoding fit failure", "bytes expected", "require(int2bytes(128, 1) == expected);", "",
			map[string][]byte{"expected": {0x80}}, "number needs 2 bytes"},
		{"narrowing cast failure", "bytes expected", "require(bytes32(int2bytes(1, 1)) == expected);", "",
			map[string][]byte{"expected": {1}}, "OP_EQUALVERIFY failed"},
		{"negative padding", "bytes expected", "require(int2bytes(-(2 + 1), 2) == expected);", "",
			map[string][]byte{"expected": {3, 0x80}}, ""},
		{"wrong negative padding", "bytes expected", "require(int2bytes(-(2 + 1), 2) == expected);", "",
			map[string][]byte{"expected": {0x83, 0}}, "false stack entry"},
		{"one byte zero", "bytes expected", "require(int2bytes(0, 1) == expected);", "",
			map[string][]byte{"expected": {0}}, ""},
		{"one byte zero is not empty", "bytes expected", "require(int2bytes(0, 1) == expected);", "",
			map[string][]byte{"expected": nil}, "false stack entry"},
		{"empty encoding", "bytes expected", "require(int2bytes(0, 0) == expected);", "",
			map[string][]byte{"expected": nil}, ""},
		{"i128 minimum", "bytes expected", "require(int2bytes(-170141183460469231731687303715884105728, 17) == expected);", "",
			map[string][]byte{"expected": append(make([]byte, 15), 0x80, 0x80)}, ""},
		{"maximum encoding width", "bytes expected", "require(int2bytes(-1, 520) == expected);", "",
			map[string][]byte{"expected": append(append([]byte{1}, bytes.Repeat([]byte{0}, 518)...), 0x80)}, ""},
		{"signed decoding of negative zero", "bytes data, int expected", "require(bytes2int(data) == expected);", "",
			map[string][]byte{"data": {0x80}, "expected": nil}, ""},
		{"unsigned decoding of the sign bit", "bytes data, int expected", "require(bytes2uint(data) == expected);", "",
			map[string][]byte{"data": {0x80}, "expected": scriptInt(t, 128)}, ""},
		{"unsigned decoding of four bytes", "bytes data, int expected", "require(bytes2uint(data) == expected);", "",
			map[string][]byte{"data": {1, 0, 0, 0x80}, "expected": scriptInt(t, 0x80000001)}, ""},
		{"unsigned decoding of empty bytes", "bytes data, int expected", "require(bytes2uint(data) == expected);", "",
			map[string][]byte{"data": nil, "expected": nil}, ""},
		{"unsigned big-endian decoding", "bytes data, int expected", "require(bytes2uint(reverseBytes(data)) == expected);", "",
			map[string][]byte{"data": {0x80, 0, 0, 1}, "expected": scriptInt(t, 0x80000001)}, ""},
		{"executed helper after true and", "int input", "require(true && verify(input));",
			"private function verify(int n) bool { require(n > 0); return true; }",
			map[string][]byte{"input": nil}, "OP_VERIFY failed"},
		{"executed helper after false or", "int input", "require(false || verify(input));",
			"private function verify(int n) bool { require(n > 0); return true; }",
			map[string][]byte{"input": nil}, "OP_VERIFY failed"},
		{"addition beyond i128", "int expected", "require(170141183460469231731687303715884105727 + 1 == expected);", "",
			map[string][]byte{"expected": scriptBigInt(t, new(big.Int).Lsh(big.NewInt(1), 127))}, ""},
		{"negation beyond i128", "int expected", "require(-(-170141183460469231731687303715884105728) == expected);", "",
			map[string][]byte{"expected": scriptBigInt(t, new(big.Int).Lsh(big.NewInt(1), 127))}, ""},
		{"division beyond i128", "int expected", "require(-170141183460469231731687303715884105728 / -1 == expected);", "",
			map[string][]byte{"expected": scriptBigInt(t, new(big.Int).Lsh(big.NewInt(1), 127))}, ""},
		{"shift beyond i128", "int expected", "require(1 << 127 == expected);", "",
			map[string][]byte{"expected": scriptBigInt(t, new(big.Int).Lsh(big.NewInt(1), 127))}, ""},
		{"remainder of i128 minimum", "int expected", "require(-170141183460469231731687303715884105728 % -1 == expected);", "",
			map[string][]byte{"expected": nil}, ""},
		{"arithmetic right shift", "int expected", "require(-7 >> 1 == expected);", "",
			map[string][]byte{"expected": scriptInt(t, -4)}, ""},
		{"wide literal read in branches and after them", "int input, bool choose", `
            if (choose) { require(input + 100000000000000000 > 0); }
            else { require(input - 100000000000000000 < 0); }
            require(input * 100000000000000000 == 300000000000000000);`, "",
			map[string][]byte{"input": scriptInt(t, 3), "choose": {1}}, ""},
		{"wide literal read only in a loop", "int input, bool choose", `
            int n = input;
            for (i) in 0..3 { if (choose) { n = n + 100000000000000000; } else { n = n - 100000000000000000; } }
            require(n == 300000000000000003);`, "",
			map[string][]byte{"input": scriptInt(t, 3), "choose": {1}}, ""},
		{"wide literal read in helpers that return early", "int input, bool choose", `
            require(shift(input, choose) == 100000000000000003);
            require(scale(input, choose) == 300000000000000000);`, `
            static function shift(int x, bool up) int { if (up) { return x + 100000000000000000; } return 100000000000000000 + x; }
            private function scale(int x, bool up) int {
                int[2] values = [7, 9];
                for (i, v) in values { if (up && i == 1) { return x * 100000000000000000; } }
                return 100000000000000000 * x;
            }`, map[string][]byte{"input": scriptInt(t, 3), "choose": {1}}, ""},
		{"squarings modulo a 254-bit constant", "int x, int y", `
            int a = x;
            for (8) { a = a * a % 21888242871839275222246405745257275088548364400416034343698204186575808495617; }
            require(a == y);`, "", map[string][]byte{"x": scriptInt(t, 3), "y": scriptBigInt(t, squared)}, ""},
		{"wrong square modulo a 254-bit constant", "int x, int y", `
            int a = x;
            for (8) { a = a * a % 21888242871839275222246405745257275088548364400416034343698204186575808495617; }
            require(a == y);`, "", map[string][]byte{"x": scriptInt(t, 3), "y": scriptBigInt(t, new(big.Int).Add(squared, big.NewInt(1)))}, "false stack entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "folding.ark")
			code := fmt.Sprintf("contract Folding() { function spend(%s) { %s } %s }", tc.parameters, tc.body, tc.helpers)
			if err := os.WriteFile(source, []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
			contract := compileArtifact(t, source)
			group := arkadeScriptGroup(t, contract, "spend")
			instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, tc.values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}

func TestConstantFoldingMixedIndexes(t *testing.T) {
	source := filepath.Join(t.TempDir(), "nested.ark")
	if err := os.WriteFile(source, []byte(`
        struct Row { int length; int[3] values; }
        contract Nested() {
            function spend(Row[3] rows, int index, int newValue, int expected) {
                require(rows[1 + 1].length == 103);
                require(rows[1 + 1].values[1 + 1] == 23);
                rows[1 + 1].values[index] = newValue;
                require(rows[1 + 1].values[index] == newValue);
                require(rows[index].values[1 + 1] == expected);
            }
        }`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := arkadeScriptGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)
	for _, index := range []int64{-1, 0, 1, 2, 3} {
		values := map[string][]byte{"index": scriptInt(t, index), "newValue": scriptInt(t, 99)}
		for row := int64(0); row < 3; row++ {
			values[fmt.Sprintf("rows.%d.length", row)] = scriptInt(t, 101+row)
			for column := int64(0); column < 3; column++ {
				values[fmt.Sprintf("rows.%d.values.%d", row, column)] = scriptInt(t, row*10+column+1)
			}
		}
		expected, wantErr := index*10+3, ""
		if index == 2 {
			expected = 99
		}
		if index < 0 || index >= 3 {
			wantErr = "OP_VERIFY failed"
		}
		values["expected"] = scriptInt(t, expected)
		spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, values))
		requireVMResult(t, spend, emulatorKey.PubKey(), wantErr)
	}
}

func TestConstantFoldingReturnJoins(t *testing.T) {
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	for _, body := range []string{
		`ECPoint p;
         if (choose) { if (1 < 2) { return {x: input, y: 11}; } else { p = {x: 9, y: 0}; } }
         else { p = {x: input, y: 11}; }
         return p;`,
		`ECPoint p; int[2] rounds = [0, 1];
         if (choose) { for (i, unused) in rounds {
             if (i == 1) { return {x: input, y: 11}; } else { p = {x: 9, y: 0}; }
         } } else { p = {x: input, y: 11}; }
         return p;`,
	} {
		source := filepath.Join(t.TempDir(), "returns.ark")
		code := fmt.Sprintf(`contract Returns() {
            private function make(int input, bool choose) ECPoint { %s }
            function spend(int input, bool choose) {
                ECPoint p = make(input, choose);
                require(p.x == 7); require(p.y == 11);
            }
        }`, body)
		if err := os.WriteFile(source, []byte(code), 0600); err != nil {
			t.Fatal(err)
		}
		contract := compileArtifact(t, source)
		group := arkadeScriptGroup(t, contract, "spend")
		instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
		deployment := fundingTx(instance.pkScript, 10_000)
		for _, choose := range []int64{0, 1} {
			for _, input := range []int64{6, 7} {
				values := map[string][]byte{"input": scriptInt(t, input), "choose": scriptInt(t, choose)}
				spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, values))
				wantErr := ""
				if input != 7 {
					wantErr = "OP_NUMEQUALVERIFY failed"
				}
				requireVMResult(t, spend, emulatorKey.PubKey(), wantErr)
			}
		}
	}
}
