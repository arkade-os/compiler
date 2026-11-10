package e2e

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUtilityBuiltins(t *testing.T) {
	source := filepath.Join(t.TempDir(), "utility.ark")
	err := os.WriteFile(source, []byte(`
contract Utility() {
    function numbers(int a, int b, int lower, int upper, int absolute, int smallest, int largest, bool inside) {
        require(abs(a) == absolute);
        require(min(a, b) == smallest);
        require(max(a, b) == largest);
        require(within(a, lower, upper) == inside);
    }
    function prefix(bytes data, int count, bytes expected) {
        require(left(data, count) == expected);
    }
    function suffix(bytes data, int count, bytes expected) {
        require(right(data, count) == expected);
    }
    private function fingerprint(bytes data, int count) bytes20 {
        return sha1(left(data, count) + right(data, count));
    }
    function hash(bytes data, int count, bytes20 expected) {
        // OP_DIGEST selector 2 is SHA-1 in the emulator.
        require(sha1(data) == digest(data, 2));
        require(fingerprint(data, count) == expected);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)

	for _, tc := range []struct {
		name                                            string
		a, b, lower, upper, absolute, smallest, largest int64
		inside                                          int64
	}{
		{"negative", -7, 2, -8, 0, 7, -7, 2, 1},
		{"positive", 7, -2, 0, 8, 7, -2, 7, 1},
		{"zero and equal", 0, 0, 0, 1, 0, 0, 0, 1},
		{"lower inclusive", -3, -5, -3, 2, 3, -5, -3, 1},
		{"upper exclusive", 2, 9, -3, 2, 2, 2, 9, 0},
		{"below lower", -4, -2, -3, 2, 4, -4, -2, 0},
		{"above upper", 3, 1, -3, 2, 3, 1, 3, 0},
		{"empty range", 2, 2, 2, 2, 2, 2, 2, 0},
		{"reversed range", 2, 2, 3, 1, 2, 2, 2, 0},
		{"wide integer", 1 << 40, -(1 << 40), 0, 1 << 41, 1 << 40, -(1 << 40), 1 << 40, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := make(map[string][]byte)
			for name, value := range map[string]int64{
				"a": tc.a, "b": tc.b, "lower": tc.lower, "upper": tc.upper,
				"absolute": tc.absolute, "smallest": tc.smallest, "largest": tc.largest, "inside": tc.inside,
			} {
				values[name] = scriptInt(t, value)
			}
			group := covenantGroup(t, contract, "numbers")
			instance := instantiateGroup(t, contract, "numbers", nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), "")
		})
	}

	for _, function := range []string{"prefix", "suffix"} {
		for _, tc := range []struct {
			data, prefix, suffix string
			count                int64
			invalid              bool
		}{
			{"", "", "", 0, false},
			{"abcd", "", "", 0, false},
			{"abcd", "ab", "cd", 2, false},
			{"abcd", "abcd", "abcd", 4, false},
			{"abcd", "", "", -1, true},
			{"abcd", "", "", 5, true},
			{"", "", "", 1, true},
		} {
			t.Run(fmt.Sprintf("%s/%q/%d", function, tc.data, tc.count), func(t *testing.T) {
				expected, wantErr := tc.prefix, ""
				if function == "suffix" {
					expected = tc.suffix
				}
				if tc.invalid {
					wantErr = "invalid left index"
					if function == "suffix" {
						wantErr = "invalid right index"
					}
				}
				values := map[string][]byte{"data": []byte(tc.data), "count": scriptInt(t, tc.count), "expected": []byte(expected)}
				group := covenantGroup(t, contract, function)
				instance := instantiateGroup(t, contract, function, nil, serverKey.PubKey(), emulatorKey.PubKey())
				deployment := fundingTx(instance.pkScript, 10_000)
				spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
				requireVMResult(t, spend, emulatorKey.PubKey(), wantErr)
			})
		}
	}

	for _, tc := range []struct {
		data  string
		count int64
	}{
		{"", 0}, {"abc", 0}, {"abc", 1}, {"abc", 3}, {"\x00\xffab", 2},
	} {
		t.Run(fmt.Sprintf("sha1/%q/%d", tc.data, tc.count), func(t *testing.T) {
			digest := sha1.Sum([]byte(tc.data[:tc.count] + tc.data[len(tc.data)-int(tc.count):]))
			values := map[string][]byte{"data": []byte(tc.data), "count": scriptInt(t, tc.count), "expected": digest[:]}
			group := covenantGroup(t, contract, "hash")
			instance := instantiateGroup(t, contract, "hash", nil, serverKey.PubKey(), emulatorKey.PubKey())
			deployment := fundingTx(instance.pkScript, 10_000)
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), "")
		})
	}
}

func TestStreamingSha256(t *testing.T) {
	source := filepath.Join(t.TempDir(), "streaming.ark")
	err := os.WriteFile(source, []byte(`
contract Streaming() {
    private function step(bytes ctx, bytes chunk) bytes {
        return sha256Update(ctx, chunk);
    }
    function chunks(bytes first, bytes second, bytes last) {
        bytes ctx = sha256Initialize(first);
        ctx = step(ctx, second);
        bytes32 digest = sha256Finalize(ctx, last);
        require(digest == sha256(first + second + last));
    }
    function resume(bytes ctx, bytes last, bytes32 expected) {
        require(sha256Finalize(ctx, last) == expected);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	spend := func(t *testing.T, function string, values map[string][]byte, wantErr string) {
		group := covenantGroup(t, contract, function)
		instance := instantiateGroup(t, contract, function, nil, serverKey.PubKey(), emulatorKey.PubKey())
		deployment := fundingTx(instance.pkScript, 10_000)
		ptx := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, covenantWitness(t, contract, group, values))
		requireVMResult(t, ptx, emulatorKey.PubKey(), wantErr)
	}

	for _, chunks := range [][3]string{{"", "", ""}, {"he", "l", "lo"}, {"a", strings.Repeat("b", 100), "c"}} {
		t.Run(fmt.Sprintf("chunks/%d", len(chunks[1])), func(t *testing.T) {
			spend(t, "chunks", map[string][]byte{"first": []byte(chunks[0]), "second": []byte(chunks[1]), "last": []byte(chunks[2])}, "")
		})
	}

	// The emulator serializes a context as the gob encoding of its SHA-256 state.
	state := sha256.New()
	state.Write([]byte("hel"))
	var ctx bytes.Buffer
	if err := gob.NewEncoder(&ctx).Encode(state); err != nil {
		t.Fatal(err)
	}
	marshaled, err := state.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	corrupted := bytes.Clone(ctx.Bytes())
	corrupted[len(corrupted)-len(marshaled)] ^= 0xff
	digest := sha256.Sum256([]byte("hello"))
	for _, tc := range []struct {
		name          string
		ctx, expected []byte
		wantErr       string
	}{
		{"resumed digest", ctx.Bytes(), digest[:], ""},
		{"wrong digest", ctx.Bytes(), make([]byte, 32), "false stack entry"},
		{"short digest", ctx.Bytes(), digest[:31], "OP_EQUALVERIFY failed"},
		{"malformed context", []byte("garbage"), digest[:], "invalid hash state"},
		{"corrupted state", corrupted, digest[:], "failed to load hash state"},
	} {
		t.Run("resume/"+tc.name, func(t *testing.T) {
			spend(t, "resume", map[string][]byte{"ctx": tc.ctx, "last": []byte("lo"), "expected": tc.expected}, tc.wantErr)
		})
	}
}
