package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Mirrors contracts/nested_arrays.ark, computed independently of the compiler.
func nestedExpectedTotal(weights, grid [2][3]int64, row [3]int64, i, j, wi, wj int) int64 {
	cells := [2][3]int64{{1, 2, 3}, {4, 5, 6}}
	cells[wi][wj] = grid[i][j] * 10
	cells[i] = row
	other := grid[1-i]
	total := weights[i][j] + other[0] + other[1] + other[2] + int64(len(cells[i]))
	for r, line := range cells {
		for c, cell := range line {
			total += cell * int64(r*3+c+1)
		}
	}
	return total
}

func TestNestedArrays(t *testing.T) {
	contract := compileArtifact(t, "contracts/nested_arrays.ark")
	serverKey := fixedPrivateKey(1)
	emulatorKey := fixedPrivateKey(2)

	// Sizes read in index order: the first is the outermost.
	if got := contract.ConstructorInputs[0]; got.Name != "weights" || got.Type != "int[2][3]" {
		t.Fatalf("constructor input 0 = %+v, want weights int[2][3]", got)
	}
	group := arkadeScriptGroup(t, contract, "spend")
	if got := group.Arkade.Inputs[4]; got.Name != "grid" || got.Type != "int[2][3]" {
		t.Fatalf("Arkade Script input 4 = %+v, want grid int[2][3]", got)
	}

	weights := [2][3]int64{{2, 3, 5}, {7, 11, 13}}
	var keys [2][2]*btcec.PrivateKey
	// Constructor arrays expand into one placeholder per element, row by row.
	constructorValues := map[string][]byte{}
	for r := range 2 {
		for c := range 3 {
			constructorValues[fmt.Sprintf("weights.%d.%d", r, c)] = scriptInt(t, weights[r][c])
		}
		for c := range 2 {
			keys[r][c] = fixedPrivateKey(byte(10 + 2*r + c))
			constructorValues[fmt.Sprintf("keys.%d.%d", r, c)] = schnorr.SerializePubKey(keys[r][c].PubKey())
		}
	}
	nested := instantiateGroup(
		t, contract, "spend", constructorValues, serverKey.PubKey(), emulatorKey.PubKey(),
	)

	grid := [2][3]int64{{17, 19, 23}, {29, 31, 37}}
	testCases := []struct {
		name         string
		i, j, wi, wj int
		grid         *[2][3]int64
		row          *[3]int64
		total        int64
		wantErr      string
	}{
		{name: "first cell", i: 0, j: 0, wi: 0, wj: 0},
		{name: "last cell", i: 1, j: 2, wi: 1, wj: 2},
		// The row write leaves the element write in the other row, and reads and writes
		// land in different columns, so a wrong stride moves a value the total weighs.
		{name: "second row reads", i: 1, j: 0, wi: 0, wj: 2},
		{name: "second row writes", i: 0, j: 1, wi: 1, wj: 1},
		// Each index is first used where it is out of range. Unchecked, it reads or writes
		// another stack item, which changes a comparison or the total (`expected` follows
		// `grid`, so a row read past it differs from `row`), or fails OP_PICK or OP_PUT on
		// a negative depth, so in optimized builds only the bound checks fail OP_VERIFY.
		{name: "outer read index past the array", i: 2, wantErr: "OP_VERIFY failed"},
		{name: "negative outer read index", i: -1, j: 2, wantErr: "OP_VERIFY failed"},
		{name: "inner read index past the row", i: 0, j: 3, wantErr: "OP_VERIFY failed"},
		{name: "negative inner read index", i: 1, j: -1, wantErr: "OP_VERIFY failed"},
		{name: "outer write index past the array", wi: 2, wantErr: "OP_VERIFY failed"},
		{name: "negative outer write index", wi: -1, wj: 2, wantErr: "OP_VERIFY failed"},
		{name: "inner write index past the row", wi: 0, wj: 3, wantErr: "OP_VERIFY failed"},
		{name: "negative inner write index", wi: 1, wj: -1, wantErr: "OP_VERIFY failed"},
		{name: "row other than the indexed one", i: 0, row: &grid[1], wantErr: "OP_NUMEQUALVERIFY failed"},
		{name: "empty grid", grid: &[2][3]int64{}, wantErr: "OP_VERIFY failed"},
		{name: "wrong total", total: 1, wantErr: "OP_NUMEQUALVERIFY failed"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// The expected total of a rejected index uses an in-range one in its place.
			in := func(index, length int) int {
				if index < 0 || index >= length {
					return 0
				}
				return index
			}
			i, j := in(testCase.i, 2), in(testCase.j, 3)
			wi, wj := in(testCase.wi, 2), in(testCase.wj, 3)
			spendGrid := grid
			if testCase.grid != nil {
				spendGrid = *testCase.grid
			}
			row := spendGrid[i]
			if testCase.row != nil {
				row = *testCase.row
			}
			total := testCase.total
			if total == 0 {
				total = nestedExpectedTotal(weights, spendGrid, row, i, j, wi, wj)
			}

			values := map[string][]byte{
				"i":        scriptInt(t, int64(testCase.i)),
				"j":        scriptInt(t, int64(testCase.j)),
				"wi":       scriptInt(t, int64(testCase.wi)),
				"wj":       scriptInt(t, int64(testCase.wj)),
				"expected": scriptInt(t, total),
				"ownerSig": nil,
			}
			for r := range 2 {
				for c := range 3 {
					values[fmt.Sprintf("grid.%d.%d", r, c)] = scriptInt(t, spendGrid[r][c])
				}
			}
			for c := range 3 {
				values[fmt.Sprintf("row.%d", c)] = scriptInt(t, row[c])
			}

			deployment := fundingTx(nested.pkScript, 10_000)
			unsigned := spendingPSBTWithWitness(
				t, deployment, nested, 10_000, nested.pkScript,
				arkadeScriptWitness(t, contract, group, values),
			)
			values["ownerSig"] = signArkadeSighash(t, unsigned, 0, keys[0][1])
			signed := spendingPSBTWithWitness(
				t, deployment, nested, 10_000, nested.pkScript,
				arkadeScriptWitness(t, contract, group, values),
			)

			requireVMResult(t, signed, emulatorKey.PubKey(), testCase.wantErr)
		})
	}

	t.Run("exit tapscript", func(t *testing.T) {
		exit := instantiateLeaf(t, contract, "exit", constructorValues, serverKey.PubKey())
		deployment := fundingTx(exit.pkScript, 10_000)
		for _, testCase := range []struct {
			name    string
			key     *btcec.PrivateKey
			wantErr string
		}{
			{"key at row 1, column 0", keys[1][0], ""},
			{"key at row 0, column 1", keys[0][1], "signature not empty on failed checksig"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				requireTapscriptResult(
					t, deployment, exit, 0, 144,
					[]*btcec.PrivateKey{testCase.key}, nil, testCase.wantErr,
				)
			})
		}
	})
}

type nestedPoint struct{ x, y int64 }

type nestedGrid struct {
	cells  [2][2]int64
	points [2][2]nestedPoint
}

// Three levels, arrays of structs, structs of nested arrays inside an array, constant
// sizes, a helper result, a loop over a literal of arrays, and nested wide literals.
func TestNestedArrayShapes(t *testing.T) {
	source := filepath.Join(t.TempDir(), "shapes.ark")
	err := os.WriteFile(source, []byte(`
struct Point { int x; int y; }
struct Grid { int[2][2] cells; Point[2][2] points; }
contract Shapes(Grid[2] grids) {
    const int N = 2;
    const int M = 3;
    const bytes32 H = 0x1111111111111111111111111111111111111111111111111111111111111111;
    private function grid(int v) int[N][M] {
        return [[v, v + 1, v + 2], [v + 3, v + 4, v + 5]];
    }
    private function corner(Point[2][2] points, int i) Point {
        return points[i][1 - i];
    }
    function spend(int i, int j, int k, int v, int[2][2][2] cube, Point[2][2] ps, bytes32[2][2] hashes, int expected) {
        bytes32[2][2] table = [[H, 0x2222222222222222222222222222222222222222222222222222222222222222], [0x3333333333333333333333333333333333333333333333333333333333333333, H]];
        require(hashes[i][j] == table[j][i]);
        int total = cube[i][j][k] + cube.length * 10 + cube[i].length * 100 + cube[i][j].length * 1000;
        cube[k][j][i] = v;
        cube[1 - i] = [[v, v + 1], [v + 2, v + 3]];
        let slab = cube[i];
        total = total + slab[j][k] * 3 + slab[1 - j][k] * 5;
        total = total + grid(v)[i][j + 1] * 7;
        int[N][M] g = grid(v + 1);
        for (r, line) in g {
            for (c, cell) in line {
                total = total + cell * (r * M + c + 1);
            }
        }
        for (r, pair) in [[v, 1], [2, v]] {
            total = total + pair[0] * (r + 1) + pair[1];
        }
        total = total + grids[k].cells[i][j] * 11 + grids[1 - k].points[j][i].y * 13;
        Point p = corner(ps, i);
        total = total + p.x * 17 + p.y * 19;
        Grid local = grids[k];
        local.points[i][j].x = v;
        local.cells[j][i] = v * 2;
        total = total + local.points[i][j].x + local.cells[j][i] * 23 + local.cells[1 - j][1 - i] * 29;
        if (ps[i] == grids[k].points[i]) {
            total = total + 1;
        }
        require(total == expected);
    }
}`), 0600)
	if err != nil {
		t.Fatal(err)
	}
	contract := compileArtifact(t, source)
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := arkadeScriptGroup(t, contract, "spend")
	for index, want := range []string{"int[2][2][2]", "Point[2][2]", "bytes32[2][2]"} {
		if got := group.Arkade.Inputs[4+index].Type; got != want {
			t.Fatalf("Arkade Script input %d has type %q, want %q", 4+index, got, want)
		}
	}

	var grids [2]nestedGrid
	constructorValues := map[string][]byte{}
	for g := range 2 {
		for r := range 2 {
			for c := range 2 {
				cell := int64(100*g + 10*r + c + 1)
				point := nestedPoint{x: cell + 40, y: cell + 70}
				grids[g].cells[r][c] = cell
				grids[g].points[r][c] = point
				prefix := fmt.Sprintf("grids.%d", g)
				constructorValues[fmt.Sprintf("%s.cells.%d.%d", prefix, r, c)] = scriptInt(t, cell)
				constructorValues[fmt.Sprintf("%s.points.%d.%d.x", prefix, r, c)] = scriptInt(t, point.x)
				constructorValues[fmt.Sprintf("%s.points.%d.%d.y", prefix, r, c)] = scriptInt(t, point.y)
			}
		}
	}
	instance := instantiateGroup(t, contract, "spend", constructorValues, serverKey.PubKey(), emulatorKey.PubKey())
	deployment := fundingTx(instance.pkScript, 10_000)

	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	table := [2][2][]byte{{hash(0x11), hash(0x22)}, {hash(0x33), hash(0x11)}}
	cube := [2][2][2]int64{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}}
	points := [2][2]nestedPoint{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}}
	total := func(i, j, k int, v int64, ps [2][2]nestedPoint) int64 {
		c := cube
		total := c[i][j][k] + 2*10 + 2*100 + 2*1000
		c[k][j][i] = v
		c[1-i] = [2][2]int64{{v, v + 1}, {v + 2, v + 3}}
		slab := c[i]
		total += slab[j][k]*3 + slab[1-j][k]*5
		grid := func(v int64) [2][3]int64 { return [2][3]int64{{v, v + 1, v + 2}, {v + 3, v + 4, v + 5}} }
		total += grid(v)[i][j+1] * 7
		for r, line := range grid(v + 1) {
			for c, cell := range line {
				total += cell * int64(r*3+c+1)
			}
		}
		for r, pair := range [2][2]int64{{v, 1}, {2, v}} {
			total += pair[0]*int64(r+1) + pair[1]
		}
		total += grids[k].cells[i][j]*11 + grids[1-k].points[j][i].y*13
		p := ps[i][1-i]
		total += p.x*17 + p.y*19
		local := grids[k]
		local.points[i][j].x = v
		local.cells[j][i] = v * 2
		total += local.points[i][j].x + local.cells[j][i]*23 + local.cells[1-j][1-i]*29
		if ps[i] == grids[k].points[i] {
			total++
		}
		return total
	}
	matching := points
	matching[1] = grids[0].points[1]
	for _, tc := range []struct {
		name    string
		i, j, k int
		ps      [2][2]nestedPoint
		hash    []byte
		wantErr string
	}{
		{name: "first cells", ps: points},
		{name: "mixed indexes", i: 1, j: 0, k: 1, ps: points},
		{name: "last cells", i: 1, j: 1, k: 1, ps: points},
		{name: "matching row of points", i: 1, j: 1, k: 0, ps: matching},
		{name: "hash from the other diagonal", i: 0, j: 1, ps: points, hash: table[0][1], wantErr: "OP_EQUALVERIFY failed"},
		{name: "third index past its dimension", k: 2, ps: points, wantErr: "OP_VERIFY failed"},
		{name: "negative third index", i: 1, j: 1, k: -1, ps: points, wantErr: "OP_VERIFY failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const v = 9
			values := map[string][]byte{
				"i": scriptInt(t, int64(tc.i)), "j": scriptInt(t, int64(tc.j)),
				"k": scriptInt(t, int64(tc.k)), "v": scriptInt(t, v),
				"expected": scriptInt(t, total(tc.i, tc.j, max(0, min(tc.k, 1)), v, tc.ps)),
			}
			for a := range 2 {
				for b := range 2 {
					for c := range 2 {
						values[fmt.Sprintf("cube.%d.%d.%d", a, b, c)] = scriptInt(t, cube[a][b][c])
					}
					values[fmt.Sprintf("ps.%d.%d.x", a, b)] = scriptInt(t, tc.ps[a][b].x)
					values[fmt.Sprintf("ps.%d.%d.y", a, b)] = scriptInt(t, tc.ps[a][b].y)
					values[fmt.Sprintf("hashes.%d.%d", a, b)] = table[b][a]
				}
			}
			if tc.hash != nil {
				values[fmt.Sprintf("hashes.%d.%d", tc.i, tc.j)] = tc.hash
			}
			spend := spendingPSBTWithWitness(t, deployment, instance, 10_000, instance.pkScript, arkadeScriptWitness(t, contract, group, values))
			requireVMResult(t, spend, emulatorKey.PubKey(), tc.wantErr)
		})
	}
}
