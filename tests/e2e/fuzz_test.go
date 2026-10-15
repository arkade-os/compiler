package e2e

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Random contracts must behave the same on the VM optimized and unoptimized. ARKADE_FUZZ_SEED
// and ARKADE_FUZZ_CASES widen the search; a failure names the seed and case to replay.
func TestDifferentialFuzz(t *testing.T) {
	if os.Getenv("ARKADEC_NO_OPTIMIZE") != "" {
		t.Skip("compiles both modes itself")
	}
	seed := envInt(t, "ARKADE_FUZZ_SEED", 1)
	cases := envInt(t, "ARKADE_FUZZ_CASES", 200)
	compiled := 0
	for index := int64(0); index < cases; index++ {
		r := rand.New(rand.NewSource(seed*1_000_003 + index))
		program := generateProgram(r)
		source := filepath.Join(t.TempDir(), "fuzz.ark")
		if err := os.WriteFile(source, []byte(program.source), 0600); err != nil {
			t.Fatal(err)
		}
		optimized, optimizedErr := compileMode(t, source, true)
		unoptimized, unoptimizedErr := compileMode(t, source, false)
		fail := func(format string, args ...any) {
			t.Helper()
			saveFailure(t, seed, index, program.source)
			t.Fatalf("seed %d case %d: %s\n%s", seed, index, fmt.Sprintf(format, args...), program.source)
		}
		if (optimizedErr == nil) != (unoptimizedErr == nil) {
			fail("only one mode compiles: optimized %v, unoptimized %v", optimizedErr, unoptimizedErr)
		}
		if optimizedErr != nil {
			continue
		}
		compiled++
		passing := program.values(t, program.passing)
		for mode, contract := range map[string]artifact{"optimized": optimized, "unoptimized": unoptimized} {
			if err := runCovenant(t, contract, passing); err != nil {
				fail("%s rejects the witness %s that every requirement accepts: %v", mode, describe(program.passing), err)
			}
		}
		for run := 0; run < 4; run++ {
			ints := program.randomWitness(r)
			values := program.values(t, ints)
			okOptimized := runCovenant(t, optimized, values)
			okUnoptimized := runCovenant(t, unoptimized, values)
			if (okOptimized == nil) != (okUnoptimized == nil) {
				fail("witness %s: optimized %v, unoptimized %v", describe(ints), okOptimized, okUnoptimized)
			}
		}
	}
	// Mostly rejected programs would test nothing.
	if compiled*10 < int(cases)*9 {
		t.Fatalf("only %d of %d generated contracts compiled", compiled, cases)
	}
}

func envInt(t *testing.T, name string, fallback int64) int64 {
	text := os.Getenv(name)
	if text == "" {
		return fallback
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value
}

func compileMode(t *testing.T, source string, optimize bool) (artifact, error) {
	t.Helper()
	compiler := os.Getenv("ARKADEC")
	if compiler == "" {
		compiler = filepath.Join("..", "..", "target", "debug", "arkadec")
	}
	output := filepath.Join(t.TempDir(), "artifact.json")
	args := []string{source, "-o", output}
	if !optimize {
		args = append(args, "--no-optimize")
	}
	if combined, err := exec.Command(compiler, args...).CombinedOutput(); err != nil {
		return artifact{}, fmt.Errorf("%v: %s", err, combined)
	}
	var contract artifact
	data, err := os.ReadFile(output)
	if err == nil {
		err = json.Unmarshal(data, &contract)
	}
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	return contract, nil
}

func runCovenant(t *testing.T, contract artifact, values map[string][]byte) error {
	serverKey, emulatorKey := fixedPrivateKey(1), fixedPrivateKey(2)
	group := covenantGroup(t, contract, "spend")
	instance := instantiateGroup(t, contract, "spend", nil, serverKey.PubKey(), emulatorKey.PubKey())
	spend := spendingPSBTWithWitness(t, fundingTx(instance.pkScript, 10_000), instance, 10_000,
		instance.pkScript, covenantWitness(t, contract, group, values))
	return executeArkadeScripts(spend, emulatorKey.PubKey())
}

func saveFailure(t *testing.T, seed, index int64, source string) {
	dir := os.Getenv("ARKADE_FUZZ_OUT")
	if dir == "" {
		return
	}
	name := filepath.Join(dir, fmt.Sprintf("seed-%d-case-%d.ark", seed, index))
	if err := os.MkdirAll(dir, 0o755); err != nil || os.WriteFile(name, []byte(source), 0o600) != nil {
		t.Logf("could not save %s", name)
	}
}

type input struct {
	name, kind string
	length     int
}

type program struct {
	source string
	inputs []input
	// A witness every requirement accepts, computed by evaluating the program in Go.
	passing map[string]int64
}

func (p program) values(t *testing.T, ints map[string]int64) map[string][]byte {
	values := map[string][]byte{}
	for name, value := range ints {
		values[name] = scriptInt(t, value)
	}
	return values
}

// A random witness of the same shape, which usually fails some requirement.
func (p program) randomWitness(r *rand.Rand) map[string]int64 {
	ints := map[string]int64{}
	for name := range p.passing {
		if strings.HasPrefix(name, "b") {
			ints[name] = r.Int63n(2)
		} else {
			ints[name] = r.Int63n(41) - 20
		}
	}
	return ints
}

func describe(ints map[string]int64) string {
	parts := make([]string, 0, len(ints))
	for name, value := range ints {
		parts = append(parts, fmt.Sprintf("%s=%d", name, value))
	}
	return strings.Join(parts, " ")
}

// env holds the values the generated code has computed so far.
type env map[string]int64

type intExpr struct {
	text string
	eval func(env) int64
}

type boolExpr struct {
	text string
	eval func(env) bool
}

// scope tracks the names visible in a block and which are not read yet; the validator
// rejects unread bindings, so a block's last requirement reads whatever is left.
type scope struct {
	parent *scope
	ints   []string
	bools  []string
	arrays map[string]int
	unread map[string]string
}

func (s *scope) child() *scope {
	return &scope{parent: s, arrays: map[string]int{}, unread: map[string]string{}}
}

func (s *scope) allInts() []string {
	if s == nil {
		return nil
	}
	return append(s.parent.allInts(), s.ints...)
}

func (s *scope) allBools() []string {
	if s == nil {
		return nil
	}
	return append(s.parent.allBools(), s.bools...)
}

func (s *scope) arrayNames() ([]string, map[string]int) {
	lengths := map[string]int{}
	var names []string
	for c := s; c != nil; c = c.parent {
		for name, length := range c.arrays {
			if _, seen := lengths[name]; !seen {
				names = append(names, name)
				lengths[name] = length
			}
		}
	}
	return names, lengths
}

func (s *scope) read(name string) string {
	for c := s; c != nil; c = c.parent {
		delete(c.unread, name)
	}
	return name
}

func (s *scope) declare(name, kind string) {
	switch kind {
	case "int":
		s.ints = append(s.ints, name)
	case "bool":
		s.bools = append(s.bools, name)
	}
	s.unread[name] = kind
}

type generator struct {
	r          *rand.Rand
	next       int
	helper     bool
	helperOp   string
	helperMult int64
	out        strings.Builder
}

func (g *generator) fresh(prefix string) string {
	g.next++
	return fmt.Sprintf("%s%d", prefix, g.next)
}

func (g *generator) pick(options []string) string {
	return options[g.r.Intn(len(options))]
}

func (g *generator) line(indent int, format string, args ...any) {
	g.out.WriteString(strings.Repeat("    ", indent))
	fmt.Fprintf(&g.out, format, args...)
	g.out.WriteByte('\n')
}

func compare(op string, a, b int64) bool {
	switch op {
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	case "==":
		return a == b
	default:
		return a != b
	}
}

func (g *generator) int(s *scope, depth int) intExpr {
	ints := s.allInts()
	arrays, lengths := s.arrayNames()
	choice := g.r.Intn(10)
	if depth <= 0 {
		choice %= 4
	}
	switch {
	case choice == 0 || len(ints) == 0 && len(arrays) == 0:
		n := int64(g.r.Intn(21) - 10)
		return intExpr{strconv.FormatInt(n, 10), func(env) int64 { return n }}
	case choice <= 2 && len(ints) > 0:
		name := s.read(g.pick(ints))
		return intExpr{name, func(e env) int64 { return e[name] }}
	case choice <= 3 && len(arrays) > 0:
		name := s.read(g.pick(arrays))
		if g.r.Intn(3) == 0 {
			n := int64(lengths[name])
			return intExpr{name + ".length", func(env) int64 { return n }}
		}
		element := fmt.Sprintf("%s.%d", name, g.r.Intn(lengths[name]))
		text := strings.Replace(element, ".", "[", 1) + "]"
		return intExpr{text, func(e env) int64 { return e[element] }}
	case choice <= 4 && g.helper:
		a, b := g.int(s, depth-1), g.int(s, depth-1)
		op, mult := g.helperOp, g.helperMult
		return intExpr{fmt.Sprintf("helper(%s, %s)", a.text, b.text), func(e env) int64 {
			x, y := a.eval(e), b.eval(e)
			if compare(op, x, y) {
				return x - y
			}
			return y*mult + x
		}}
	case choice == 5:
		a := g.int(s, depth-1)
		return intExpr{fmt.Sprintf("(-%s)", a.text), func(e env) int64 { return -a.eval(e) }}
	default:
		a, b := g.int(s, depth-1), g.int(s, depth-1)
		op := g.pick([]string{"+", "-", "*"})
		return intExpr{fmt.Sprintf("(%s %s %s)", a.text, op, b.text), func(e env) int64 {
			x, y := a.eval(e), b.eval(e)
			switch op {
			case "+":
				return x + y
			case "-":
				return x - y
			}
			return x * y
		}}
	}
}

func (g *generator) bool(s *scope, depth int) boolExpr {
	bools := s.allBools()
	choice := g.r.Intn(8)
	if depth <= 0 {
		choice %= 3
	}
	switch {
	case choice == 0 && len(bools) > 0:
		name := s.read(g.pick(bools))
		return boolExpr{name, func(e env) bool { return e[name] != 0 }}
	case choice <= 2:
		a, b := g.int(s, depth-1), g.int(s, depth-1)
		op := g.pick([]string{"<", "<=", ">", ">=", "==", "!="})
		return boolExpr{fmt.Sprintf("%s %s %s", a.text, op, b.text), func(e env) bool {
			return compare(op, a.eval(e), b.eval(e))
		}}
	case choice == 3:
		a := g.bool(s, depth-1)
		return boolExpr{fmt.Sprintf("!(%s)", a.text), func(e env) bool { return !a.eval(e) }}
	default:
		a, b := g.bool(s, depth-1), g.bool(s, depth-1)
		if g.r.Intn(2) == 0 {
			return boolExpr{fmt.Sprintf("(%s && %s)", a.text, b.text), func(e env) bool { return a.eval(e) && b.eval(e) }}
		}
		return boolExpr{fmt.Sprintf("(%s || %s)", a.text, b.text), func(e env) bool { return a.eval(e) || b.eval(e) }}
	}
}

// require emits a requirement that holds in every one of `envs`, or nothing if none can.
func (g *generator) require(indent int, condition boolExpr, envs []env) {
	holds, fails := true, true
	for _, e := range envs {
		ok := condition.eval(e)
		holds, fails = holds && ok, fails && !ok
	}
	switch {
	case holds:
		g.line(indent, "require(%s);", condition.text)
	case fails:
		g.line(indent, "require(!(%s));", condition.text)
	}
}

func (g *generator) block(s *scope, e env, indent, depth int) {
	for statements := 1 + g.r.Intn(3); statements > 0; statements-- {
		switch choice := g.r.Intn(6); {
		case choice <= 1:
			g.require(indent, g.bool(s, 2), []env{e})
		case choice == 2:
			name, value := g.fresh("v"), g.int(s, 2)
			g.line(indent, "let %s = %s;", name, value.text)
			e[name] = value.eval(e)
			s.declare(name, "int")
		case choice == 3 && depth > 0:
			condition := g.bool(s, 2)
			taken := condition.eval(e)
			g.line(indent, "if (%s) {", condition.text)
			g.branch(s, e, taken, indent, depth)
			g.line(indent, "} else {")
			g.branch(s, e, !taken, indent, depth)
			g.line(indent, "}")
		case choice == 4 && depth > 0:
			g.loop(s, e, indent)
		default:
			g.require(indent, g.bool(s, 1), []env{e})
		}
	}
	g.readRemaining(s, e, indent)
}

// branch generates one arm; an arm that does not run sees copied values and changes nothing.
func (g *generator) branch(s *scope, e env, runs bool, indent, depth int) {
	arm := e
	if !runs {
		arm = maps.Clone(e)
	}
	g.block(s.child(), arm, indent+1, depth-1)
}

// loop sums a term over an array and requires the sum, so every iteration's arithmetic counts.
func (g *generator) loop(s *scope, e env, indent int) {
	arrays, lengths := s.arrayNames()
	if len(arrays) == 0 {
		g.require(indent, g.bool(s, 1), []env{e})
		return
	}
	array := s.read(g.pick(arrays))
	acc, index, value := g.fresh("acc"), g.fresh("i"), g.fresh("x")
	inner := s.child()
	inner.declare(index, "int")
	inner.declare(value, "int")
	term := g.int(inner, 1)
	inner.read(index)
	inner.read(value)
	condition := g.bool(inner, 1)
	iterations := make([]env, lengths[array])
	for k := range iterations {
		iterations[k] = maps.Clone(e)
		iterations[k][index] = int64(k)
		iterations[k][value] = e[fmt.Sprintf("%s.%d", array, k)]
	}
	g.line(indent, "int %s = 0;", acc)
	g.line(indent, "for (%s, %s) in %s {", index, value, array)
	g.line(indent+1, "%s = %s + %s * (%s + 1) + %s;", acc, acc, value, index, term.text)
	g.require(indent+1, condition, iterations)
	g.line(indent, "}")
	total := int64(0)
	for _, iteration := range iterations {
		total += iteration[value]*(iteration[index]+1) + term.eval(iteration)
	}
	g.line(indent, "require(%s == %d);", acc, total)
}

func (g *generator) readRemaining(s *scope, e env, indent int) {
	var terms []boolExpr
	var read []string
	for name, kind := range s.unread {
		read = append(read, name)
		switch kind {
		case "bool":
			name := name
			terms = append(terms, boolExpr{name, func(e env) bool { return e[name] != 0 }})
		default:
			text, key := name, name
			if kind == "array" {
				text, key = name+"[0]", name+".0"
			}
			op, bound := g.pick([]string{"<", ">=", "!="}), int64(g.r.Intn(21)-10)
			terms = append(terms, boolExpr{fmt.Sprintf("%s %s %d", text, op, bound), func(e env) bool {
				return compare(op, e[key], bound)
			}})
		}
	}
	for _, name := range read {
		s.read(name)
	}
	if len(terms) == 0 {
		return
	}
	joined := terms[0]
	for _, term := range terms[1:] {
		left, right := joined, term
		joined = boolExpr{left.text + " || " + right.text, func(e env) bool { return left.eval(e) || right.eval(e) }}
	}
	// A requirement that cannot hold here still reads its names when negated.
	g.require(indent, joined, []env{e})
}

func generateProgram(r *rand.Rand) program {
	g := &generator{
		r:          r,
		helper:     r.Intn(2) == 0,
		helperOp:   []string{"<", ">", "=="}[r.Intn(3)],
		helperMult: int64(1 + r.Intn(3)),
	}
	root := (&scope{}).child()
	e := env{}
	var params []string
	var inputs []input
	for count := 1 + r.Intn(4); count > 0; count-- {
		switch r.Intn(4) {
		case 0:
			name := g.fresh("b")
			params, inputs = append(params, "bool "+name), append(inputs, input{name: name, kind: "bool"})
			root.declare(name, "bool")
			e[name] = r.Int63n(2)
		case 1:
			name, length := g.fresh("xs"), 1+r.Intn(3)
			params = append(params, fmt.Sprintf("int[%d] %s", length, name))
			inputs = append(inputs, input{name: name, kind: "array", length: length})
			root.arrays[name] = length
			root.unread[name] = "array"
			for i := 0; i < length; i++ {
				e[fmt.Sprintf("%s.%d", name, i)] = r.Int63n(41) - 20
			}
		default:
			name := g.fresh("n")
			params, inputs = append(params, "int "+name), append(inputs, input{name: name, kind: "int"})
			root.declare(name, "int")
			e[name] = r.Int63n(41) - 20
		}
	}
	witness := maps.Clone(e)
	g.line(0, "contract Fuzz() {")
	if g.helper {
		g.line(1, "private function helper(int a, int b) int {")
		g.line(2, "if (a %s b) {", g.helperOp)
		g.line(3, "return a - b;")
		g.line(2, "}")
		g.line(2, "return (b * %d) + a;", g.helperMult)
		g.line(1, "}")
	}
	g.line(1, "function spend(%s) {", strings.Join(params, ", "))
	g.block(root, e, 2, 2)
	g.line(1, "}")
	g.line(0, "}")
	return program{source: g.out.String(), inputs: inputs, passing: witness}
}
