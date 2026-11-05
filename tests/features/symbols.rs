use arkade_compiler::analyze;
use arkade_compiler::symbols::{Definition, SymbolKind, Symbols};
use std::collections::BTreeMap;

const FEES: &str = "library Fees {
    const int DELAY = 144;
    function calculate(int amount) int { return amount * 2; }
}";

const MAIN: &str = "import \"fees.ark\";
struct Point { int x; }
contract Vault(Point p, pubkey owner) {
    const int LIMIT = 3;
    function spend(signature sig, int[2] xs) {
        let total = xs[0] + LIMIT;
        for (i, x) in xs {
            int doubled = x * 2; doubled = doubled + i;
            require(doubled + i >= Fees.calculate(x) + Fees.DELAY);
        }
        require(checkSig(sig, owner));
        require(helper(total) == p.x);
        require(tx.outputs[0].script == new Vault(p, owner));
    }
    private function helper(int amount) int { return amount + Vault.LIMIT; }
    function unilateral(signature ownerSig) tapscript {
        require(older(blocks(144)));
        require(checkSig(ownerSig, owner));
    }
}";

fn project(main: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("main.ark".to_string(), main.to_string()),
        ("fees.ark".to_string(), FEES.to_string()),
    ])
}

fn position(source: &str, offset: usize) -> String {
    let before = &source[..offset];
    let line = before.matches('\n').count() + 1;
    let column = offset - before.rfind('\n').map_or(0, |newline| newline + 1) + 1;
    format!("{line}:{column}")
}

fn describe(files: &BTreeMap<String, String>, definition: &Definition) -> String {
    let ty = definition
        .ty
        .as_ref()
        .map(|ty| format!(" {ty}"))
        .unwrap_or_default();
    let at = position(&files[&definition.file], definition.span.start);
    format!(
        "{:?} {}{ty} {}:{at}",
        definition.kind, definition.name, definition.file
    )
}

fn references(files: &BTreeMap<String, String>, symbols: &Symbols) -> Vec<String> {
    symbols
        .references()
        .iter()
        .map(|reference| {
            let source = &files[&reference.file];
            let text = &source[reference.span.start..reference.span.end];
            let at = position(source, reference.span.start);
            let definition = &symbols.definitions()[reference.definition];
            format!(
                "{}:{at} {text} -> {}",
                reference.file,
                describe(files, definition)
            )
        })
        .collect()
}

#[test]
fn symbols_resolve_bindings_calls_and_constants_across_files() {
    let files = project(MAIN);
    let analysis = analyze("main.ark", &files);
    assert!(
        analysis.diagnostics().is_empty(),
        "{:?}",
        analysis.diagnostics()
    );
    let symbols = analysis.symbols();
    let definitions: Vec<_> = symbols
        .definitions()
        .iter()
        .map(|definition| describe(&files, definition))
        .collect();
    assert_eq!(
        definitions,
        [
            "Library Fees fees.ark:1:9",
            "Constant DELAY int fees.ark:2:15",
            "Function calculate int fees.ark:3:14",
            "Parameter amount int fees.ark:3:28",
            "Contract Vault main.ark:3:10",
            "Struct Point main.ark:2:8",
            "Field x int main.ark:2:20",
            "Constant LIMIT int main.ark:4:15",
            "Function spend main.ark:5:14",
            "Function helper int main.ark:15:22",
            "Tapscript unilateral main.ark:16:14",
            "Parameter ownerSig signature main.ark:16:35",
            "Parameter p Point main.ark:3:22",
            "Parameter owner pubkey main.ark:3:32",
            "Parameter sig signature main.ark:5:30",
            "Parameter xs int[2] main.ark:5:42",
            "Variable total int main.ark:6:13",
            "Variable i int main.ark:7:14",
            "Variable x int main.ark:7:17",
            "Variable doubled int main.ark:8:17",
            "Parameter amount int main.ark:15:33",
        ]
    );
    assert_eq!(
        references(&files, symbols),
        [
            "fees.ark:3:49 amount -> Parameter amount int fees.ark:3:28",
            "main.ark:6:29 LIMIT -> Constant LIMIT int main.ark:4:15",
            "main.ark:9:56 Fees -> Library Fees fees.ark:1:9",
            "main.ark:9:61 DELAY -> Constant DELAY int fees.ark:2:15",
            "main.ark:15:63 Vault -> Contract Vault main.ark:3:10",
            "main.ark:15:69 LIMIT -> Constant LIMIT int main.ark:4:15",
            "main.ark:6:21 xs -> Parameter xs int[2] main.ark:5:42",
            "main.ark:7:23 xs -> Parameter xs int[2] main.ark:5:42",
            "main.ark:8:27 x -> Variable x int main.ark:7:17",
            "main.ark:8:34 doubled -> Variable doubled int main.ark:8:17",
            "main.ark:8:44 doubled -> Variable doubled int main.ark:8:17",
            "main.ark:8:54 i -> Variable i int main.ark:7:14",
            "main.ark:9:21 doubled -> Variable doubled int main.ark:8:17",
            "main.ark:9:31 i -> Variable i int main.ark:7:14",
            "main.ark:9:36 Fees -> Library Fees fees.ark:1:9",
            "main.ark:9:41 calculate -> Function calculate int fees.ark:3:14",
            "main.ark:9:51 x -> Variable x int main.ark:7:17",
            "main.ark:11:26 sig -> Parameter sig signature main.ark:5:30",
            "main.ark:11:31 owner -> Parameter owner pubkey main.ark:3:32",
            "main.ark:12:17 helper -> Function helper int main.ark:15:22",
            "main.ark:12:24 total -> Variable total int main.ark:6:13",
            "main.ark:12:34 p -> Parameter p Point main.ark:3:22",
            "main.ark:13:45 Vault -> Contract Vault main.ark:3:10",
            "main.ark:13:51 p -> Parameter p Point main.ark:3:22",
            "main.ark:13:54 owner -> Parameter owner pubkey main.ark:3:32",
            "main.ark:15:54 amount -> Parameter amount int main.ark:15:33",
        ]
    );
}

#[test]
fn definition_at_finds_a_name_from_its_uses_and_locals_are_visible_in_their_block() {
    let files = project(MAIN);
    let analysis = analyze("main.ark", &files);
    let symbols = analysis.symbols();
    let use_end = MAIN.find("doubled + i").unwrap() + "doubled".len();
    let doubled = symbols.definition_at("main.ark", use_end).unwrap();
    assert_eq!(
        describe(&files, doubled),
        "Variable doubled int main.ark:8:17"
    );
    assert_eq!(
        symbols.definition_at("main.ark", doubled.span.start),
        Some(doubled)
    );
    let visible = doubled.visible.unwrap();
    assert_eq!(
        &MAIN[visible.start..visible.end].lines().last(),
        &Some("        }")
    );
    let amount = symbols.definition_at("fees.ark", FEES.find("amount * 2").unwrap());
    assert_eq!(
        describe(&files, amount.unwrap()),
        "Parameter amount int fees.ark:3:28"
    );
    let xs = symbols
        .definition_at("main.ark", MAIN.find("xs[0]").unwrap())
        .unwrap();
    assert_eq!(xs.kind, SymbolKind::Parameter);
    let function = xs.visible.unwrap();
    assert!(MAIN[function.start..function.end].starts_with("function spend"));
    assert!(MAIN[function.start..function.end].ends_with('}'));
}

#[test]
fn symbols_survive_validation_errors() {
    let source = "contract C() { function spend(int n) { let m = n + 1; require(m > k); } }";
    let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
    let analysis = analyze("main.ark", &files);
    assert!(analysis.contract().is_none());
    assert!(!analysis.diagnostics().is_empty());
    let m = analysis
        .symbols()
        .definition_at("main.ark", source.find("m > k").unwrap())
        .unwrap();
    assert_eq!(describe(&files, m), "Variable m int main.ark:1:44");
}

#[test]
fn symbols_survive_constant_and_scope_errors() {
    for source in [
        "contract C() { function spend(int n, int[Q] xs) { require(n > 0); } }",
        "contract C() { function spend(int n, Missing m) { require(n > 0); } }",
    ] {
        let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
        let analysis = analyze("main.ark", &files);
        assert!(analysis.contract().is_none());
        let n = analysis
            .symbols()
            .definition_at("main.ark", source.find("n > 0").unwrap());
        assert_eq!(n.map(|n| n.kind), Some(SymbolKind::Parameter), "{source}");
    }
}

#[test]
fn references_in_parentheses_and_after_new_cover_the_name() {
    let source = "contract C(int a) {
    const int K = 1;
    function spend(int n) {
        require(( n ) + (h(a)) > (K));
        require(tx.outputs[0].script == new // C
            C(a));
    }
    private function h(int x) int { return x; }
}";
    let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
    let analysis = analyze("main.ark", &files);
    let symbols = analysis.symbols();
    let mut names: Vec<_> = symbols
        .references()
        .iter()
        .map(|reference| {
            let text = &source[reference.span.start..reference.span.end];
            assert_eq!(text, symbols.definitions()[reference.definition].name);
            text
        })
        .collect();
    names.sort();
    assert_eq!(names, ["C", "K", "a", "a", "h", "n", "x"]);
}

#[test]
fn a_local_is_visible_to_the_end_of_its_branch() {
    let source = "contract C() { function spend(int n) { if (n > 0) { let a = n; require(a == 1); } else { let b = n; require(b == 0); } } }";
    let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
    let analysis = analyze("main.ark", &files);
    for (local, visible) in [
        ("a = n", " require(a == 1); }"),
        ("b = n", " require(b == 0); }"),
    ] {
        let definition = analysis
            .symbols()
            .definition_at("main.ark", source.find(local).unwrap())
            .unwrap();
        let span = definition.visible.unwrap();
        assert_eq!(&source[span.start..span.end], visible);
    }
    let after_branch = source.find(" else").unwrap();
    let visible = analysis.symbols().visible_at("main.ark", after_branch);
    assert!(!visible.iter().any(|(name, _)| *name == "a"), "{visible:?}");
}

#[test]
fn visible_names_follow_blocks_and_include_imports() {
    let files = project(MAIN);
    let analysis = analyze("main.ark", &files);
    let visible = |needle: &str| {
        let offset = MAIN.find(needle).unwrap();
        let names: Vec<String> = analysis
            .symbols()
            .visible_at("main.ark", offset)
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();
        names
    };
    let in_loop = visible("require(doubled");
    for name in [
        "doubled",
        "i",
        "x",
        "total",
        "xs",
        "sig",
        "owner",
        "LIMIT",
        "Fees",
        "Fees.calculate",
        "Fees.DELAY",
        "Point",
        "helper",
    ] {
        assert!(in_loop.iter().any(|n| n == name), "{name}: {in_loop:?}");
    }
    let after_loop = visible("require(checkSig");
    assert!(
        !after_loop.iter().any(|n| n == "doubled" || n == "i"),
        "{after_loop:?}"
    );
    let before_total = visible("let total");
    assert!(
        !before_total.iter().any(|n| n == "total"),
        "{before_total:?}"
    );
    let in_initializer = visible("xs[0] + LIMIT");
    assert!(
        !in_initializer.iter().any(|n| n == "total"),
        "{in_initializer:?}"
    );
    assert!(!in_loop.iter().any(|n| n == "spend" || n == "Vault.spend"));
    let in_tapscript = visible("checkSig(ownerSig");
    assert!(
        in_tapscript.iter().any(|n| n == "ownerSig") && !in_tapscript.iter().any(|n| n == "sig"),
        "{in_tapscript:?}"
    );
    let in_helper = visible("return amount");
    assert!(
        in_helper.iter().any(|n| n == "amount") && !in_helper.iter().any(|n| n == "sig"),
        "{in_helper:?}"
    );
}

#[test]
fn a_shadowing_name_is_visible_once_as_the_inner_definition() {
    let source = "contract C(int amount) { function spend(int amount) { require(amount > 0); } }";
    let files = BTreeMap::from([("main.ark".to_string(), source.to_string())]);
    let analysis = analyze("main.ark", &files);
    let offset = source.find("amount > 0").unwrap();
    let amounts: Vec<_> = analysis
        .symbols()
        .visible_at("main.ark", offset)
        .into_iter()
        .filter(|(name, _)| *name == "amount")
        .map(|(_, definition)| definition.span.start)
        .collect();
    assert_eq!(amounts, [source.rfind("int amount)").unwrap() + 4]);
}

#[test]
fn a_file_keeps_its_names_when_an_import_fails() {
    let main = "import \"fees.ark\";\ncontract C(int limit) { function spend(int n) { require(n > limit); } }";
    for (fees, imported) in [
        ("library Fees {", None),
        (
            "library Fees { function f(int a) int { return a + nope; } }",
            Some("Fees.f"),
        ),
        ("struct C { int x; }", None),
    ] {
        let files = BTreeMap::from([
            ("main.ark".to_string(), main.to_string()),
            ("fees.ark".to_string(), fees.to_string()),
        ]);
        let analysis = analyze("main.ark", &files);
        assert!(analysis.contract().is_none(), "{fees}");
        let offset = main.find("require").unwrap();
        let visible: Vec<_> = analysis
            .symbols()
            .visible_at("main.ark", offset)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert!(
            visible.contains(&"limit") && visible.contains(&"n"),
            "{fees}: {visible:?}"
        );
        assert!(
            imported.is_none_or(|name| visible.contains(&name)),
            "{visible:?}"
        );
    }
}
