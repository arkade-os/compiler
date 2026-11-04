use std::path::Path;
use std::thread::JoinHandle;

use lsp_server::{Connection, Message, Notification, Request, RequestId};
use lsp_types::Url;
use proptest::prelude::*;
use serde_json::{json, Value};

const RULES: &str = r#"library Rules {
  function preservesValue() {
    require(tx.outputs[0].value >= tx.inputs[0].value, "value");
  }
}
"#;

const VAULT: &str = r#"import "lib/rules.ark";

contract Vault(pubkey owner, int exit) {
  function spend(signature ownerSig) {
    Rules.preservesValue();
    require(checkSig(ownerSig, owner));
  }

  function unilateral(signature ownerSig) tapscript {
    require(older(exit));
    require(checkSig(ownerSig, owner));
  }
}
"#;

struct Client {
    connection: Connection,
    server: JoinHandle<Result<(), String>>,
    next_id: i32,
}

impl Client {
    fn start(root: &Path) -> Self {
        let root = Url::from_directory_path(root).unwrap();
        Self::start_with(json!({ "capabilities": {}, "rootUri": root }))
    }

    fn start_with(initialize: Value) -> Self {
        let (server, connection) = Connection::memory();
        let server = std::thread::spawn(move || arkade_lsp::run(server).map_err(|e| e.to_string()));
        let mut client = Client {
            connection,
            server,
            next_id: 0,
        };
        client.request("initialize", initialize);
        client.notify("initialized", json!({}));
        client
    }

    fn notify(&self, method: &str, params: Value) {
        let notification = Notification::new(method.to_string(), params);
        self.connection.sender.send(notification.into()).unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let response = self.call(method, params);
        assert!(response.error.is_none(), "{:?}", response.error);
        response.result.unwrap_or(Value::Null)
    }

    fn call(&mut self, method: &str, params: Value) -> lsp_server::Response {
        self.next_id += 1;
        let id = RequestId::from(self.next_id);
        let request = Request::new(id.clone(), method.to_string(), params);
        self.connection.sender.send(request.into()).unwrap();
        loop {
            if let Message::Response(response) = self.connection.receiver.recv().unwrap() {
                assert_eq!(response.id, id);
                return response;
            }
        }
    }

    fn diagnostics(&self, uri: &Url) -> Vec<Value> {
        loop {
            if let Message::Notification(n) = self.connection.receiver.recv().unwrap() {
                if n.method == "textDocument/publishDiagnostics" && n.params["uri"] == json!(uri) {
                    return n.params["diagnostics"].as_array().unwrap().clone();
                }
            }
        }
    }

    fn open(&self, uri: &Url, text: &str) -> Vec<Value> {
        self.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": uri, "languageId": "arkade", "version": 1, "text": text } }),
        );
        self.diagnostics(uri)
    }

    fn change(&self, uri: &Url, text: &str) -> Vec<Value> {
        self.notify(
            "textDocument/didChange",
            json!({ "textDocument": { "uri": uri, "version": 2 }, "contentChanges": [{ "text": text }] }),
        );
        self.diagnostics(uri)
    }

    fn definition(&mut self, uri: &Url, line: u32, character: u32) -> Value {
        self.request(
            "textDocument/definition",
            json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } }),
        )
    }

    fn stop(mut self) {
        self.request("shutdown", Value::Null);
        self.notify("exit", Value::Null);
        self.server.join().unwrap().unwrap();
    }
}

fn workspace() -> (tempfile::TempDir, Url, Url) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("lib")).unwrap();
    std::fs::write(root.join("lib/rules.ark"), RULES).unwrap();
    std::fs::write(root.join("vault.ark"), VAULT).unwrap();
    let vault = Url::from_file_path(root.join("vault.ark")).unwrap();
    let rules = Url::from_file_path(root.join("lib/rules.ark")).unwrap();
    (dir, vault, rules)
}

fn range(diagnostic: &Value) -> (u64, u64, u64) {
    let start = &diagnostic["range"]["start"];
    let end = &diagnostic["range"]["end"];
    assert_eq!(start["line"], end["line"]);
    (
        start["line"].as_u64().unwrap(),
        start["character"].as_u64().unwrap(),
        end["character"].as_u64().unwrap(),
    )
}

#[test]
fn diagnostics_follow_edits() {
    let (dir, vault, _) = workspace();
    let client = Client::start(&dir.path().canonicalize().unwrap());
    assert_eq!(client.open(&vault, VAULT), Vec::<Value>::new());

    let broken = VAULT.replace(
        "function spend(signature ownerSig)",
        "function spend(signature ownerSig",
    );
    let [syntax] = client.change(&vault, &broken).try_into().unwrap();
    assert_eq!(range(&syntax).0, 3);
    assert_eq!(syntax["severity"], 1);

    let unknown = VAULT.replace("pubkey owner", "Owner owner");
    let [semantic] = client.change(&vault, &unknown).try_into().unwrap();
    assert!(semantic["message"]
        .as_str()
        .unwrap()
        .starts_with("unknown type 'Owner'"));
    assert_eq!(range(&semantic), (2, 21, 26));

    let typo = VAULT.replace(
        "require(checkSig(ownerSig, owner));\n  }\n}",
        "require(checkSig(ownerSig, ownr));\n  }\n}",
    );
    let [unknown] = client.change(&vault, &typo).try_into().unwrap();
    assert!(unknown["message"].as_str().unwrap().contains("`ownr`"));
    assert_eq!(range(&unknown), (10, 31, 35));

    client.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": vault } }),
    );
    assert_eq!(client.diagnostics(&vault), Vec::<Value>::new());
    client.stop();
}

#[test]
fn library_errors_reach_importers() {
    let (dir, vault, rules) = workspace();
    let client = Client::start(&dir.path().canonicalize().unwrap());
    client.open(&vault, VAULT);
    client.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rules, "languageId": "arkade", "version": 1, "text": RULES.replace("tx.inputs[0].value", "missing") } }),
    );
    let mut importer = Vec::new();
    let mut library = Vec::new();
    for _ in 0..2 {
        match client.connection.receiver.recv().unwrap() {
            Message::Notification(n) if n.params["uri"] == json!(vault) => {
                importer = n.params["diagnostics"].as_array().unwrap().clone()
            }
            Message::Notification(n) => {
                library = n.params["diagnostics"].as_array().unwrap().clone()
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(library.len(), 1);
    let [import] = importer.try_into().unwrap();
    assert_eq!(range(&import), (0, 0, 23));
    client.stop();
}

#[test]
fn outline_and_definitions() {
    let (dir, vault, rules) = workspace();
    let mut client = Client::start(&dir.path().canonicalize().unwrap());
    client.open(&vault, VAULT);

    let outline = client.request(
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": vault } }),
    );
    let [contract] = outline.as_array().unwrap().clone().try_into().unwrap();
    assert_eq!(contract["name"], "Vault");
    let children: Vec<_> = contract["children"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].clone())
        .collect();
    assert_eq!(
        children,
        [
            json!("owner"),
            json!("exit"),
            json!("spend"),
            json!("unilateral")
        ]
    );

    let owner = client.definition(&vault, 5, 33);
    assert_eq!(owner["uri"], json!(vault));
    assert_eq!(
        owner["range"]["start"],
        json!({ "line": 2, "character": 22 })
    );

    let local = client.definition(&vault, 10, 22);
    assert_eq!(
        local["range"]["start"],
        json!({ "line": 8, "character": 32 })
    );

    let function = client.definition(&vault, 4, 14);
    assert_eq!(function["uri"], json!(rules));
    assert_eq!(
        function["range"]["start"],
        json!({ "line": 1, "character": 11 })
    );

    let import = client.definition(&vault, 0, 12);
    assert_eq!(import["uri"], json!(rules));

    assert_eq!(client.definition(&vault, 5, 18), Value::Null);
    client.stop();
}

fn labels(items: &Value) -> Vec<String> {
    let mut labels: Vec<String> = items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["label"].as_str().unwrap().to_string())
        .collect();
    labels.sort();
    labels
}

#[test]
fn completion_of_imports() {
    let (dir, vault, rules) = workspace();
    let mut client = Client::start(&dir.path().canonicalize().unwrap());
    let complete = |client: &mut Client, uri: &Url, line: u32, character: u32| {
        client.request(
            "textDocument/completion",
            json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } }),
        )
    };

    let typing = VAULT.replace("    Rules.preservesValue();", "    Rules.");
    client.open(&vault, &typing);
    let members = complete(&mut client, &vault, 4, 10);
    assert_eq!(labels(&members), ["preservesValue"]);
    assert_eq!(members[0]["insertText"], "preservesValue($0)");

    client.change(
        &vault,
        &VAULT.replace("    Rules.preservesValue();", "    Ru"),
    );
    let top = complete(&mut client, &vault, 4, 6);
    assert_eq!(
        labels(&top),
        ["Rules", "Vault", "exit", "owner", "ownerSig"]
    );

    client.change(&vault, &format!("import \"\n{VAULT}"));
    let paths = complete(&mut client, &vault, 0, 8);
    assert_eq!(labels(&paths), ["lib/rules.ark"]);
    assert_eq!(
        paths[0]["textEdit"]["range"]["start"],
        json!({ "line": 0, "character": 8 })
    );

    client.open(&rules, &format!("import \"../\n{RULES}"));
    assert_eq!(
        labels(&complete(&mut client, &rules, 0, 11)),
        ["../vault.ark"]
    );
    client.stop();
}

#[test]
fn completion_imports_what_it_offers() {
    let (dir, vault, _) = workspace();
    let mut client = Client::start(&dir.path().canonicalize().unwrap());
    let unimported = VAULT.replace("import \"lib/rules.ark\";\n", "");
    let complete = |client: &mut Client, text: String, line: u32, character: u32| {
        client.change(&vault, &text);
        client.request(
            "textDocument/completion",
            json!({ "textDocument": { "uri": vault }, "position": { "line": line, "character": character } }),
        )
    };
    client.open(&vault, &unimported);
    let edit = json!([{ "range": { "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 0 } }, "newText": "import \"lib/rules.ark\";\n" }]);

    let name = complete(
        &mut client,
        unimported.replace("    Rules.preservesValue();", "    Ru"),
        3,
        6,
    );
    let rules = name
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == "Rules")
        .unwrap();
    assert_eq!(rules["additionalTextEdits"], edit);
    let owner = name
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == "owner")
        .unwrap();
    assert_eq!(owner["additionalTextEdits"], Value::Null);

    let member = complete(
        &mut client,
        unimported.replace("    Rules.preservesValue();", "    Rules."),
        3,
        10,
    );
    assert_eq!(labels(&member), ["preservesValue"]);
    assert_eq!(member[0]["additionalTextEdits"], edit);

    let pragma = format!(
        "pragma arkade ^0.1.0;\n{}",
        unimported.replace("    Rules.preservesValue();", "    Ru")
    );
    let after_pragma = complete(&mut client, pragma, 4, 6);
    let rules = after_pragma
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == "Rules")
        .unwrap();
    assert_eq!(rules["additionalTextEdits"][0]["range"]["start"]["line"], 1);
    client.stop();
}

#[test]
fn hover_shows_folded_constants() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("lib")).unwrap();
    std::fs::write(
        root.join("lib/fees.ark"),
        "library Fees {\n  const int BASIS = 10000;\n  function f() { require(true); }\n}\n",
    )
    .unwrap();
    let main = "import \"lib/fees.ark\";\n\ncontract Vault(pubkey owner, int exit) {\n  const int DAY = 144;\n  const int EXIT = DAY * 7;\n  const int FEE = Fees.BASIS / 20;\n\n  function spend(signature sig) {\n    require(tx.outputs[0].value >= FEE);\n    require(checkSig(sig, owner));\n  }\n}\n";
    std::fs::write(root.join("vault.ark"), main).unwrap();
    let uri = Url::from_file_path(root.join("vault.ark")).unwrap();
    let mut client = Client::start(&root);
    client.open(&uri, main);
    let mut hover = |line: usize, word: &str| {
        let character = main.lines().nth(line).unwrap().rfind(word).unwrap() + 1;
        let result = client.request(
            "textDocument/hover",
            json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } }),
        );
        result["contents"]["value"].as_str().unwrap().to_string()
    };

    assert_eq!(hover(4, "EXIT"), "```arkade\nconst int EXIT = 1008\n```");
    assert_eq!(hover(8, "FEE"), "```arkade\nconst int FEE = 500\n```");
    assert_eq!(
        hover(5, "BASIS"),
        "```arkade\nconst int BASIS = 10000\n```\n\nFrom `lib/fees.ark`"
    );
    assert_eq!(hover(9, "owner"), "```arkade\nparameter pubkey owner\n```");
    client.stop();
}

#[test]
fn references_and_highlights_cover_covenants_and_tapscripts() {
    let (dir, vault, _) = workspace();
    let mut client = Client::start(&dir.path().canonicalize().unwrap());
    client.open(&vault, VAULT);
    let starts = |locations: &Value| -> Vec<(u64, u64)> {
        let mut starts: Vec<_> = locations
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                let start = &l["range"]["start"];
                (
                    start["line"].as_u64().unwrap(),
                    start["character"].as_u64().unwrap(),
                )
            })
            .collect();
        starts.sort();
        starts
    };
    let position =
        json!({ "textDocument": { "uri": vault }, "position": { "line": 5, "character": 33 } });
    let mut with_declaration = position.clone();
    with_declaration["context"] = json!({ "includeDeclaration": true });
    let owner = client.request("textDocument/references", with_declaration);
    assert_eq!(starts(&owner), [(2, 22), (5, 31), (10, 31)]);
    let mut without = position;
    without["context"] = json!({ "includeDeclaration": false });
    assert_eq!(
        starts(&client.request("textDocument/references", without)),
        [(5, 31), (10, 31)]
    );

    let highlights = client.request(
        "textDocument/documentHighlight",
        json!({ "textDocument": { "uri": vault }, "position": { "line": 10, "character": 22 } }),
    );
    assert_eq!(starts(&highlights), [(8, 32), (10, 21)]);
    client.stop();
}

#[test]
fn completion_after_a_multibyte_character() {
    let (dir, vault, _) = workspace();
    let mut client = Client::start(&dir.path().canonicalize().unwrap());
    let text = VAULT.replace("    Rules.preservesValue();", "    // łowner");
    client.open(&vault, &text);
    let line = "    // łowner";
    let items = client.request(
        "textDocument/completion",
        json!({ "textDocument": { "uri": vault }, "position": { "line": 4, "character": line.encode_utf16().count() } }),
    );
    assert!(items.is_array());
    client.stop();
}

#[test]
fn an_import_followed_by_a_quoted_comment() {
    let (dir, vault, rules) = workspace();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(
        root.join("lib/other.ark"),
        "library Other {\n  function f() { require(true); }\n}\n",
    )
    .unwrap();
    let mut client = Client::start(&root);
    let text = VAULT.replace(
        "import \"lib/rules.ark\";",
        "import \"lib/other.ark\";\nimport \"lib/rules.ark\"; // see \"docs\"",
    );
    client.open(&vault, &text);
    assert_eq!(client.definition(&vault, 1, 10)["uri"], json!(rules));
    client.change(
        &vault,
        &text.replace("\n\ncontract", "\nimport \"\ncontract"),
    );
    assert_eq!(client.definition(&vault, 1, 10)["uri"], json!(rules));

    let typing = text.replace("    Rules.preservesValue();", "    Ru");
    client.change(&vault, &typing);
    let items = client.request(
        "textDocument/completion",
        json!({ "textDocument": { "uri": vault }, "position": { "line": 5, "character": 6 } }),
    );
    let item = items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == "Rules")
        .unwrap();
    assert_eq!(item["additionalTextEdits"], Value::Null);

    client.change(&vault, &text);
    client.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": rules, "languageId": "arkade", "version": 1, "text": RULES.replace("tx.inputs[0].value", "missing") } }),
    );
    let [import] = client.diagnostics(&vault).try_into().unwrap();
    assert_eq!(range(&import), (1, 0, 23));
    client.stop();
}

fn import_paths(client: &mut Client, uri: &Url) -> Vec<String> {
    client.change(uri, &format!("import \"\n{VAULT}"));
    labels(&client.request(
        "textDocument/completion",
        json!({ "textDocument": { "uri": uri }, "position": { "line": 0, "character": 8 } }),
    ))
}

#[test]
fn the_workspace_scan_skips_symlinked_directories() {
    let (dir, vault, _) = workspace();
    let root = dir.path().canonicalize().unwrap();
    std::os::unix::fs::symlink("..", root.join("lib/up")).unwrap();
    std::os::unix::fs::symlink(".", root.join("here")).unwrap();
    let mut client = Client::start(&root);
    client.open(&vault, VAULT);
    assert_eq!(import_paths(&mut client, &vault), ["lib/rules.ark"]);
    client.stop();
}

#[test]
fn the_import_closure_loads_past_the_file_cap() {
    let (dir, vault, _) = workspace();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    for i in 0..2100 {
        std::fs::write(root.join(format!("a/f{i:04}.ark")), "").unwrap();
    }
    let client = Client::start(&root);
    assert_eq!(client.open(&vault, VAULT), Vec::<Value>::new());
    client.stop();
}

#[test]
fn a_file_outside_a_workspace_folder_loads_only_its_imports() {
    let (dir, vault, _) = workspace();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("deep")).unwrap();
    std::fs::write(root.join("deep/other.ark"), RULES).unwrap();
    let mut client = Client::start_with(json!({ "capabilities": {} }));
    assert_eq!(client.open(&vault, VAULT), Vec::<Value>::new());
    assert_eq!(import_paths(&mut client, &vault), ["lib/rules.ark"]);
    client.stop();
}

/// Whether every `range` in `value` lies inside the text of the `uri` that encloses it.
fn ranges_inside(value: &Value, text: &str, open: (&Url, &str)) -> bool {
    let text = match value.get("uri").and_then(|uri| uri.as_str()) {
        Some(uri) if uri == open.0.as_str() => open.1.to_string(),
        Some(uri) => {
            let path = Url::parse(uri).unwrap().to_file_path().unwrap();
            std::fs::read_to_string(path).unwrap()
        }
        None => text.to_string(),
    };
    let inside = |position: &Value| {
        let lines: Vec<&str> = text.split('\n').collect();
        let line = position["line"].as_u64().unwrap() as usize;
        let character = position["character"].as_u64().unwrap();
        line < lines.len()
            && character <= lines[line].trim_end_matches('\r').encode_utf16().count() as u64
    };
    let range_ok = value.get("range").is_none_or(|range| {
        let at = |p: &Value| (p["line"].as_u64(), p["character"].as_u64());
        inside(&range["start"]) && inside(&range["end"]) && at(&range["start"]) <= at(&range["end"])
    });
    let children: Box<dyn Iterator<Item = &Value>> = match value {
        Value::Array(items) => Box::new(items.iter()),
        Value::Object(fields) => {
            Box::new(fields.iter().filter(|(k, _)| *k != "range").map(|(_, v)| v))
        }
        _ => Box::new(std::iter::empty()),
    };
    range_ok
        && children
            .into_iter()
            .all(|child| ranges_inside(child, &text, open))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_position_is_answered_inside_the_document(
        chunks in prop::collection::vec(prop_oneof![
            Just(VAULT.to_string()),
            prop::sample::select(vec![
                "ł", "żó", "🐴", "😀", "\r\n", "\n", " ", "owner", "Rules.", "Rules", "exit",
                "import \"lib/rules.ark\";", "(", ")", "{", "}", ";", "\"", ".", "// ",
            ]).prop_map(str::to_string),
            "\\PC{0,4}",
        ], 0..12),
        positions in prop::collection::vec((0u32..40, 0u32..120), 1..6),
    ) {
        let text = chunks.concat();
        let (dir, vault, _) = workspace();
        let mut client = Client::start(&dir.path().canonicalize().unwrap());
        client.notify(
            "textDocument/didOpen",
            json!({ "textDocument": { "uri": vault, "languageId": "arkade", "version": 1, "text": text } }),
        );
        for (line, character) in positions {
            let at = json!({ "textDocument": { "uri": vault }, "position": { "line": line, "character": character } });
            let mut references = at.clone();
            references["context"] = json!({ "includeDeclaration": true });
            for (method, params) in [
                ("textDocument/completion", at.clone()),
                ("textDocument/hover", at.clone()),
                ("textDocument/definition", at.clone()),
                ("textDocument/references", references),
                ("textDocument/documentHighlight", at.clone()),
            ] {
                let result = client.request(method, params);
                prop_assert!(ranges_inside(&result, &text, (&vault, &text)), "{method} {line}:{character} {result}");
            }
        }
        client.stop();
    }
}

#[test]
fn watched_files_update_importers() {
    let (dir, vault, rules) = workspace();
    let root = dir.path().canonicalize().unwrap();
    let watching =
        json!({ "workspace": { "didChangeWatchedFiles": { "dynamicRegistration": true } } });
    let client = Client::start_with(
        json!({ "capabilities": watching, "rootUri": Url::from_directory_path(&root).unwrap() }),
    );
    let Message::Request(register) = client.connection.receiver.recv().unwrap() else {
        panic!("expected the watcher registration");
    };
    assert_eq!(register.method, "client/registerCapability");
    assert_eq!(client.open(&vault, VAULT), Vec::<Value>::new());

    std::fs::write(
        root.join("lib/rules.ark"),
        RULES.replace("tx.inputs[0].value", "missing"),
    )
    .unwrap();
    let changes = json!({ "changes": [{ "uri": rules, "type": 2 }] });
    client.notify("workspace/didChangeWatchedFiles", changes);
    assert_eq!(client.diagnostics(&vault).len(), 1);
    client.stop();
}

#[test]
fn a_save_rescans_its_directory_without_a_watcher() {
    let (dir, vault, rules) = workspace();
    let root = dir.path().canonicalize().unwrap();
    let client = Client::start(&root);
    assert_eq!(client.open(&vault, VAULT), Vec::<Value>::new());
    std::fs::write(
        root.join("lib/rules.ark"),
        RULES.replace("tx.inputs[0].value", "missing"),
    )
    .unwrap();
    client.notify(
        "textDocument/didSave",
        json!({ "textDocument": { "uri": rules } }),
    );
    assert_eq!(client.diagnostics(&vault).len(), 1);
    client.stop();
}

#[test]
fn closing_a_library_falls_back_to_its_file() {
    let (dir, vault, rules) = workspace();
    let client = Client::start(&dir.path().canonicalize().unwrap());
    client.open(&vault, VAULT);
    client.open(&rules, &RULES.replace("tx.inputs[0].value", "missing"));
    assert_eq!(client.diagnostics(&vault).len(), 1);
    client.notify(
        "textDocument/didClose",
        json!({ "textDocument": { "uri": rules } }),
    );
    assert_eq!(client.diagnostics(&vault), Vec::<Value>::new());
    client.stop();
}

#[test]
fn an_edit_republishes_only_the_documents_it_reaches() {
    let (dir, vault, rules) = workspace();
    let root = dir.path().canonicalize().unwrap();
    let other = Url::from_file_path(root.join("other.ark")).unwrap();
    let mut client = Client::start(&root);
    client.open(&rules, RULES);
    client.open(&vault, VAULT);
    client.open(&other, &RULES.replace("Rules", "Other"));
    client.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": rules, "version": 2 }, "contentChanges": [{ "text": format!("{RULES}\n") }] }),
    );
    client.next_id += 1;
    let id = RequestId::from(client.next_id);
    let request = Request::new(id, "shutdown".to_string(), Value::Null);
    client.connection.sender.send(request.into()).unwrap();
    let mut published = Vec::new();
    while let Message::Notification(n) = client.connection.receiver.recv().unwrap() {
        published.push(n.params["uri"].as_str().unwrap().to_string());
    }
    published.sort();
    assert_eq!(published, [rules.to_string(), vault.to_string()]);
    client.notify("exit", Value::Null);
    client.server.join().unwrap().unwrap();
}

#[test]
fn a_burst_of_edits_publishes_once_before_waiting_requests() {
    let (dir, vault, _) = workspace();
    let root = Url::from_directory_path(dir.path().canonicalize().unwrap()).unwrap();
    let (server, connection) = Connection::memory();
    let send = |message: Message| connection.sender.send(message).unwrap();
    let initialize = json!({ "capabilities": {}, "rootUri": root });
    send(Request::new(1.into(), "initialize".into(), initialize).into());
    send(Notification::new("initialized".into(), json!({})).into());
    let document = json!({ "uri": vault, "languageId": "arkade", "version": 1, "text": "broken" });
    send(
        Notification::new(
            "textDocument/didOpen".into(),
            json!({ "textDocument": document }),
        )
        .into(),
    );
    for version in 2..5 {
        let text = if version == 4 { VAULT } else { "still broken" };
        let change = json!({ "textDocument": { "uri": vault, "version": version }, "contentChanges": [{ "text": text }] });
        send(Notification::new("textDocument/didChange".into(), change).into());
    }
    let at =
        json!({ "textDocument": { "uri": vault }, "position": { "line": 5, "character": 33 } });
    send(Request::new(2.into(), "textDocument/hover".into(), at).into());
    let server = std::thread::spawn(move || arkade_lsp::run(server).map_err(|e| e.to_string()));

    let mut received = Vec::new();
    loop {
        match connection.receiver.recv().unwrap() {
            Message::Response(r) if r.id == 2.into() => break,
            Message::Response(_) => {}
            Message::Notification(n) => received.push(n.params["diagnostics"].clone()),
            Message::Request(r) => panic!("{r:?}"),
        }
    }
    assert_eq!(received, [json!([])]);
    send(Request::new(3.into(), "shutdown".into(), Value::Null).into());
    send(Notification::new("exit".into(), Value::Null).into());
    server.join().unwrap().unwrap();
}

#[test]
fn completion_offers_each_file_declaring_a_name() {
    let (dir, vault, _) = workspace();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("vendor")).unwrap();
    std::fs::write(root.join("vendor/rules.ark"), RULES).unwrap();
    let mut client = Client::start(&root);
    let unimported = VAULT.replace("import \"lib/rules.ark\";\n", "");
    client.open(
        &vault,
        &unimported.replace("    Rules.preservesValue();", "    Ru"),
    );
    let complete = |client: &mut Client, character: u32| {
        client.request(
            "textDocument/completion",
            json!({ "textDocument": { "uri": vault }, "position": { "line": 3, "character": character } }),
        )
    };
    let details = |items: Value| -> Vec<(String, String)> {
        let items = items.as_array().unwrap().iter();
        let mut details: Vec<_> = items
            .filter(|i| {
                !i["detail"].is_null() && i["detail"].as_str().unwrap().starts_with("import")
            })
            .map(|i| {
                (
                    i["label"].as_str().unwrap().to_string(),
                    i["detail"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        details.sort();
        details
    };
    let from = |file: &str| format!("import from {file}");
    assert_eq!(
        details(complete(&mut client, 6)),
        [
            ("Rules".to_string(), from("lib/rules.ark")),
            ("Rules".to_string(), from("vendor/rules.ark"))
        ]
    );
    client.change(
        &vault,
        &unimported.replace("    Rules.preservesValue();", "    Rules."),
    );
    assert_eq!(
        details(complete(&mut client, 10)),
        [
            ("preservesValue".to_string(), from("lib/rules.ark")),
            ("preservesValue".to_string(), from("vendor/rules.ark"))
        ]
    );
    client.stop();
}

/// Keystroke-to-publish and completion latency over 2500 libraries and 20 open contracts; run
/// with `cargo test --release -p arkade-lsp --test lsp -- --ignored --nocapture`.
#[test]
#[ignore]
fn benchmark_a_large_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("lib")).unwrap();
    for i in 0..2500 {
        let library = format!("library L{i} {{\n  function f{i}() {{\n    require(tx.outputs[0].value >= {i});\n  }}\n}}\n");
        std::fs::write(root.join(format!("lib/l{i}.ark")), library).unwrap();
    }
    let contract = |j: usize, k: usize| {
        format!("import \"lib/l{j}.ark\";\nimport \"lib/l{}.ark\";\n\ncontract C{j}(pubkey owner) {{\n  function spend(signature sig) {{\n    L{j}.f{j}();\n    require(tx.outputs[0].value >= {k});\n    require(checkSig(sig, owner));\n  }}\n}}\n", j + 100)
    };
    let mut client = Client::start(&root);
    let uris: Vec<Url> = (0..20)
        .map(|j| {
            let path = root.join(format!("c{j}.ark"));
            std::fs::write(&path, contract(j, 0)).unwrap();
            Url::from_file_path(path).unwrap()
        })
        .collect();
    for (j, uri) in uris.iter().enumerate() {
        client.open(uri, &contract(j, 0));
    }
    // Answered after every publish so far, which leaves none stale.
    client.request(
        "textDocument/documentSymbol",
        json!({ "textDocument": { "uri": uris[0] } }),
    );
    let median = |mut samples: Vec<f64>| {
        samples.sort_by(f64::total_cmp);
        samples[samples.len() / 2]
    };
    let mut keystrokes = Vec::new();
    for k in 1..=30 {
        let start = std::time::Instant::now();
        let text = match k % 2 {
            0 => contract(3, k),
            _ => contract(3, k).replace("sig, owner", "sig, ownr"),
        };
        let diagnostics = client.change(&uris[3], &text);
        keystrokes.push(start.elapsed().as_secs_f64() * 1e3);
        assert_eq!(diagnostics.len(), k % 2, "{diagnostics:?}");
    }
    let typing = contract(3, 0).replace("    L3.f3();", "    L");
    client.change(&uris[3], &typing);
    let mut completions = Vec::new();
    for _ in 0..30 {
        let start = std::time::Instant::now();
        let items = client.request(
            "textDocument/completion",
            json!({ "textDocument": { "uri": uris[3] }, "position": { "line": 5, "character": 5 } }),
        );
        completions.push(start.elapsed().as_secs_f64() * 1e3);
        let items = items.get("items").unwrap_or(&items).as_array().unwrap();
        assert!(items.iter().any(|i| i["label"] == "L3"));
    }
    let (keystroke, completion) = (median(keystrokes), median(completions));
    println!(
        "keystroke → publish: median {keystroke:.1} ms; completion: median {completion:.1} ms"
    );
    if !cfg!(debug_assertions) {
        assert!(keystroke < 20.0 && completion < 20.0);
    }
    client.stop();
}

#[test]
fn a_transitive_dependency_error_shows_on_the_import_reaching_it() {
    let (dir, vault, _) = workspace();
    let root = dir.path().canonicalize().unwrap();
    let broken = RULES
        .replace("Rules", "Deep")
        .replace("tx.inputs[0].value", "missing");
    std::fs::write(root.join("lib/deep.ark"), broken).unwrap();
    std::fs::write(
        root.join("lib/middle.ark"),
        "import \"deep.ark\";\nlibrary Middle {\n  function f() { require(true); }\n}\n",
    )
    .unwrap();
    let client = Client::start(&root);
    let text = VAULT.replace(
        "import \"lib/rules.ark\";",
        "import \"lib/rules.ark\";\nimport \"lib/middle.ark\";",
    );
    let [import] = client.open(&vault, &text).try_into().unwrap();
    assert_eq!(range(&import), (1, 0, 24));
    assert!(import["message"]
        .as_str()
        .unwrap()
        .starts_with("lib/deep.ark: "));
    let [related] = import["relatedInformation"]
        .as_array()
        .unwrap()
        .clone()
        .try_into()
        .unwrap();
    let deep = Url::from_file_path(root.join("lib/deep.ark")).unwrap();
    assert_eq!(related["location"]["uri"], json!(deep));
    assert_eq!(
        related["location"]["range"]["start"],
        json!({ "line": 2, "character": 35 })
    );
    client.stop();
}

#[test]
fn diagnostics_carry_the_document_version() {
    let (dir, vault, _) = workspace();
    let client = Client::start(&dir.path().canonicalize().unwrap());
    let version = || loop {
        if let Message::Notification(n) = client.connection.receiver.recv().unwrap() {
            return n.params["version"].clone();
        }
    };
    client.notify(
        "textDocument/didOpen",
        json!({ "textDocument": { "uri": vault, "languageId": "arkade", "version": 7, "text": VAULT } }),
    );
    assert_eq!(version(), json!(7));
    client.notify(
        "textDocument/didChange",
        json!({ "textDocument": { "uri": vault, "version": 8 }, "contentChanges": [{ "text": VAULT }] }),
    );
    assert_eq!(version(), json!(8));
    client.stop();
}

#[test]
fn rename_reaches_every_file_that_sees_the_name() {
    let (dir, vault, rules) = workspace();
    let root = dir.path().canonicalize().unwrap();
    let other = VAULT.replace("Vault", "Other");
    std::fs::write(root.join("other.ark"), &other).unwrap();
    let other = Url::from_file_path(root.join("other.ark")).unwrap();
    let mut client = Client::start(&root);
    client.open(&vault, VAULT);
    let at = |line: u32, character: u32| json!({ "textDocument": { "uri": vault }, "position": { "line": line, "character": character } });
    let prepared = client.request("textDocument/prepareRename", at(5, 33));
    assert_eq!(prepared["start"], json!({ "line": 5, "character": 31 }));
    assert_eq!(prepared["end"], json!({ "line": 5, "character": 36 }));

    let rename = |client: &mut Client, line, character, name: &str| {
        let mut params = at(line, character);
        params["newName"] = json!(name);
        client.call("textDocument/rename", params)
    };
    let starts = |edit: &Value, uri: &Url| -> Vec<(u64, u64)> {
        let mut starts: Vec<_> = edit["changes"][uri.as_str()]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["range"]["start"]["line"].as_u64().unwrap(),
                    e["range"]["start"]["character"].as_u64().unwrap(),
                )
            })
            .collect();
        starts.sort();
        starts
    };
    let owner = rename(&mut client, 5, 33, "key").result.unwrap();
    assert_eq!(starts(&owner, &vault), [(2, 22), (5, 31), (10, 31)]);
    assert_eq!(owner["changes"].as_object().unwrap().len(), 1);

    let function = rename(&mut client, 4, 14, "keepsValue").result.unwrap();
    assert_eq!(starts(&function, &vault), [(4, 10)]);
    assert_eq!(starts(&function, &rules), [(1, 11)]);
    assert_eq!(starts(&function, &other), [(4, 10)]);

    for (name, why) in [
        ("exit", "'exit' is already defined there"),
        ("1x", "'1x' is not an identifier"),
        ("tx", "renaming to 'tx' fails: "),
    ] {
        let error = rename(&mut client, 5, 33, name).error.unwrap();
        assert_eq!(error.code, -32803);
        assert!(error.message.starts_with(why), "{}", error.message);
    }
    client.stop();
}
