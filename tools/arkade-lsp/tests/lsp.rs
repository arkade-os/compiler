use std::path::Path;
use std::thread::JoinHandle;

use lsp_server::{Connection, Message, Notification, Request, RequestId};
use lsp_types::Url;
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
        let (server, connection) = Connection::memory();
        let server = std::thread::spawn(move || arkade_lsp::run(server).map_err(|e| e.to_string()));
        let mut client = Client {
            connection,
            server,
            next_id: 0,
        };
        let root = Url::from_directory_path(root).unwrap();
        client.request("initialize", json!({ "capabilities": {}, "rootUri": root }));
        client.notify("initialized", json!({}));
        client
    }

    fn notify(&self, method: &str, params: Value) {
        let notification = Notification::new(method.to_string(), params);
        self.connection.sender.send(notification.into()).unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = RequestId::from(self.next_id);
        let request = Request::new(id.clone(), method.to_string(), params);
        self.connection.sender.send(request.into()).unwrap();
        loop {
            if let Message::Response(response) = self.connection.receiver.recv().unwrap() {
                assert_eq!(response.id, id);
                assert!(response.error.is_none(), "{:?}", response.error);
                return response.result.unwrap_or(Value::Null);
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
        ["Rules", "Vault", "exit", "owner", "ownerSig", "spend"]
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
