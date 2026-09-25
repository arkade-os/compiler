use super::*;

/// A declaration offered by editor tooling. `position` is the 1-based line and
/// character column where its name starts; `scope` is the 1-based line range of
/// the enclosing function, and file-level declarations have none.
#[derive(serde::Serialize, Debug, Clone, PartialEq)]
pub(crate) struct Symbol {
    pub name: String,
    pub kind: &'static str,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub symbol_type: Option<String>,
    pub position: (usize, usize),
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<(usize, usize)>,
    /// Source path of a declaration from an imported file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Callable by importers as `Owner.name`.
    #[serde(skip)]
    pub exported: bool,
}

/// Declarations and struct definitions of one source file, read from the parse tree.
pub(crate) fn symbols(source: &str) -> Result<(Vec<Symbol>, Vec<StructDefinition>), String> {
    let main = ArkadeParser::parse(Rule::main, source)
        .map_err(|e| format!("Parse error: {e}"))?
        .next()
        .expect("main");
    let mut symbols = Vec::new();
    let mut structs = Vec::new();
    for item in main.into_inner() {
        match item.as_rule() {
            Rule::struct_definition => {
                let name = item
                    .clone()
                    .into_inner()
                    .next()
                    .ok_or("Missing struct name")?;
                symbols.push(symbol(&name, "struct", None, None));
                structs.push(parse_struct_definition(item)?);
            }
            Rule::contract | Rule::library => {
                let kind = if item.as_rule() == Rule::contract {
                    "contract"
                } else {
                    "library"
                };
                let mut inner = item.into_inner();
                let name = inner.next().ok_or("Missing contract name")?;
                symbols.push(symbol(&name, kind, None, None));
                for member in inner {
                    match member.as_rule() {
                        Rule::param_list => {
                            for parameter in member.into_inner() {
                                symbols.push(typed(parameter, "parameter", None)?);
                            }
                        }
                        Rule::const_decl => {
                            let mut decl = member
                                .into_inner()
                                .filter(|p| p.as_rule() != Rule::const_keyword);
                            let const_type =
                                parse_data_type(decl.next().ok_or("Missing constant type")?);
                            let name = decl.next().ok_or("Missing constant name")?;
                            symbols.push(symbol(&name, "constant", Some(const_type), None));
                        }
                        Rule::function => {
                            function_symbols(member, kind == "library", &mut symbols)?
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok((symbols, structs))
}

fn symbol(
    name: &Pair<Rule>,
    kind: &'static str,
    symbol_type: Option<String>,
    scope: Option<(usize, usize)>,
) -> Symbol {
    Symbol {
        name: name.as_str().to_string(),
        kind,
        symbol_type,
        position: name.as_span().start_pos().line_col(),
        scope,
        file: None,
        exported: false,
    }
}

/// A `parameter` or `variable_declaration`: a data type followed by a name.
fn typed(
    pair: Pair<Rule>,
    kind: &'static str,
    scope: Option<(usize, usize)>,
) -> Result<Symbol, String> {
    let mut inner = pair.into_inner();
    let declared_type = parse_data_type(inner.next().ok_or("Missing type")?);
    let name = inner.next().ok_or("Missing name")?;
    Ok(symbol(&name, kind, Some(declared_type), scope))
}

// ponytail: locals are scoped to their whole function, not their block; track block spans if shadowing across blocks matters.
fn function_symbols(
    function: Pair<Rule>,
    in_library: bool,
    symbols: &mut Vec<Symbol>,
) -> Result<(), String> {
    let span = function.as_span();
    let scope = Some((span.start_pos().line_col().0, span.end_pos().line_col().0));
    let mut header = function.clone().into_inner().peekable();
    let visibility = header
        .next_if(|p| p.as_rule() == Rule::function_visibility)
        .map_or("public", |p| p.as_str());
    let name = header.next().ok_or("Missing function name")?;
    header.next();
    let return_type = header
        .next()
        .filter(|p| p.as_rule() == Rule::data_type)
        .map(parse_data_type);
    symbols.push(Symbol {
        exported: (in_library || visibility == "static") && visibility != "private",
        ..symbol(&name, "function", return_type, None)
    });

    for pair in function.into_inner().flatten() {
        let mut inner = pair.clone().into_inner();
        match pair.as_rule() {
            Rule::parameter => symbols.push(typed(pair, "parameter", scope)?),
            Rule::variable_declaration => symbols.push(typed(pair, "variable", scope)?),
            Rule::let_binding => {
                let name = inner.next().ok_or("Missing let name")?;
                // Group properties (`group.sumInputs`) resolve on bindings of `tx.assetGroups.find(...)`.
                let group = inner.next().map(parse_general_expression);
                let symbol_type =
                    matches!(group, Some(Ok(crate::models::Expression::GroupFind { .. })))
                        .then(|| "assetGroup".to_string());
                symbols.push(symbol(&name, "variable", symbol_type, scope));
            }
            Rule::for_in_stmt => {
                let index = inner.next().ok_or("Missing loop index")?;
                let item = inner.next().ok_or("Missing loop item")?;
                let iterable = inner.next().ok_or("Missing loop iterable")?.as_str().trim();
                let element = symbols
                    .iter()
                    .rev()
                    .find(|s| s.name == iterable && (s.scope.is_none() || s.scope == scope))
                    .and_then(|s| s.symbol_type.as_deref()?.strip_suffix(']')?.split_once('['))
                    .map(|(element, _)| element.to_string());
                symbols.push(symbol(&index, "variable", Some("int".to_string()), scope));
                symbols.push(symbol(&item, "variable", element, scope));
            }
            _ => {}
        }
    }
    Ok(())
}
