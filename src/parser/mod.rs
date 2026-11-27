use std::ops::Range;
use std::sync::Mutex;
use std::{array, iter, mem};

use pest::error::Error as PestError;
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;

use crate::diagnostics::{CompileError, Diagnostic, Span};
use crate::models::{
    ArraySize, AssignmentTarget, Attribute, AttributeArg, Constant, Contract, ExprKind, Expression,
    Function, LocatedStatement, NamedTapscript, Parameter, Statement, StructDefinition, TypeName,
};
use crate::{builtins, compiler};

/// Pest parser generated from grammar.pest
#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct ArkadeParser;

mod crypto;
mod expr;
mod introspection;
mod tapscript;

pub(crate) use expr::reserved_function_signature;

#[cfg(test)]
pub fn parse(source: &str) -> Result<Contract, String> {
    build_ast(parse_main(source)?, &[]).map_err(|error| error.to_string())
}

/// Each import's path and the span of its statement.
pub(crate) fn imports(pairs: &Pairs<'_, Rule>) -> Result<Vec<(String, Span)>, String> {
    pairs
        .clone()
        .next()
        .expect("main")
        .into_inner()
        .filter(|p| p.as_rule() == Rule::import_stmt)
        .map(|p| {
            let span = p.as_span().into();
            let path = p.into_inner().next().expect("import path");
            Ok((expr::parse_string_literal(path.as_str())?, span))
        })
        .collect()
}

/// Fail at the leading pragma of `source` when compiler `version` satisfies none of its
/// alternatives. Only `version`'s major.minor.patch counts, so a prerelease satisfies what its
/// release does. The pragma is parsed on its own, so a file written for another compiler fails
/// here rather than on syntax this one does not know; an absent or malformed pragma passes, and
/// the full parse reports a malformed one.
pub(crate) fn check_pragma(source: &str, version: &str) -> Result<(), CompileError> {
    let Ok(mut head) = ArkadeParser::parse(Rule::pragma_head, source) else {
        return Ok(());
    };
    let head = head.next().expect("pragma head");
    let pragma = head.into_inner().next().expect("pragma");
    let current = version_numbers(version);
    let mut satisfied = false;
    let mut alternatives = Vec::new();
    for range in pragma
        .clone()
        .into_inner()
        .filter(|p| p.as_rule() == Rule::pragma_range)
    {
        let mut all = true;
        let mut constraints = Vec::new();
        for constraint in range.into_inner() {
            let operator = [">=", "<=", ">", "<", "=", "^", "~"]
                .into_iter()
                .find(|operator| constraint.as_str().starts_with(operator))
                .unwrap_or("");
            let wanted = constraint
                .into_inner()
                .next()
                .expect("pragma version")
                .as_str();
            all &= satisfies(operator, version_numbers(wanted), current);
            constraints.push(format!("{operator}{wanted}"));
        }
        satisfied |= all;
        alternatives.push(constraints.join(" "));
    }
    if satisfied {
        return Ok(());
    }
    Err(CompileError::from(format!(
        "pragma requires arkade {}, but this compiler is version {version}",
        alternatives.join(" || ")
    ))
    .at(pragma.as_span().into()))
}

/// The major, minor and patch numbers that start `version`.
fn version_numbers(version: &str) -> [u64; 3] {
    // A component beyond u64 saturates; the compiler's own never does, so comparisons stay exact.
    let mut parts = version
        .split(['.', '-', '+'])
        .map(|part| part.parse().unwrap_or(u64::MAX));
    array::from_fn(|_| parts.next().expect("three version components"))
}

/// Whether `version` satisfies `operator` `wanted`, with npm's caret and tilde ranges.
fn satisfies(operator: &str, wanted: [u64; 3], version: [u64; 3]) -> bool {
    match operator {
        ">" => version > wanted,
        ">=" => version >= wanted,
        "<" => version < wanted,
        "<=" => version <= wanted,
        // `^` keeps the first nonzero component, so `^0.0.x` is exact; `~` keeps major.minor.
        "^" if wanted[0] > 0 => version >= wanted && version[0] == wanted[0],
        "^" if wanted[1] > 0 => version >= wanted && version[..2] == wanted[..2],
        "~" => version >= wanted && version[..2] == wanted[..2],
        _ => version == wanted,
    }
}

/// Parse a source file, naming expected tokens in source terms instead of grammar rules.
#[cfg(test)]
pub(crate) fn parse_main(source: &str) -> Result<Pairs<'_, Rule>, String> {
    try_parse(source).map_err(|e| format!("Parse error: {e}"))
}

/// Rewrite a pest error in source-language terms: report the farthest position
/// reached, quote the closing tokens expected there, and name rules in plain words.
fn readable_error(error: PestError<Rule>, source: &str) -> PestError<Rule> {
    use pest::error::{Error, ErrorVariant, InputLocation};
    let Some(attempts) = error.parse_attempts() else {
        return error;
    };
    // Literal tokens only; `a..z` style entries are character ranges.
    let tokens: Vec<String> = attempts
        .expected_tokens()
        .iter()
        .map(ToString::to_string)
        .filter(|t| !t.trim().is_empty() && t != "//" && t != "/*" && !t.contains(".."))
        .map(|t| format!("'{t}'"))
        .collect();
    let mut expected: Vec<String> = tokens
        .iter()
        .filter(|t| ["';'", "')'", "'}'", "']'", "','"].contains(&t.as_str()))
        .cloned()
        .collect();
    // Pest's rule positives can point at an earlier position than the attempts.
    if let ErrorVariant::ParsingError { positives, .. } = &error.variant {
        if error.location == InputLocation::Pos(attempts.max_position) {
            for term in positives.iter().filter_map(rule_term) {
                if !expected.contains(&term) {
                    expected.push(term);
                }
            }
        }
    }
    // A block comment left open fails where the file ends, where pest may not name `*/`.
    let unterminated =
        unterminated_comment(source).filter(|_| attempts.max_position == source.len());
    if unterminated.is_some() {
        expected = vec!["'*/'".to_string()];
    } else if expected.is_empty() {
        expected = tokens;
    }
    let message = match expected.split_last() {
        None => "unexpected input".to_string(),
        Some((last, [])) => format!("expected {last}"),
        Some((last, rest)) => format!("expected {} or {last}", rest.join(", ")),
    };
    let closing = ["';'", "')'", "'}'", "']'", "','", "an operator"];
    let mut at = attempts.max_position;
    if let Some(open) = unterminated {
        at = open;
    } else if let Some((word, start, end)) = lone_word(source, at) {
        let message = format!("`{word}` on its own is not a statement");
        return match (
            pest::Position::new(source, start),
            pest::Position::new(source, end),
        ) {
            (Some(start), Some(end)) => {
                Error::new_from_span(ErrorVariant::CustomError { message }, start.span(&end))
            }
            _ => error,
        };
    }
    if !expected.is_empty() && expected.iter().all(|t| closing.contains(&t.as_str())) {
        at = missing_at(source, at);
    }
    match pest::Position::new(source, at) {
        Some(pos) => Error::new_from_pos(ErrorVariant::CustomError { message }, pos),
        None => error,
    }
}

/// Where a token missing before `at` belongs: on the last character of the code before it, when a
/// line break separates them, since the token ends that line. Otherwise `at` itself.
fn missing_at(source: &str, at: usize) -> usize {
    let end = code_end(source, at);
    match source[..end].char_indices().next_back() {
        Some((last, _)) if source[end..at].contains('\n') => last,
        _ => at,
    }
}

/// `text` without the whitespace and comments that end it.
pub(crate) fn trim_trivia_end(text: &str) -> &str {
    &text[..code_end(text, text.len())]
}

/// The end of the code before `at`, past whitespace and comments.
fn code_end(source: &str, at: usize) -> usize {
    code(&source[..at]).last().map_or(0, |code| code.end)
}

/// `text` without the whitespace and comments the grammar allows between terms.
pub(crate) fn without_trivia(text: &str) -> String {
    code(text).map(|code| &text[code]).collect()
}

/// The byte ranges of `source` that are code: each character outside comments, string literal
/// contents and escapes included, other than whitespace outside string literals.
fn code(source: &str) -> impl Iterator<Item = Range<usize>> + '_ {
    let (mut i, mut quoted) = (0, false);
    iter::from_fn(move || loop {
        let c = source[i..].chars().next()?;
        if let Some(comment) = comment_len(&source[i..]).filter(|_| !quoted) {
            i += comment;
            continue;
        }
        let start = i;
        i += c.len_utf8();
        match c {
            '\\' if quoted => i += source[i..].chars().next().map_or(0, char::len_utf8),
            '"' => quoted = !quoted,
            // A string literal cannot span lines.
            '\n' => quoted = false,
            _ => {}
        }
        if quoted || !c.is_whitespace() {
            return Some(start..i);
        }
    })
}

/// Where the block comment that `source` ends inside opens, if it ends inside one.
fn unterminated_comment(source: &str) -> Option<usize> {
    let mut at = code_end(source, source.len());
    loop {
        at = source.len() - source[at..].trim_start().len();
        let comment = &source[at..at + comment_len(&source[at..])?];
        if comment.starts_with("/*") && !comment[2..].ends_with("*/") {
            return Some(at);
        }
        at += comment.len();
    }
}

/// The length of the `//` or `/* */` comment that starts `text`; an unterminated block comment
/// runs to the end of `text`.
pub(crate) fn comment_len(text: &str) -> Option<usize> {
    if text.starts_with("//") {
        return Some(text.find('\n').unwrap_or(text.len()));
    }
    let body = text.strip_prefix("/*")?;
    Some(body.find("*/").map_or(text.len(), |end| end + 4))
}

/// A single word that starts a statement and ends the code before `at`, as in `dasd` left on its
/// own line: the word and its byte range.
fn lone_word(source: &str, at: usize) -> Option<(&str, usize, usize)> {
    let end = code_end(source, at);
    let start = source[..end]
        .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_')
        .len();
    let word = &source[start..end];
    let starts_statement = source[..code_end(source, start)].ends_with([';', '{', '}']);
    let keyword = ["return", "else", "require", "let", "if", "for"].contains(&word);
    // A word the error splits, as at the `é` of `héllo`, is not one on its own.
    let split = source[end..].starts_with(char::is_alphanumeric);
    let lone = word.starts_with(|c: char| c.is_ascii_alphabetic())
        && starts_statement
        && !keyword
        && !split;
    lone.then_some((word, start, end))
}

fn rule_term(rule: &Rule) -> Option<String> {
    let term = match rule {
        Rule::main => return None,
        Rule::EOI => "end of file",
        Rule::comparison_operator
        | Rule::add_op
        | Rule::sub_op
        | Rule::not_op
        | Rule::and_op
        | Rule::or_op
        | Rule::bit_and_op
        | Rule::bit_or_op
        | Rule::bit_xor_op
        | Rule::shift_op
        | Rule::invert_op
        | Rule::mul_op
        | Rule::div_op
        | Rule::rem_op
        // Field, index and call suffixes are postfix operators.
        | Rule::binding_suffix
        | Rule::postfix
        | Rule::call_args => "an operator",
        Rule::identifier => "a name",
        Rule::const_keyword => "a constant",
        Rule::function_visibility | Rule::function => "a function",
        Rule::data_type => "a type",
        Rule::block => "a block",
        Rule::attribute => "an attribute",
        Rule::attribute_name => "a name",
        Rule::unary_expr
        | Rule::primary_expr
        | Rule::parenthesized_expr
        | Rule::general_expression
        | Rule::empty_list => "an expression",
        Rule::number_literal => "a number",
        Rule::string_literal => "a string",
        // ponytail: unmapped rules fall back to their grammar name with spaces, and a keyword
        // rule to its quoted keyword; map any that show up confusingly in real errors.
        other => {
            let name = format!("{other:?}");
            return Some(match name.strip_suffix("_keyword") {
                Some(keyword) => format!("'{keyword}'"),
                None => name.replace('_', " "),
            });
        }
    };
    Some(term.to_string())
}

/// The raw pest parse, with the error already rewritten in source-language
/// terms by `readable_error`. Used where the byte position of a failure
/// matters, e.g. `check()`, instead of `parse_main`'s rendered string.
pub(crate) fn try_parse(source: &str) -> Result<Pairs<'_, Rule>, PestError<Rule>> {
    // Tracking parse attempts, which only the error message needs, slows every parse, so a
    // failed parse is repeated with it unless it was already on, which an error with attempts
    // shows. The flag is global: only the lock holder turns it on, and back off.
    static DETAILED: Mutex<()> = Mutex::new(());
    ArkadeParser::parse(Rule::main, source)
        .or_else(|error| {
            if error.parse_attempts().is_some() {
                return Err(error);
            }
            let _detailed = DETAILED
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pest::set_error_detail(true);
            let detailed = ArkadeParser::parse(Rule::main, source);
            pest::set_error_detail(false);
            detailed
        })
        .map_err(|e| readable_error(e, source))
}

pub(crate) fn parse_error_diagnostic(
    error: &PestError<Rule>,
    file: &str,
    source: &str,
) -> Diagnostic {
    use pest::error::InputLocation;
    let (start, end) = match error.location {
        // A point location still needs a non-empty span to underline: cover the
        // character there, or at end of input the last non-whitespace one.
        InputLocation::Pos(pos) => match source[pos..].chars().next() {
            Some(c) => (pos, pos + c.len_utf8()),
            None => {
                let text = source[..pos].trim_end();
                let start = text.char_indices().next_back().map_or(0, |(i, _)| i);
                (start, text.len())
            }
        },
        InputLocation::Span((start, end)) => (start, end),
    };
    Diagnostic::error(file, error.variant.message().into_owned()).with_span(Span { start, end })
}

/// Build a Contract AST from parsed Pest pairs
pub(crate) fn build_ast(
    pairs: Pairs<Rule>,
    constants: &[Constant],
) -> Result<Contract, CompileError> {
    let mut contract = Contract {
        name: String::new(),
        span: Default::default(),
        is_library: false,
        structs: Vec::new(),
        parameters: Vec::new(),
        functions: Vec::new(),
        tapscripts: Vec::new(),
        imports: Vec::new(),
        constants: constants.to_vec(),
        declaration: Default::default(),
        attributes: Vec::new(),
    };

    for pair in pairs {
        match pair.as_rule() {
            Rule::main => {
                let mut attributes = Vec::new();
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::attribute => attributes.push(parse_attribute(inner_pair)?),
                        Rule::import_stmt => {
                            // Extract the import path (string literal without quotes)
                            if let Some(path_pair) = inner_pair.into_inner().next() {
                                let path = expr::parse_string_literal(path_pair.as_str())?;
                                contract.imports.push(path);
                            }
                        }
                        Rule::contract | Rule::library => {
                            contract.attributes = mem::take(&mut attributes);
                            parse_contract(&mut contract, inner_pair)?;
                        }
                        Rule::struct_definition => {
                            let span = inner_pair.as_span().into();
                            let definition = parse_struct_definition(inner_pair)
                                .map_err(|error| CompileError::from(error).at(span))?;
                            contract.structs.push(definition);
                        }
                        _ => {}
                    }
                }
            }
            Rule::contract | Rule::library => {
                parse_contract(&mut contract, pair)?;
            }
            _ => {}
        }
    }

    Ok(contract)
}

/// Parse `@name(arg, ...)`.
fn parse_attribute(pair: Pair<Rule>) -> Result<Attribute, String> {
    let span = pair.as_span().into();
    let mut inner = pair.into_inner();
    let name = inner.next().ok_or("Missing attribute name")?;
    let args = inner
        .map(|arg| {
            let span = arg.as_span().into();
            Ok(match arg.as_rule() {
                Rule::string_literal => {
                    AttributeArg::Text(expr::parse_string_literal(arg.as_str())?, span)
                }
                _ => AttributeArg::Name(arg.as_str().to_string(), span),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(Attribute {
        name: name.as_str().to_string(),
        name_span: name.as_span().into(),
        args,
        span,
    })
}

fn parse_struct_definition(pair: Pair<Rule>) -> Result<StructDefinition, String> {
    let mut inner = pair.into_inner();
    let name = inner
        .next()
        .ok_or_else(|| "Missing struct name".to_string())?;
    let span = name.as_span().into();
    let name = name.as_str().to_string();
    let fields = inner
        .map(|field| {
            let mut field = field.into_inner();
            let param_type = parse_data_type(
                field
                    .next()
                    .ok_or_else(|| format!("struct '{name}' field is missing a type"))?,
            );
            let name = field
                .next()
                .ok_or_else(|| format!("struct '{name}' field is missing a name"))?;
            Ok(Parameter {
                name: name.as_str().to_string(),
                param_type,
                span: name.as_span().into(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(StructDefinition { name, fields, span })
}

/// Parse a contract or library definition.
fn parse_contract(contract: &mut Contract, pair: Pair<Rule>) -> Result<(), CompileError> {
    contract.is_library = pair.as_rule() == Rule::library;
    contract.declaration = pair.as_span().into();
    let mut inner_pairs = pair.into_inner().peekable();

    // Contract name (required)
    let name = inner_pairs.next().ok_or("Missing contract name")?;
    contract.name = name.as_str().to_string();
    contract.span = name.as_span().into();

    // Parameters (optional)
    if !contract.is_library {
        if let Some(param_list) = inner_pairs.next() {
            contract.parameters = parse_parameters(param_list)?;
        }
    }

    let constants = inner_pairs
        .clone()
        .filter(|pair| pair.as_rule() == Rule::const_decl)
        .map(|pair| {
            let span = pair.as_span().into();
            parse_const_decl(pair).map_err(|error| CompileError::from(error).at(span))
        })
        .collect::<Result<Vec<_>, _>>()?;
    contract.constants.extend(constants);
    compiler::resolve_constants(contract)?;
    let mut parsing_constants = contract.constants.clone();
    parsing_constants.extend(
        contract
            .constants
            .iter()
            .filter(|c| !c.name.contains('.'))
            .cloned()
            .map(|mut constant| {
                constant.name = format!("{}.{}", contract.name, constant.name);
                constant
            }),
    );

    // Arkade Script and tapscript functions share the `function` rule;
    // a tapscript carries a `tapscript_block` body.
    let mut attributes = Vec::new();
    for func_pair in inner_pairs {
        match func_pair.as_rule() {
            Rule::attribute => {
                attributes.push(parse_attribute(func_pair)?);
                continue;
            }
            Rule::function => {}
            _ => continue,
        }
        let attributes = mem::take(&mut attributes);
        if tapscript::function_pair_is_tapscript(&func_pair) {
            let span = func_pair.as_span().into();
            if contract.is_library {
                let message = "libraries cannot declare tapscript functions";
                return Err(CompileError::from(message).at(span));
            }
            let ts = tapscript::parse_named_tapscript(func_pair, &parsing_constants)
                .map_err(|error| error.at(span))?;
            contract
                .tapscripts
                .push(NamedTapscript { attributes, ..ts });
        } else {
            let func = parse_function(func_pair, &parsing_constants, contract.is_library)?;
            contract.functions.push(Function { attributes, ..func });
        }
    }
    Ok(())
}

fn parse_const_decl(pair: Pair<Rule>) -> Result<Constant, String> {
    let mut inner = pair
        .into_inner()
        .filter(|p| p.as_rule() != Rule::const_keyword);
    let const_type = parse_data_type(inner.next().ok_or("Missing constant type")?);
    let name = inner.next().ok_or("Missing constant name")?;
    let value = expr::parse_general_expression(inner.next().ok_or("Missing constant value")?)?;
    Ok(Constant {
        name: name.as_str().to_string(),
        const_type,
        value,
        span: name.as_span().into(),
    })
}

/// Parse a function definition
fn parse_function(
    pair: Pair<Rule>,
    constants: &[Constant],
    is_library: bool,
) -> Result<Function, CompileError> {
    let declaration = pair.as_span().into();
    let mut inner = pair.into_inner().peekable();
    let modifier = inner.next_if(|p| p.as_rule() == Rule::function_visibility);
    let visibility = modifier.as_ref().map_or("", |p| p.as_str());
    if is_library && visibility == "static" {
        let message =
            "`static` marks a contract's stateless helper; library functions need no modifier";
        let span = modifier.expect("static modifier").as_span().into();
        return Err(CompileError::from(message).at(span));
    }
    let is_static = is_library || visibility == "static";
    let is_private = is_library || !visibility.is_empty();
    let is_exported = is_static && visibility != "private";
    let name = inner.next().ok_or("Missing function name")?;
    let span = Span {
        start: name.as_span().start(),
        end: name.as_span().end(),
    };
    let name = name.as_str().to_string();
    let parameters = parse_parameters(inner.next().ok_or("Missing parameter list")?)?;
    let return_type = if inner.peek().is_some_and(|p| p.as_rule() == Rule::data_type) {
        Some(parse_data_type(inner.next().expect("return type")))
    } else {
        None
    };
    let statements = parse_statements(&name, inner, constants)?;
    Ok(Function {
        name,
        span,
        declaration,
        parameters,
        statements,
        is_private,
        is_static,
        is_exported,
        return_type,
        attributes: Vec::new(),
    })
}

/// Parse a function body or block: statements, each after its own attributes.
fn parse_statements<'a>(
    function_name: &str,
    pairs: impl Iterator<Item = Pair<'a, Rule>>,
    constants: &[Constant],
) -> Result<Vec<LocatedStatement>, CompileError> {
    let mut statements = Vec::new();
    let mut attributes = Vec::new();
    for pair in pairs {
        let span = pair.as_span().into();
        if pair.as_rule() == Rule::attribute {
            attributes.push(parse_attribute(pair).map_err(|e| CompileError::from(e).at(span))?);
            continue;
        }
        let statement = parse_statement(function_name, pair, constants).map_err(|e| e.at(span))?;
        statements.extend(statement.map(|statement| LocatedStatement {
            attributes: mem::take(&mut attributes),
            ..statement
        }));
    }
    Ok(statements)
}

/// Parse a statement in a function body (require, let binding, function call, variable declaration)
fn parse_statement(
    function_name: &str,
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<Option<LocatedStatement>, CompileError> {
    let mut span: Span = pair.as_span().into();
    let mut names = Vec::new();
    let mut branches: Vec<Span> = Vec::new();
    let mut message = None;
    let statement = match pair.as_rule() {
        Rule::require_stmt => {
            let mut inner = pair.into_inner();
            let expr = match inner.next() {
                Some(expr) => expr,
                None => {
                    return Err(format!(
                        "Parse error: Invalid arguments to function {function_name}"
                    )
                    .into())
                }
            };
            let condition = expr::parse_general_expression(expr)?;

            if let Some(text) = inner.next() {
                message = Some(expr::parse_string_literal(text.as_str())?);
            }

            Statement::Require(condition)
        }
        Rule::let_binding => {
            let mut inner = pair.into_inner();
            let name = inner
                .next()
                .ok_or_else(|| "Parse error: Missing variable name in let binding".to_string())?;
            names.push(name.as_span().into());
            let name = name.as_str().to_string();
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value in let binding".to_string())?;
            let value = expr::parse_general_expression(value_pair)?;

            Statement::LetBinding {
                name,
                declared_type: None,
                value,
            }
        }
        Rule::var_assign => {
            let mut inner = pair.into_inner();
            let target = parse_assignment_target(
                inner
                    .next()
                    .ok_or_else(|| "Parse error: Missing assignment target".to_string())?,
            )?;
            let value_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing value in assignment".to_string())?;
            let value = expr::parse_general_expression(value_pair)?;

            Statement::VarAssign { target, value }
        }
        Rule::if_stmt => {
            let mut inner = pair.into_inner();
            let condition_pair = inner
                .next()
                .ok_or_else(|| "Parse error: Missing condition in if statement".to_string())?;
            let condition = expr::parse_general_expression(condition_pair)?;

            let then_block = inner
                .next()
                .ok_or_else(|| "Parse error: Missing then block in if statement".to_string())?;
            branches.push(then_block.as_span().into());
            let then_body = parse_block(function_name, then_block, constants)?;

            let else_body =
                if let Some(else_block) = inner.find(|p| p.as_rule() != Rule::else_keyword) {
                    branches.push(else_block.as_span().into());
                    Some(match else_block.as_rule() {
                        Rule::if_stmt => {
                            parse_statements(function_name, iter::once(else_block), constants)?
                        }
                        _ => parse_block(function_name, else_block, constants)?,
                    })
                } else {
                    // The pair also takes the whitespace and comments before where an `else` would be.
                    span.end = branches[0].end;
                    None
                };

            Statement::IfElse {
                condition,
                then_body,
                else_body,
            }
        }
        Rule::for_stmt => {
            let loop_statement = pair
                .into_inner()
                .next()
                .ok_or_else(|| "Parse error: Missing for loop".to_string())?;
            let loop_rule = loop_statement.as_rule();
            let mut inner = loop_statement.into_inner();
            match loop_rule {
                Rule::for_in_stmt => {
                    let index_var = inner.next().ok_or_else(|| {
                        "Parse error: Missing index variable in for loop".to_string()
                    })?;
                    let value_var = inner.next().ok_or_else(|| {
                        "Parse error: Missing value variable in for loop".to_string()
                    })?;
                    names.extend([index_var.as_span(), value_var.as_span()].map(Span::from));
                    let (index_var, value_var) = (
                        index_var.as_str().to_string(),
                        value_var.as_str().to_string(),
                    );
                    let iterable =
                        expr::parse_general_expression(inner.next().ok_or_else(|| {
                            "Parse error: Missing iterable in for loop".to_string()
                        })?)?;
                    let body = parse_block(
                        function_name,
                        inner
                            .next()
                            .ok_or_else(|| "Parse error: Missing body in for loop".to_string())?,
                        constants,
                    )?;
                    Statement::ForIn {
                        index_var,
                        value_var,
                        iterable,
                        body,
                    }
                }
                Rule::for_count_stmt => {
                    let count =
                        expr::parse_general_expression(inner.next().ok_or_else(|| {
                            "Parse error: Missing count in for loop".to_string()
                        })?)?;
                    let body = parse_block(
                        function_name,
                        inner
                            .next()
                            .ok_or_else(|| "Parse error: Missing body in for loop".to_string())?,
                        constants,
                    )?;
                    Statement::ForCount { count, body }
                }
                Rule::for_range_stmt => {
                    let [index_var, range, body] = <[_; 3]>::try_from(inner.collect::<Vec<_>>())
                        .map_err(|_| "a range binds one loop variable, as in `for (i) in 0..N`")?;
                    if range.as_rule() != Rule::loop_range {
                        return Err(
                            "one loop variable iterates a range, as in `for (i) in 0..N`; \
                             an array takes two, as in `for (i, x) in items`"
                                .into(),
                        );
                    }
                    names.push(index_var.as_span().into());
                    let mut bounds = range.into_inner();
                    let (Some(start), Some(end)) = (bounds.next(), bounds.next()) else {
                        return Err("Parse error: Invalid loop range".into());
                    };
                    Statement::ForRange {
                        index_var: index_var.as_str().to_string(),
                        start: Box::new(expr::parse_general_expression(start)?),
                        end: Box::new(expr::parse_general_expression(end)?),
                        body: parse_block(function_name, body, constants)?,
                    }
                }
                _ => return Err("Parse error: Invalid for loop".into()),
            }
        }
        Rule::function_call_stmt => {
            let mut inner = pair.into_inner();
            let mut name = Vec::new();
            let args = loop {
                let part = inner.next().ok_or("Missing call arguments")?;
                if part.as_rule() == Rule::call_args {
                    break part;
                }
                name.push(part.as_str());
            };
            let name = name.join(".");
            if name == "this.tunnel" || builtins::find(&name).is_some() {
                return Err(CompileError::from(format!(
                    "`{name}(...)` cannot be a statement; use it inside require()"
                )));
            }
            let span = Span {
                start: span.start,
                end: args.as_span().end(),
            };
            Statement::Call(expr::parse_call(name, args.into_inner().collect(), span)?)
        }
        Rule::return_stmt => {
            let value = pair
                .into_inner()
                .nth(1)
                .map(expr::parse_general_expression)
                .transpose()?;
            Statement::Return(value)
        }
        Rule::variable_declaration => {
            let mut inner = pair.into_inner();
            let declared_type = parse_data_type(
                inner
                    .next()
                    .ok_or_else(|| "Parse error: Missing variable type".to_string())?,
            );
            let name = inner
                .next()
                .ok_or_else(|| "Parse error: Missing variable name".to_string())?;
            names.push(name.as_span().into());
            let name = name.as_str().to_string();
            match inner.next() {
                Some(value) => Statement::LetBinding {
                    name,
                    declared_type: Some(declared_type),
                    value: expr::parse_general_expression(value)?,
                },
                None => Statement::Declaration {
                    name,
                    declared_type,
                },
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(LocatedStatement {
        span,
        names,
        branches,
        message,
        statement,
        attributes: Vec::new(),
    }))
}

fn parse_assignment_target(pair: Pair<Rule>) -> Result<AssignmentTarget, String> {
    Ok(match expr::parse_property_access(pair)? {
        Expression {
            kind: ExprKind::Name(path),
            ..
        } => AssignmentTarget::Binding(path),
        Expression {
            kind: ExprKind::ArrayIndex { array, index },
            ..
        } => AssignmentTarget::ArrayIndex { array, index },
        value => AssignmentTarget::Access(Box::new(value)),
    })
}

// ─── Expression Parsing ────────────────────────────────────────────────────────

// Parse a block of statements
fn parse_block(
    function_name: &str,
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<Vec<LocatedStatement>, CompileError> {
    parse_statements(function_name, pair.into_inner(), constants)
}

pub(crate) fn parse_data_type(type_pair: Pair<Rule>) -> TypeName {
    let text = type_pair.as_str().trim().to_string();
    let mut inner = type_pair.into_inner();
    let Some(base) = inner.next() else {
        return TypeName::Named(text);
    };
    // `T[a][b]` holds `a` elements of `T[b]`, so the last size is the innermost.
    inner.rfold(
        TypeName::Named(base.as_str().to_string()),
        |element, size| TypeName::Array(Box::new(element), ArraySize::parse(size.as_str())),
    )
}

/// Parse parameter list from contracts or functions
pub(crate) fn parse_parameters(params: Pair<Rule>) -> Result<Vec<Parameter>, String> {
    let mut parameters = Vec::new();
    for param_pair in params.into_inner() {
        if param_pair.as_rule() == Rule::parameter {
            let mut param_inner = param_pair.into_inner();
            let param_type = match param_inner.next() {
                Some(type_pair) => parse_data_type(type_pair),
                None => return Err("Parameter is missing data type".to_string()),
            };
            let Some(name) = param_inner.next() else {
                return Err("Missing parameter name after data type".to_string());
            };
            parameters.push(Parameter {
                name: name.as_str().to_string(),
                param_type,
                span: name.as_span().into(),
            });
        }
    }
    Ok(parameters)
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::parse;
    use crate::models::{
        self, AssignmentTarget, Attribute, AttributeArg, ExprKind, Expression, Function, Statement,
    };
    use crate::operators::UnaryOperator;
    use crate::properties::TxProperty;

    #[test]
    fn transaction_member_forms_parse_by_rule() {
        let value = |expression: &str| {
            let source = format!("contract C() {{ function spend(bytes32 t, int g) {{ let v = {expression}; require(v == v); }} }}");
            match parse(&source)
                .map(|contract| contract.functions[0].statements[0].statement.clone())
            {
                Ok(Statement::LetBinding { value, .. }) => Ok(value.kind),
                Ok(other) => panic!("{other:?}"),
                Err(error) => Err(error),
            }
        };
        assert!(matches!(
            value("tx.input.current.value"),
            Ok(ExprKind::InputIntrospection { .. })
        ));
        assert!(matches!(
            value("tx.assetGroups.has({ txid: t, gidx: g })"),
            Ok(ExprKind::GroupHas { .. })
        ));
        assert!(matches!(
            value("tx.assetGroups.length"),
            Ok(ExprKind::AssetGroupsLength)
        ));
        assert!(matches!(
            value("tx.assetGroups[g].delta"),
            Ok(ExprKind::GroupProperty { .. })
        ));
        assert!(
            matches!(value("tx.assetGroups"), Ok(ExprKind::Name(path)) if path.key() == "tx.assetGroups")
        );
        assert!(matches!(
            value("tx.version"),
            Ok(ExprKind::TxIntrospection { .. })
        ));
        for misuse in [
            "tx.input.current",
            "tx.input.current.weight",
            "tx.input. /* c */ current",
        ] {
            let error = value(misuse).unwrap_err();
            assert!(
                error.contains("tx.input.current requires one of"),
                "{misuse}: {error}"
            );
        }
    }

    #[test]
    fn member_chains_resolve_after_parsing() {
        let value = |expression: &str| {
            let source = format!(
                "contract C() {{ function spend(AssetGroup g) {{ let v = {expression}; }} }}"
            );
            let statement = parse(&source).map(|c| c.functions[0].statements[0].statement.clone());
            let Ok(Statement::LetBinding { value, .. }) = statement else {
                return Err(format!("{statement:?}"));
            };
            let start = source.find(expression).unwrap();
            assert_eq!(
                (value.span.start, value.span.end),
                (start, start + expression.len())
            );
            Ok(value.kind)
        };
        // A member call resolves by its member: a group's `controlIs`, a `tx` or `this` member.
        assert!(matches!(
            value("g.controlIs(id)"),
            Ok(ExprKind::GroupControlIs { .. })
        ));
        assert!(matches!(
            value("g . controlIs(id)"),
            Ok(ExprKind::GroupControlIs { .. })
        ));
        assert!(matches!(
            value("tx.packet(1)"),
            Ok(ExprKind::PacketInspect {
                presence_only: false,
                ..
            })
        ));
        assert!(matches!(
            value("tx.inputs[0].packet.has(1)"),
            Ok(ExprKind::InputPacketInspect {
                presence_only: true,
                ..
            })
        ));
        assert!(matches!(
            value("tx . outputs [ i ] . assets . lookup ( id , )"),
            Ok(ExprKind::AssetLookup { .. })
        ));
        assert!(matches!(
            value("tx.inputs[0].assets[1]"),
            Ok(ExprKind::AssetAt { property: None, .. })
        ));
        assert!(matches!(
            value("tx.inputs[0].assets[1].amount"),
            Ok(ExprKind::AssetAt {
                property: Some(_),
                ..
            })
        ));
        assert!(matches!(
            value("tx.assetGroups.lookup(id).inputs[0].amount"),
            Ok(ExprKind::GroupIOAccess {
                property: Some(_),
                ..
            })
        ));
        for (count, property) in [
            ("inputs", TxProperty::NumInputs),
            ("outputs", TxProperty::NumOutputs),
        ] {
            assert!(matches!(
                value(&format!("tx.{count}.length")),
                Ok(ExprKind::TxIntrospection { property: p }) if p == property
            ));
        }
        assert!(matches!(
            value("this.tunnel(0, {script: true, value: true, assets: true}, [])"),
            Ok(ExprKind::Tunnel { exceptions, .. }) if exceptions.is_empty()
        ));
        let error = value("this.tunnel(0, ({script: true, value: true, assets: true}))");
        assert!(error
            .unwrap_err()
            .contains("wrong arguments to `this.tunnel`"));
        assert!(matches!(value("bytes32(x)"), Ok(ExprKind::Cast { .. })));
        assert!(matches!(value("int(0x0100)"), Ok(ExprKind::Literal(value)) if value == "256"));
        // Fields after a member apply to its value.
        assert!(matches!(
            value("tx.inputs[0].script.program"),
            Ok(ExprKind::FieldAccess { value, .. }) if matches!(value.kind, ExprKind::InputIntrospection { .. })
        ));
        assert!(matches!(value("this.expiry"), Ok(ExprKind::This(_))));
        assert!(
            matches!(value("xs.length"), Ok(ExprKind::Name(path)) if path.key() == "xs.length")
        );
        assert!(matches!(value("Lib . f(x)"), Ok(ExprKind::Call { name, .. }) if name == "Lib.f"));
        assert!(
            matches!(value("Lib.length(x)"), Ok(ExprKind::Call { name, .. }) if name == "Lib.length")
        );
        // A chain no member spells keeps its spelling, strings included, for validation to report.
        for (chain, path) in [
            ("tx.inputs[0].valueX", "tx.inputs[0].valueX"),
            (
                "tx.assetGroups[0].inputs[0].amountX",
                "tx.assetGroups[0].inputs[0].amountX",
            ),
            (r#"tx.packet("a b", "//x")"#, r#"tx.packet("a b","//x")"#),
        ] {
            assert!(
                matches!(value(chain), Ok(ExprKind::Name(p)) if p.key() == path),
                "{chain}"
            );
        }
        for call in ["a.b.c(x)", "f(x).controlIs(id)", "(Lib).f(x)"] {
            assert!(value(call).unwrap_err().contains("cannot call"), "{call}");
        }
        // A call statement names its function.
        for (call, name) in [
            ("g.controlIs(id)", "g.controlIs"),
            ("Lib . check(x)", "Lib.check"),
        ] {
            let source = format!("contract C() {{ function spend(AssetGroup g) {{ {call}; }} }}");
            let statement = &parse(&source).unwrap().functions[0].statements[0].statement;
            assert!(
                matches!(statement, Statement::Call(value) if matches!(&value.kind, ExprKind::Call { name: n, .. } if n == name)),
                "{call}"
            );
        }
    }

    #[test]
    fn nested_operands_parse_in_linear_time() {
        // Each operand has one parse, so a failure deep inside one is never retried by another.
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let nested = [
                "Lib.f(",
                "size(tx.packet(",
                "this.tunnel(",
                "bytes(",
                "g.controlIs(",
                "(Lib.f(",
            ]
            .map(|open| format!("{}0", open.repeat(24)));
            let closed = format!("{}0{}", "tx.inputs[".repeat(24), "].value".repeat(24));
            for operand in nested.iter().chain([&closed]) {
                let source =
                    format!("contract C() {{ function spend() {{ require({operand} > 0); }} }}");
                let _ = parse(&source);
            }
            sender.send(()).unwrap();
        });
        let parsed = receiver.recv_timeout(Duration::from_secs(10));
        assert!(
            parsed.is_ok(),
            "deeply nested operands did not parse in time"
        );
    }

    #[test]
    fn typed_struct_literals_nest_and_leave_loop_bodies_alone() {
        let source = "contract C() { function spend(int a) {
            let p = Outer { inner: Inner { x: a }, id: { txid: t, gidx: 0 } };
            for (i, x) in items { require(x > i); }
            for (i, x) in Lib.items { require(x > i); }
            for (i, x) in items { y = x; }
            for (i, x) in items {}
            require(f(AssetId { txid: t, gidx: 0 }) == AssetId { txid: t, gidx: 1 });
        } }";
        let contract = parse(source).unwrap();
        let statements = &contract.functions[0].statements;
        let Statement::LetBinding { value, .. } = &statements[0].statement else {
            panic!("{:?}", statements[0]);
        };
        assert!(source[value.span.start..value.span.end].starts_with("Outer {"));
        let ExprKind::StructLiteral {
            name: Some(outer),
            fields,
        } = &value.kind
        else {
            panic!("{value:?}");
        };
        assert_eq!(outer, "Outer");
        assert!(
            matches!(&fields[0].1.kind, ExprKind::StructLiteral { name: Some(name), .. } if name == "Inner")
        );
        assert!(matches!(
            &fields[1].1.kind,
            ExprKind::StructLiteral { name: None, .. }
        ));
        let loops = [("items", 1), ("Lib.items", 1), ("items", 1), ("items", 0)];
        for (statement, (name, length)) in statements[1..5].iter().zip(loops) {
            let Statement::ForIn { iterable, body, .. } = &statement.statement else {
                panic!("{statement:?}");
            };
            assert!(matches!(&iterable.kind, ExprKind::Name(path) if path.key() == name));
            assert_eq!(body.len(), length);
        }
        let Statement::Require(Expression {
            kind: ExprKind::BinaryOp { left, right, .. },
            ..
        }) = &statements[5].statement
        else {
            panic!("{:?}", statements[5]);
        };
        let ExprKind::Call { args, .. } = &left.kind else {
            panic!("{left:?}");
        };
        for literal in [&args[0], &**right] {
            assert!(
                matches!(&literal.kind, ExprKind::StructLiteral { name: Some(name), .. } if name == "AssetId")
            );
        }
    }

    #[test]
    fn typed_declarations_may_omit_initializers() {
        let contract = parse("contract C() { function spend() { int x; int[2] values; x = 7; values = [7, 9]; require(x == values[0]); } }").unwrap();
        let statements = &contract.functions[0].statements;
        assert!(
            matches!(&statements[0].statement, Statement::Declaration { name, declared_type } if name == "x" && declared_type.to_string() == "int")
        );
        assert!(
            matches!(&statements[1].statement, Statement::Declaration { name, declared_type } if name == "values" && declared_type.to_string() == "int[2]")
        );
        assert!(matches!(
            &statements[2].statement,
            Statement::VarAssign { .. }
        ));
        assert!(parse("contract C() { function spend() { let x; } }").is_err());
        assert!(parse("contract C() { const int X; }").is_err());
    }

    #[test]
    fn let_prefix_assignments_are_not_declarations() {
        for name in ["letter", "letValue", "let_value", "let2"] {
            let source = format!(
                "contract C() {{ function spend() {{ int {name}; {name} = 6; let alias = {name}; require(alias == 6); }} }}"
            );
            let contract = parse(&source).unwrap();
            let statements = &contract.functions[0].statements;
            assert!(matches!(
                &statements[1].statement,
                Statement::VarAssign { target: AssignmentTarget::Binding(target), .. }
                    if target.key() == name
            ));
            assert!(matches!(
                &statements[2].statement,
                Statement::LetBinding { name, declared_type: None, .. } if name == "alias"
            ));
            crate::compile(&source).unwrap();
        }
    }

    #[test]
    fn keywords_end_at_a_word_boundary() {
        // One glued keyword per source. The `if`, `for`, `tapscript` and `new` boundaries change no
        // parse: `(` or `{` follows the first three, and a glued `new` call reads as a call.
        for source in [
            "structPoint { int x; } contract C(pubkey pk) { function spend(signature s) { require(checkSig(s, pk)); } }",
            "contractC(pubkey pk) { function spend(signature s) { require(checkSig(s, pk)); } }",
            "contract C(pubkey pk) { functionspend(signature s) { require(checkSig(s, pk)); } }",
            "libraryL { function f() int { return 1; } }",
            "contract C() { private functionf() int { return 1; } function g() { require(true); } }",
            "contract C(pubkey pk, int[2] xs) { function spend(signature s) { require(checkSig(s, pk)); for (i, v) inxs { require(v > 0); } } }",
        ] {
            assert!(parse(source).is_err(), "{source}");
        }

        let source = "struct structure { int index; int inputs; }
            contract contractor(pubkey library_key, structure functional, int[2] inputs) {
                function format(signature s, int newValue) {
                    require(checkSig(s, library_key));
                    int iffy = tapscriptX(newValue);
                    iffy = iffy + functional.index;
                    for (index, input) in inputs { require(input == iffy + index); }
                    require(functional.inputs == tx.inputs.length);
                }
                private function tapscriptX(int index) int { return index; }
            }";
        let contract = parse(source).unwrap();
        assert_eq!(contract.name, "contractor");
        assert_eq!(contract.structs[0].name, "structure");
        let names = |functions: &[Function]| -> Vec<String> {
            functions.iter().map(|f| f.name.clone()).collect()
        };
        assert_eq!(names(&contract.functions), ["format", "tapscriptX"]);
        let statements = &contract.functions[0].statements;
        assert!(matches!(
            &statements[2].statement,
            Statement::VarAssign { target: AssignmentTarget::Binding(target), .. } if target.key() == "iffy"
        ));
        assert!(matches!(
            &statements[3].statement,
            Statement::ForIn { index_var, iterable, .. }
                if index_var == "index" && matches!(&iterable.kind, ExprKind::Name(path) if path.key() == "inputs")
        ));
        crate::compile(source).unwrap();

        // A word that only starts with `tapscript` is a return type.
        let contract = parse("contract C(pubkey o) { function f(signature s) tapscript{ require(checkSig(s, o)); } function g() tapscriptX { require(true); } }").unwrap();
        assert_eq!(contract.tapscripts[0].name, "f");
        let return_type = contract.functions[0].return_type.as_ref().unwrap();
        assert_eq!(return_type.base_name(), "tapscriptX");
    }

    #[test]
    fn an_if_without_else_ends_at_its_block() {
        let source = "contract C() { function spend(int n) {
            if (n > 0) { require(n > 1); }
            // next
            require(n > 2);
        } }";
        let span = parse(source).expect("parses").functions[0].statements[0].span;
        assert_eq!(
            &source[span.start..span.end],
            "if (n > 0) { require(n > 1); }"
        );
    }

    #[test]
    fn ranges_parse_only_as_the_iterable_of_a_single_variable_loop() {
        let source = "contract C() { function spend(int a) {
            for (i) in 0..N { require(a > i); }
            for (i) in a.b..c.d(e) {}
            for (i) in 0 .. Lib.N - 1 {}
            for (i, x) in items {}
            for (N) {}
        } }";
        let statements = &parse(source).unwrap().functions[0].statements;
        let text = |expression: &Expression| &source[expression.span.start..expression.span.end];
        for (statement, expected) in
            statements
                .iter()
                .zip([("0", "N", 1), ("a.b", "c.d(e)", 0), ("0", "Lib.N - 1", 0)])
        {
            let Statement::ForRange {
                index_var,
                start,
                end,
                body,
            } = &statement.statement
            else {
                panic!("{statement:?}");
            };
            assert_eq!(index_var, "i");
            assert_eq!((text(start), text(end), body.len()), expected);
        }
        assert!(matches!(statements[3].statement, Statement::ForIn { .. }));
        assert!(matches!(
            statements[4].statement,
            Statement::ForCount { .. }
        ));
        for (statement, expected) in [
            ("for (i) in items {}", "one loop variable iterates a range"),
            ("for (i, x) in 0..N {}", "a range binds one loop variable"),
            ("let r = 0..N;", "Parse error"),
            ("require(f(0..N));", "Parse error"),
            ("for (i) in (0..N) {}", "Parse error"),
            ("for (i) in 0...N {}", "Parse error"),
            ("for (i) in 0..N..M {}", "Parse error"),
            ("for (i) in 0.. {}", "Parse error"),
            ("for (i) in ..N {}", "Parse error"),
            ("for (i) 0..N {}", "Parse error"),
        ] {
            let source = format!("contract C() {{ function spend() {{ {statement} }} }}");
            let error = parse(&source).unwrap_err();
            assert!(error.contains(expected), "{statement}: {error}");
        }
    }

    #[test]
    fn expression_spans_cover_their_source_and_nest() {
        let source = "contract C(bytes a, bytes32 h, int[2] xs) { function spend(int n) {
            require(sha256(cat(a, a)) == h);
            let total = xs[n] + -n * 2;
            let mask = ~a ^ a;
            let flipped = -~n;
            let grouped = (n) + ((2));
            let prefixed = -!(n);
            let packet = tx.packet(-!(n));
            let sum = tx.assetGroups[n].sumInputs;
            let owned = tx.assetGroups.lookup(id).controlIs(AssetId { txid: h, gidx: n });
            require(total > 0);
        } }";
        let contract = parse(source).expect("parses");
        let text = |e: &Expression| &source[e.span.start..e.span.end];
        fn walk<'a>(e: &'a Expression, out: &mut Vec<&'a Expression>) {
            out.push(e);
            for child in models::child_exprs(e) {
                assert!(
                    e.span.start <= child.span.start && child.span.end <= e.span.end,
                    "{child:?} escapes {e:?}"
                );
                walk(child, out);
            }
        }
        let mut nodes = Vec::new();
        for statement in &contract.functions[0].statements {
            match &statement.statement {
                Statement::Require(value) | Statement::LetBinding { value, .. } => {
                    walk(value, &mut nodes)
                }
                other => panic!("unexpected statement {other:?}"),
            }
        }
        let texts: Vec<&str> = nodes.iter().map(|e| text(e)).collect();
        for expected in [
            "sha256(cat(a, a))",
            "cat(a, a)",
            "h",
            "xs[n] + -n * 2",
            "xs[n]",
            "-n * 2",
            "-n",
            "~a ^ a",
            "~a",
            "-~n",
            "~n",
            "(n) + ((2))",
            "(n)",
            "((2))",
            "-!(n)",
            "!(n)",
            "tx.packet(-!(n))",
            "tx.assetGroups[n].sumInputs",
            "tx.assetGroups.lookup(id).controlIs(AssetId { txid: h, gidx: n })",
            "AssetId { txid: h, gidx: n }",
            "total",
            "0",
        ] {
            assert!(
                texts.contains(&expected),
                "no node spans {expected:?} in {texts:?}"
            );
        }
    }

    #[test]
    fn attributes_attach_to_the_node_after_them() {
        let source = r#"
@allow(unused-parameter, "kept")
contract C(pubkey k, int unused) {
    @deny(self-comparison)
    function f(signature s, int x) {
        if (x > 0) {
            @allow(self-comparison, "a")
            @warn(divide-before-multiply)
            require(x == x);
        }
        require(checkSig(s, k));
    }
    @allow(timelock-without-unit, "raw")
    function t(signature s) tapscript { require(checkSig(s, k)); }
}"#;
        let contract = parse(source).unwrap();
        fn names(attributes: &[Attribute]) -> Vec<&str> {
            attributes.iter().map(|a| a.name.as_str()).collect()
        }
        assert_eq!(names(&contract.attributes), ["allow"]);
        assert_eq!(names(&contract.functions[0].attributes), ["deny"]);
        assert_eq!(names(&contract.tapscripts[0].attributes), ["allow"]);
        let Statement::IfElse { then_body, .. } = &contract.functions[0].statements[0].statement
        else {
            panic!("expected if");
        };
        assert_eq!(names(&then_body[0].attributes), ["allow", "warn"]);
        assert!(matches!(
            &then_body[0].attributes[0].args[..],
            [AttributeArg::Name(lint, _), AttributeArg::Text(reason, _)]
                if lint == "self-comparison" && reason == "a"
        ));
        assert!(contract.functions[0].statements[1].attributes.is_empty());
        for span in [
            then_body[0].span,
            contract.functions[0].declaration,
            contract.declaration,
        ] {
            assert!(!source[span.start..span.end].starts_with('@'));
        }
    }

    #[test]
    fn parses_version_pragmas_without_enforcing_compatibility() {
        for version in [
            "0.1.0",
            "=0.1.0",
            "^0.1.0",
            "~0.1.0",
            ">=0.1.0 <0.2.0",
            ">0.0.0 <=0.1.0",
            "^0.1.0 || >=1.0.0 <2.0.0",
            "99.0.0",
            "^ // constraint\n 0.1.0",
        ] {
            let source = format!("// header\npragma arkade {version}; contract C() {{}}");
            assert_eq!(parse(&source).unwrap().name, "C", "{version}");
        }
    }

    #[test]
    fn rejects_malformed_or_misplaced_pragmas() {
        for header in [
            "pragma arkade;",
            "pragma other ^0.1.0;",
            "pragmaarkade ^0.1.0;",
            "pragma arkade0.1.0;",
            "pragma arkade ^0.1;",
            "pragma arkade 0.1.*;",
            "pragma arkade 0.1.0-beta;",
            "pragma arkade 0.1.0+build;",
            "pragma arkade ^0.1.0",
            "pragma arkade ^01.1.0;",
            "pragma arkade ^0.01.0;",
            "pragma arkade ^0.1.00;",
            "pragma arkade 0.1.00.2.0;",
            "pragma arkade 0.1.0.0;",
            "pragma arkade 0 .1.0;",
            "pragma arkade =>0.1.0;",
            "pragma arkade ^0.1.0 ||;",
            "pragma arkade ^0.1.0; pragma arkade ^0.1.0;",
            "import \"a.ark\"; pragma arkade ^0.1.0;",
            "struct S { int value; } pragma arkade ^0.1.0;",
        ] {
            assert!(
                parse(&format!("{header} contract C() {{}}")).is_err(),
                "{header}"
            );
        }
        assert!(parse("contract C() { pragma arkade ^0.1.0; }").is_err());
        assert!(parse("contract C() {} pragma arkade ^0.1.0;").is_err());
    }

    #[test]
    fn checks_version_pragmas_against_the_compiler_version() {
        let check = |constraint: &str, version: &str| {
            let source = format!("pragma arkade {constraint}; contract C() {{}}");
            super::check_pragma(&source, version)
        };
        for (constraint, version, accepted) in [
            ("1.2.3", "1.2.3", true),
            ("1.2.3", "1.2.4", false),
            ("=1.2.3", "1.2.3", true),
            ("=1.2.3", "1.2.2", false),
            (">1.2.3", "1.2.4", true),
            (">1.2.3", "1.2.3", false),
            (">=1.2.3", "1.2.3", true),
            (">=1.2.3", "1.2.2", false),
            ("<1.2.3", "1.2.2", true),
            ("<1.2.3", "1.2.3", false),
            ("<=1.2.3", "1.2.3", true),
            ("<=1.2.3", "1.2.4", false),
            ("^1.2.3", "1.9.0", true),
            ("^1.2.3", "2.0.0", false),
            ("^1.2.3", "1.2.2", false),
            ("^0.1.2", "0.1.9", true),
            ("^0.1.2", "0.2.0", false),
            ("^0.1.2", "0.1.1", false),
            ("^0.0.3", "0.0.3", true),
            ("^0.0.3", "0.0.4", false),
            ("~1.2.3", "1.2.9", true),
            ("~1.2.3", "1.3.0", false),
            ("~1.2.3", "1.2.2", false),
            ("~0.0.3", "0.0.9", true),
            (">=0.1.0 <0.2.0", "0.1.5", true),
            (">=0.1.0 <0.2.0", "0.2.0", false),
            ("^0.1.0 || ^1.0.0", "0.1.3", true),
            ("^0.1.0 || ^1.0.0", "1.4.0", true),
            ("^0.1.0 || ^1.0.0", "0.2.0", false),
            ("^0.1.0", "0.1.0-rc.1", true),
            (">0.1.0", "0.1.0-rc.1", false),
            ("^ // constraint\n 1.2.3", "1.3.0", true),
            ("<99999999999999999999.0.0", "0.1.0", true),
        ] {
            assert_eq!(
                check(constraint, version).is_ok(),
                accepted,
                "{constraint} with {version}"
            );
        }
        let error = check("^1.0.0 || >=2.0.0 // range\n <3.0.0", "0.1.0-rc.1").unwrap_err();
        assert_eq!(
            error.message,
            "pragma requires arkade ^1.0.0 || >=2.0.0 <3.0.0, but this compiler is version 0.1.0-rc.1"
        );
    }

    #[test]
    fn parses_constant_array_sizes_without_changing_index_expressions() {
        let contract = parse(
            "struct State { int[N] values; } contract C(pubkey[C.N] keys) { const int N = 2; function spend(int[N] values) { int[N] local = [1, 2]; local[N - 1] = values[0]; require(true); } }",
        ).unwrap();
        assert_eq!(
            contract.structs[0].fields[0].param_type.to_string(),
            "int[N]"
        );
        assert_eq!(contract.parameters[0].param_type.to_string(), "pubkey[C.N]");
        assert_eq!(
            contract.functions[0].parameters[0].param_type.to_string(),
            "int[N]"
        );
        assert!(
            matches!(&contract.functions[0].statements[0].statement, Statement::LetBinding { declared_type: Some(ty), .. } if ty.to_string() == "int[N]")
        );
        assert!(
            matches!(&contract.functions[0].statements[1].statement, Statement::VarAssign { target: AssignmentTarget::ArrayIndex { index, .. }, .. } if matches!(&index.kind, ExprKind::BinaryOp { op, .. } if op.symbol() == "-"))
        );
        for size in ["", "0", "-1", "1 2", "N + 1"] {
            assert!(
                parse(&format!("contract C(int[{size}] values) {{}}")).is_err(),
                "{size}"
            );
        }
    }

    #[test]
    fn nested_array_types_list_sizes_outermost_first() {
        use crate::models::{ArraySize, TypeName};
        let array =
            |element, size: &str| TypeName::Array(Box::new(element), ArraySize::parse(size));
        let int = || TypeName::Named("int".into());
        let contract = parse(
            "struct Grid { int[2][N] cells; } contract C(pubkey[4][2][3] keys) { function spend(int [N] [M] grid) { int[2][3] local = [[1, 2, 3], [4, 5, 6]]; require(true); } }",
        )
        .unwrap();
        // `T[a][b]` is `a` elements of `T[b]`.
        assert_eq!(
            contract.structs[0].fields[0].param_type,
            array(array(int(), "N"), "2")
        );
        let keys = &contract.parameters[0].param_type;
        let pubkey = TypeName::Named("pubkey".into());
        assert_eq!(*keys, array(array(array(pubkey, "3"), "2"), "4"));
        assert_eq!(keys.to_string(), "pubkey[4][2][3]");
        assert_eq!(
            contract.functions[0].parameters[0].param_type,
            array(array(int(), "M"), "N")
        );
        assert!(
            matches!(&contract.functions[0].statements[0].statement, Statement::LetBinding { declared_type: Some(ty), .. } if *ty == array(array(int(), "3"), "2"))
        );
        for sizes in ["[2][]", "[][2]", "[2][0]", "[2]x[3]"] {
            assert!(
                parse(&format!("contract C(int{sizes} values) {{}}")).is_err(),
                "{sizes}"
            );
        }
    }

    #[test]
    fn parses_bytes_literals_before_decimal_and_preserves_utf8() {
        let contract = parse(
            r#"contract C() { function spend() {
            bytes x = 0xDEADbeef;
            bytes y = "ž\n";
            require("hello" == 0x68656c6c6f);
        } }"#,
        )
        .unwrap();
        let statements = &contract.functions[0].statements;
        assert!(
            matches!(&statements[0].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Literal(value), .. }, .. } if value == "0xdeadbeef")
        );
        assert!(
            matches!(&statements[1].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Literal(value), .. }, .. } if value == "0xc5be0a")
        );
        assert!(
            matches!(&statements[2].statement, Statement::Require(Expression { kind: ExprKind::BinaryOp { left, right, .. }, .. })
                if matches!((&left.kind, &right.kind), (ExprKind::Literal(left), ExprKind::Literal(right)) if left == "0x68656c6c6f" && left == right))
        );
    }

    #[test]
    fn distinguishes_property_access_from_qualified_calls() {
        let contract = parse(
            "contract C() { function spend() { let field = x.field; let call = Helper.value(); } }",
        )
        .unwrap();
        let statements = &contract.functions[0].statements;
        assert!(
            matches!(&statements[0].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Name(path), .. }, .. } if path.key() == "x.field")
        );
        assert!(
            matches!(&statements[1].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Call { name, args, .. }, .. }, .. } if name == "Helper.value" && args.is_empty())
        );
    }

    #[test]
    fn parses_private_visibility_return_types_and_call_arguments() {
        use crate::models::{ExprKind, Expression};
        let contract = parse(
            r#"contract C() {
            function spend(int amount) { check(amount + 1 * 2); }
            private function check(int value) { let returnValue = value; return; }
            private function sufficient(int value) bool { return value >= 1; }
            function other() { require(true); }
        }"#,
        )
        .unwrap();
        assert!(!contract.functions[0].is_private);
        assert!(contract.functions[1].is_private);
        assert_eq!(contract.functions[2].return_type, Some("bool".into()));
        assert!(!contract.functions[3].is_private);
        assert!(
            matches!(&contract.functions[0].statements[0].statement, Statement::Call(Expression { kind: ExprKind::Call { name, args, .. }, .. }) if name == "check" && matches!(&args[0].kind, ExprKind::BinaryOp { op, .. } if op.symbol() == "+"))
        );
        assert!(matches!(
            &contract.functions[1].statements[1].statement,
            Statement::Return(None)
        ));
        assert!(matches!(
            &contract.functions[2].statements[0].statement,
            Statement::Return(Some(_))
        ));
    }

    #[test]
    fn parses_logical_precedence_and_grouping() {
        let contract = parse("contract C() { function spend() { let value = !a == b || c && d && e; require((a || b) && !(c < d)); } }").unwrap();
        let Statement::LetBinding {
            value:
                Expression {
                    kind: ExprKind::BinaryOp { left, op, right },
                    ..
                },
            ..
        } = &contract.functions[0].statements[0].statement
        else {
            panic!("expected logical expression");
        };
        assert_eq!(op.symbol(), "||");
        assert!(matches!(&left.kind, ExprKind::BinaryOp { left, op, .. }
            if op.symbol() == "==" && matches!(&left.kind, ExprKind::Unary { op: UnaryOperator::Not, .. })));
        assert!(matches!(&right.kind, ExprKind::BinaryOp { left, op, .. }
            if op.symbol() == "&&" && matches!(&left.kind, ExprKind::BinaryOp { op, .. } if op.symbol() == "&&")));
        assert!(matches!(&contract.functions[0].statements[1].statement,
            Statement::Require(Expression { kind: ExprKind::BinaryOp { left, op, right }, .. })
            if op.symbol() == "&&"
                && matches!(&left.kind, ExprKind::BinaryOp { op, .. } if op.symbol() == "||")
                && matches!(&right.kind, ExprKind::Unary { op: UnaryOperator::Not, value }
                    if matches!(&value.kind, ExprKind::BinaryOp { op, .. } if op.symbol() == "<"))));
    }

    #[test]
    fn parses_unary_prefix_order_and_boolean_boundaries() {
        let contract = parse("contract Unary() { function spend() { let result = -!true != false; let truth = !trueValue; } }").unwrap();
        let Statement::LetBinding {
            value:
                Expression {
                    kind: ExprKind::BinaryOp { left, op, right },
                    ..
                },
            ..
        } = &contract.functions[0].statements[0].statement
        else {
            panic!("comparison must be the outer expression");
        };
        assert_eq!(op.symbol(), "!=");
        let ExprKind::Unary {
            op: UnaryOperator::Neg,
            value,
        } = &left.kind
        else {
            panic!("minus must be the outer prefix");
        };
        let ExprKind::Unary {
            op: UnaryOperator::Not,
            value,
        } = &value.kind
        else {
            panic!("not must be the inner prefix");
        };
        assert!(matches!(&value.kind, ExprKind::Literal(value) if value == "true"));
        assert!(matches!(&right.kind, ExprKind::Literal(value) if value == "false"));
        assert!(
            matches!(&contract.functions[0].statements[1].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Unary { op: UnaryOperator::Not, value }, .. }, .. } if matches!(&value.kind, ExprKind::Name(path) if path.key() == "trueValue"))
        );
    }

    #[test]
    fn parses_operand_paths_as_structured_accesses() {
        let contract = parse(
            r#"
contract C() {
    function spend(signature sig) {
        require(checkSig(sig, signers[i + 1].keys[0]));
        let part = substr(rows[0].data, p.offset, 1);
    }
}
"#,
        )
        .unwrap();
        let statements = &contract.functions[0].statements;
        assert!(matches!(
            &statements[0].statement,
            Statement::Require(Expression { kind: ExprKind::Builtin { builtin, args }, .. })
                if builtin.name == "checkSig" && matches!(&args[1].kind, ExprKind::IndexAccess { .. })
                    && args[1].source_text() == "signers[i + 1].keys[0]"
        ));
        assert!(matches!(
            &statements[1].statement,
            Statement::LetBinding { value: Expression { kind: ExprKind::Builtin { builtin, args }, .. }, .. }
                if builtin.name == "substr"
                    && matches!(&args[0].kind, ExprKind::FieldAccess { field, .. } if field == "data")
                    && matches!(&args[1].kind, ExprKind::Name(path) if path.key() == "p.offset")
        ));
    }

    #[test]
    fn parses_field_and_index_suffixes_on_computed_values() {
        let source = "contract C() { function spend(int i) {
            require(make(i).points[i].x == tx.outputs[0].script.version);
            require((p).x == 1);
        } }";
        let contract = parse(source).unwrap();
        let statements = &contract.functions[0].statements;
        let Statement::Require(Expression {
            kind: ExprKind::BinaryOp { left, right, .. },
            ..
        }) = &statements[0].statement
        else {
            panic!("{:?}", statements[0].statement);
        };
        let span = left.span;
        assert_eq!(&source[span.start..span.end], "make(i).points[i].x");
        let ExprKind::FieldAccess { value: element, .. } = &left.kind else {
            panic!("{left:?}");
        };
        let ExprKind::IndexAccess { value: points, .. } = &element.kind else {
            panic!("{element:?}");
        };
        let ExprKind::FieldAccess { value: call, .. } = &points.kind else {
            panic!("{points:?}");
        };
        assert!(matches!(&call.kind, ExprKind::Call { name, .. } if name == "make"));
        let ExprKind::FieldAccess { value: script, .. } = &right.kind else {
            panic!("{right:?}");
        };
        assert!(matches!(&script.kind, ExprKind::OutputIntrospection { .. }));
        // A grouped binding keeps its binding path.
        assert!(matches!(
            &statements[1].statement,
            Statement::Require(Expression { kind: ExprKind::BinaryOp { left, .. }, .. })
                if matches!(&left.kind, ExprKind::Name(path) if path.key() == "p.x")
        ));
    }

    #[test]
    fn parses_structured_assignment_targets() {
        let contract = parse(
            r#"
struct State {
    bool enabled;
    int[3] values;
}

contract Demo() {
    function spend(State state, int index) {
        state.enabled = true;
        state.values[index + 1] = 9;
        index = 0;
        require(true);
    }
}
"#,
        )
        .expect("contract should parse");

        let statements = &contract.functions[0].statements;
        assert!(matches!(
            &statements[0].statement,
            Statement::VarAssign {
                target: AssignmentTarget::Binding(name),
                ..
            } if name.key() == "state.enabled"
        ));
        assert!(matches!(
            &statements[1].statement,
            Statement::VarAssign {
                target: AssignmentTarget::ArrayIndex { array, index },
                ..
            } if array.key() == "state.values"
                && matches!(&index.kind, ExprKind::BinaryOp { op, .. } if op.symbol() == "+")
        ));
        assert!(matches!(
            &statements[2].statement,
            Statement::VarAssign {
                target: AssignmentTarget::Binding(name),
                ..
            } if name.key() == "index"
        ));
    }

    #[test]
    fn retains_declared_local_types_and_multisig_signatures() {
        let contract = parse(
            r#"
contract Demo(pubkey first, pubkey second) {
    function spend(signature firstSig, signature secondSig) {
        let inferred = 1;
        int explicit = inferred + 1;
        require(checkMultisig([first, second], [firstSig, secondSig]));
    }
}
"#,
        )
        .expect("contract should parse");

        let statements = &contract.functions[0].statements;
        assert!(matches!(
            &statements[0].statement,
            Statement::LetBinding {
                name,
                declared_type: None,
                ..
            } if name == "inferred"
        ));
        assert!(matches!(
            &statements[1].statement,
            Statement::LetBinding {
                name,
                declared_type: Some(declared_type),
                ..
            } if name == "explicit" && declared_type.to_string() == "int"
        ));
        assert!(matches!(
            &statements[2].statement,
            Statement::Require(Expression { kind: ExprKind::Builtin { builtin, args }, .. })
                if builtin.name == "checkMultisig" && args.len() == 2
                    && matches!(&args[0].kind, ExprKind::ArrayLiteral(keys) if keys.iter().map(Expression::source_text).eq(["first", "second"]))
                    && matches!(&args[1].kind, ExprKind::ArrayLiteral(sigs) if sigs.iter().map(Expression::source_text).eq(["firstSig", "secondSig"]))
        ));
    }

    #[test]
    fn retains_constant_thresholds_in_nested_helper_bodies() {
        let contract = parse(
            r#"
contract Demo() {
    static function authorize(pubkey key, signature sig, bool choose) {
        if (choose) { require(checkMultisig([key], [sig], QUORUM)); }
        else { require(checkMultisig([key], [sig], QUORUM)); }
    }
    const int QUORUM = 1;
}
"#,
        )
        .unwrap();
        let Statement::IfElse {
            then_body,
            else_body: Some(else_body),
            ..
        } = &contract.functions[0].statements[0].statement
        else {
            panic!("expected if/else");
        };
        for body in [then_body, else_body] {
            assert!(matches!(
                &body[0].statement,
                Statement::Require(Expression { kind: ExprKind::Builtin { builtin, args }, .. })
                    if builtin.name == "checkMultisig" && matches!(&args[2].kind, ExprKind::Name(path) if path.key() == "QUORUM")
            ));
        }
    }

    #[test]
    fn rejects_multisig_without_explicit_signatures() {
        for call in ["checkMultisig([first, second])"] {
            for modifier in ["", " tapscript"] {
                let source = format!(
                    r#"
contract Demo(pubkey first, pubkey second) {{
    function spend(signature firstSig, signature secondSig){modifier} {{
        require({call});
    }}
}}
"#
                );
                assert!(
                    parse(&source).is_err(),
                    "checkMultisig without signatures must fail for `{modifier}` functions"
                );
            }
        }
    }

    #[test]
    fn else_if_is_an_else_block_holding_one_if() {
        let contract = parse(
            "contract C() { function spend(int x) {
                if (x == 1) { require(x > 0); } else if (x == 2) { require(x > 1); }
                else if (x == 3) { require(x > 2); } else { require(x > 3); }
            } }",
        )
        .unwrap();
        let mut statement = &contract.functions[0].statements[0].statement;
        let mut arms = 1;
        while let Statement::IfElse {
            else_body: Some(body),
            ..
        } = statement
        {
            arms += 1;
            match body.as_slice() {
                [nested] if matches!(nested.statement, Statement::IfElse { .. }) => {
                    statement = &nested.statement
                }
                [_] => break,
                _ => panic!("{body:?}"),
            }
        }
        assert_eq!(arms, 4);
        for chain in [
            "elseif (x == 2) { require(x > 1); }",
            "else if x == 2 { require(x > 1); }",
        ] {
            let source = format!(
                "contract C() {{ function spend(int x) {{ if (x == 1) {{ require(x > 0); }} {chain} }} }}"
            );
            assert!(parse(&source).is_err(), "{chain}");
        }
    }

    #[test]
    fn block_comments_separate_tokens_and_do_not_nest() {
        let contract = parse(
            r#"/* header
            */ contract/**/C(/* none */) { function spend(/* a */int/* b */x/* c */) {
                bytes text = "/* text */"; // a line comment holds /* without closing it
                let groups = tx /* all */ . /* the */ assetGroups;
                require(x /* multi
                   line */ == /* // */ 1);
            } }"#,
        )
        .unwrap();
        let statements = &contract.functions[0].statements;
        assert!(
            matches!(&statements[0].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Literal(value), .. }, .. } if value == "0x2f2a2074657874202a2f")
        );
        assert!(
            matches!(&statements[1].statement, Statement::LetBinding { value: Expression { kind: ExprKind::Name(path), .. }, .. } if path.key() == "tx.assetGroups")
        );
        for source in [
            "/* /* nested */ */ contract C() {}",
            "contract C() {} /* unterminated",
            "contract C() {} /* unterminated *",
            "contract C() {} /*/",
            "contract C() {} / * split * /",
        ] {
            assert!(parse(source).is_err(), "{source}");
        }
        // Reported where it opens, also after the contract, where pest does not name `*/`.
        let error = parse("contract C() {}\n/* unterminated").unwrap_err();
        assert!(
            error.contains("--> 2:1") && error.contains("expected '*/'"),
            "{error}"
        );
    }

    #[test]
    fn every_list_takes_one_trailing_comma() {
        let contract = parse(
            r#"@allow(unused-parameter, "kept",)
            contract C(pubkey k, int[2] xs,) {
            function spend(signature s, int n, bytes32 id,) {
                let a = [n, 2,];
                let p = { x: n, y: 2, };
                let m = min(n, 2,);
                let h = sha256(cat(id, id,),);
                let v = int(0x01,);
                let l = tx.inputs[0].assets.lookup(AssetId { txid: id, gidx: 0, },);
                let f = tx.proof.field("type",);
                let t = this.tunnel(0, { script: true, value: true, assets: true, }, [id,],);
                require(checkMultisig([k, k,], [s, s,], 2,), "m",);
                require(n > 0,);
            }
            function exit(signature s,) tapscript {
                require(checkSig(s, tweak(k, spend,),),);
                require(older(blocks(144,),), "wait",);
            }
        }"#,
        )
        .unwrap();
        assert_eq!(contract.parameters.len(), 2);
        assert_eq!(contract.functions[0].parameters.len(), 3);
        assert_eq!(contract.functions[0].statements.len(), 10);
        // A lone quoted proof path is still checked at compile time.
        let error = parse(r#"contract C() { function spend() { let f = tx.proof.field("Bad Path",); require(f == f); } }"#).unwrap_err();
        assert!(error.contains("invalid proof message path"), "{error}");
        for list in [
            "f(,)",
            "f(n,,)",
            "f(, n)",
            "[,]",
            "[n,,]",
            "{,}",
            "{ x: n,, }",
            "(n,)",
            "int(,)",
            "sha256(,)",
            "new C(,)",
        ] {
            let source = format!(
                "contract C() {{ function spend(int n) {{ let a = {list}; require(a); }} }}"
            );
            assert!(parse(&source).is_err(), "{list}");
        }
        for source in [
            "contract C(,) {}",
            "contract C(int n,,) {}",
            "@allow(,) contract C() {}",
            "contract C() { function spend(int n) { require(n > 0,,); } }",
            "contract C() { function spend(int n) { require(,); } }",
            "contract C(pubkey k) { function exit(signature s) tapscript { require(checkSig(s, k,,)); } }",
        ] {
            assert!(parse(source).is_err(), "{source}");
        }
    }

    #[test]
    fn digit_separators_sit_between_digits_and_drop_out_of_values() {
        let contract = parse(
            "contract C(int[1_0] xs) { const int BIG = 1_000_000; function spend(int n) { let a = 1_2_3 + 1000; require(n > 0); } }",
        )
        .unwrap();
        assert_eq!(contract.parameters[0].param_type.to_string(), "int[10]");
        assert!(
            matches!(&contract.constants[0].value.kind, ExprKind::Literal(value) if value == "1000000")
        );
        assert!(
            matches!(&contract.functions[0].statements[0].statement, Statement::LetBinding { value: Expression { kind: ExprKind::BinaryOp { left, .. }, .. }, .. } if matches!(&left.kind, ExprKind::Literal(value) if value == "123"))
        );
        for literal in ["_1", "1_", "1__0", "1_ 0", "0_1", "01", "0x1_0", "0x_10"] {
            let source = format!(
                "contract C() {{ function spend(int n) {{ let a = {literal}; require(n > a); }} }}"
            );
            assert!(parse(&source).is_err(), "{literal}");
        }
        for source in [
            "contract C(int[0_1] xs) {}",
            "contract C(int[1_] xs) {}",
            "pragma arkade ^0.1_0.0; contract C() {}",
        ] {
            assert!(parse(source).is_err(), "{source}");
        }
    }
}
