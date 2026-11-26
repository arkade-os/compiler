use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::diagnostics::Span;
use crate::models::*;
use crate::operators::BinaryOperator;
use crate::properties::{
    AssetProperty, GroupIoProperty, GroupProperty, InputProperty, OutputProperty, ThisProperty,
    TxProperty,
};
use pest::iterators::Pair;
use Suffix::{Call, Field, Index};

/// A resolved member, where it ends, and the suffixes after it.
type Member<'s, 'a> = (ExprKind, usize, &'s [Suffix<'a>]);

/// Resolve the member chain of `this`: `this.tunnel(...)`, `this.activeInputIndex` or
/// `this.expiry`, then the suffixes after it. A chain that spells no member reads as the path
/// it spells, which validation reports. `this.renew(...)` is no value: `parse_renew` reads it
/// as a whole requirement.
pub(crate) fn parse_this_chain(
    this: Expression,
    suffixes: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    let start = this.span.start;
    let member = match suffixes {
        [Index(..), ..] => return apply_suffixes(this, false, suffixes),
        [Call("tunnel", args, end), rest @ ..] => {
            let span = Span { start, end: *end };
            Some((parse_tunnel(args, span)?, *end, rest))
        }
        [Call("renew", ..), ..] => {
            return Err(
                "`this.renew(...)` must be the whole condition of a require, as in \
                 `require(this.renew())`"
                    .to_string(),
            )
        }
        [Field(name, end), rest @ ..] => {
            ThisProperty::from_name(name).map(|property| (ExprKind::This(property), *end, rest))
        }
        _ => None,
    };
    let (kind, end, rest) = member.unwrap_or((this.kind, this.span.end, suffixes));
    member_value(kind, start, end, rest, text)
}

/// Resolve the member chain of `tx` left to right, then the suffixes after the member. A chain
/// that spells no member reads as the path it spells, which validation reports.
pub(crate) fn parse_tx_chain(
    tx: Expression,
    suffixes: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    let start = tx.span.start;
    let (kind, end, rest) = match suffixes {
        [] | [Index(..), ..] => return apply_suffixes(tx, false, suffixes),
        // ponytail: `tx.intent` is the deprecated spelling of `tx.proof`; remove it in 0.2.
        [Field("proof" | "intent", _), Call(member @ ("field" | "has"), args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let path = Box::new(parse_proof_path(&args[0])?);
            let presence_only = *member == "has";
            (
                ExprKind::IntentInspect {
                    path,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        // `.packet.has(type)` reads the presence flag instead of the bytes.
        [Field("packet", _), Call(method @ "has", args, end), rest @ ..]
        | [Call(method @ "packet", args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let packet_type = operand(&args[0])?;
            let presence_only = *method == "has";
            (
                ExprKind::PacketInspect {
                    packet_type,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        [Field("inputs", _), Index(index, _), Field("packet", _), Call(method @ "has", args, end), rest @ ..]
        | [Field("inputs", _), Index(index, _), Call(method @ "packet", args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let (index, packet_type) = (operand(index)?, operand(&args[0])?);
            let presence_only = *method == "has";
            (
                ExprKind::InputPacketInspect {
                    index,
                    packet_type,
                    presence_only,
                },
                *end,
                rest,
            )
        }
        // The output a proof pairs with the current input, read by an output's members.
        [Field("proof", _), Field("output", end), members @ ..] => {
            let index = Box::new(proof_output_index(Span { start, end: *end }));
            let member = match members {
                [Field("assets", _), assets @ ..] => {
                    asset_member(AssetLookupSource::Output, index, assets)?
                }
                [Field(name, end), rest @ ..] => OutputProperty::from_name(name).map(|property| {
                    let kind = ExprKind::OutputIntrospection { index, property };
                    (kind, *end, rest)
                }),
                _ => None,
            };
            match member {
                Some(member) => member,
                None => return Ok(member_path(text, start)),
            }
        }
        [Field(io @ ("inputs" | "outputs"), _), Field("length", end), rest @ ..] => {
            let property = match *io {
                "inputs" => TxProperty::NumInputs,
                _ => TxProperty::NumOutputs,
            };
            (ExprKind::TxIntrospection { property }, *end, rest)
        }
        [Field(io @ ("inputs" | "outputs"), _), Index(index, _), Field("assets", _), assets @ ..] =>
        {
            let source = match *io {
                "inputs" => AssetLookupSource::Input,
                _ => AssetLookupSource::Output,
            };
            match asset_member(source, operand(index)?, assets)? {
                Some(member) => member,
                None => return Ok(member_path(text, start)),
            }
        }
        [Field(io @ ("inputs" | "outputs"), _), Index(index, _), Field(property, end), rest @ ..] =>
        {
            let index = operand(index)?;
            let kind = match *io {
                "inputs" => InputProperty::from_name(property)
                    .map(|property| ExprKind::InputIntrospection { index, property }),
                _ => OutputProperty::from_name(property)
                    .map(|property| ExprKind::OutputIntrospection { index, property }),
            };
            match kind {
                Some(kind) => (kind, *end, rest),
                None => return Ok(member_path(text, start)),
            }
        }
        [Field("input", _), Field("current", _), rest @ ..] => {
            let current = match rest {
                [Field(name, end), rest @ ..] => {
                    InputProperty::from_name(name).map(|property| (property, *end, rest))
                }
                _ => None,
            };
            let Some((property, end, rest)) = current else {
                return Err(format!(
                    "tx.input.current requires one of: {} (got '{}')",
                    InputProperty::ALL
                        .iter()
                        .map(|property| property.name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    without_trivia(trim_trivia_end(text))
                ));
            };
            (current_input(property, Span { start, end }).kind, end, rest)
        }
        [Field("assetGroups", end), rest @ ..] => match rest {
            [Call("has", args, end), rest @ ..] if args.len() == 1 => {
                let asset_id = operand(&args[0])?;
                (ExprKind::GroupHas { asset_id }, *end, rest)
            }
            [Field("length", end), rest @ ..] => (ExprKind::AssetGroupsLength, *end, rest),
            [Call("lookup", args, end), members @ ..] if args.len() == 1 => {
                let kind = ExprKind::GroupLookup {
                    asset_id: operand(&args[0])?,
                };
                let group = Expression::new(kind, Span { start, end: *end });
                match group_member(group, members)? {
                    Some(member) => member,
                    None => return Ok(member_path(text, start)),
                }
            }
            [Index(index, end), members @ ..] => {
                let kind = ExprKind::AssetGroupAt {
                    index: operand(index)?,
                };
                let group = Expression::new(kind, Span { start, end: *end });
                match group_member(group, members)? {
                    Some(member) => member,
                    None => return Ok(member_path(text, start)),
                }
            }
            rest => (ExprKind::Name(Path::from_key("tx.assetGroups")), *end, rest),
        },
        [Field(name, end), rest @ ..] => match TxProperty::from_name(name) {
            Some(property) => (ExprKind::TxIntrospection { property }, *end, rest),
            None => return Ok(member_path(text, start)),
        },
        _ => return Ok(member_path(text, start)),
    };
    member_value(kind, start, end, rest, text)
}

/// A member's value with the field and index suffixes after it applied. A member's value has no
/// members to call, so a call after it reads the whole chain as the path `text` spells.
fn member_value(
    kind: ExprKind,
    start: usize,
    end: usize,
    rest: &[Suffix],
    text: &str,
) -> Result<Expression, String> {
    if rest.iter().any(|suffix| matches!(suffix, Call(..))) {
        return Ok(member_path(text, start));
    }
    apply_suffixes(Expression::new(kind, Span { start, end }), false, rest)
}

/// The member read on the assets of input or output `index`, if `assets` spells one.
fn asset_member<'s, 'a>(
    source: AssetLookupSource,
    index: Box<Expression>,
    assets: &'s [Suffix<'a>],
) -> Result<Option<Member<'s, 'a>>, String> {
    Ok(Some(match assets {
        [Index(asset, end), rest @ ..] => {
            let read = match rest {
                [Field(name, end), rest @ ..] => {
                    AssetProperty::from_name(name).map(|property| (Some(property), *end, rest))
                }
                _ => None,
            };
            let (property, end, rest) = read.unwrap_or((None, *end, rest));
            let kind = ExprKind::AssetAt {
                source,
                io_index: index,
                asset_index: operand(asset)?,
                property,
            };
            (kind, end, rest)
        }
        [Field("length", end), rest @ ..] => (ExprKind::AssetCount { source, index }, *end, rest),
        [Call(method @ ("has" | "lookup" | "tryLookup"), args, end), rest @ ..]
            if args.len() == 1 =>
        {
            let asset_id = operand(&args[0])?;
            let kind = match *method {
                "has" => ExprKind::AssetHas {
                    source,
                    index,
                    asset_id,
                },
                "lookup" => ExprKind::AssetLookup {
                    source,
                    index,
                    asset_id,
                },
                _ => ExprKind::AssetTryLookup {
                    source,
                    index,
                    asset_id,
                },
            };
            (kind, *end, rest)
        }
        _ => return Ok(None),
    }))
}

/// The member read on an asset group of a `tx` chain, or the group itself when `members`
/// starts with none; `None` when a field read on a group record is not one of its own.
fn group_member<'s, 'a>(
    group: Expression,
    members: &'s [Suffix<'a>],
) -> Result<Option<Member<'s, 'a>>, String> {
    Ok(Some(match members {
        [Call("controlIs", args, end), rest @ ..] if args.len() == 1 => {
            let asset_id = operand(&args[0])?;
            let group = Box::new(group);
            (ExprKind::GroupControlIs { group, asset_id }, *end, rest)
        }
        [Field(source @ ("inputs" | "outputs"), _), Index(index, end), rest @ ..] => {
            let (property, end, rest) = match rest {
                [Field(name, end), rest @ ..] => match GroupIoProperty::from_name(name) {
                    Some(property) => (Some(property), *end, rest),
                    None => return Ok(None),
                },
                _ => (None, *end, rest),
            };
            let kind = ExprKind::GroupIOAccess {
                group: Box::new(group),
                io_index: operand(index)?,
                source: crate::types::group_io_source(source)
                    .ok_or("Invalid asset group io source")?,
                property,
            };
            (kind, end, rest)
        }
        [Field(name, end), rest @ ..] => match GroupProperty::from_name(name) {
            Some(property) => {
                let group = Box::new(group);
                (ExprKind::GroupProperty { group, property }, *end, rest)
            }
            None => (group.kind, group.span.end, members),
        },
        _ => (group.kind, group.span.end, members),
    }))
}

/// A member chain that spells no member, as the path its `text` spells.
fn member_path(text: &str, start: usize) -> Expression {
    let text = trim_trivia_end(text);
    let span = Span {
        start,
        end: start + text.len(),
    };
    Expression::new(ExprKind::Name(Path::from_key(&without_trivia(text))), span)
}

fn operand(pair: &Pair<Rule>) -> Result<Box<Expression>, String> {
    parse_general_expression(pair.clone()).map(Box::new)
}

/// A proof message path operand; a lone string literal is checked at compile time, any other
/// bytes expression by the VM.
fn parse_proof_path(operand: &Pair<Rule>) -> Result<Expression, String> {
    let literal = lone(operand);
    if literal.as_rule() != Rule::string_literal {
        return parse_general_expression(operand.clone());
    }
    let text = parse_string_literal(literal.as_str())?;
    if !is_proof_path(&text) {
        return Err(format!("invalid proof message path '{text}'"));
    }
    let span = literal.as_span().into();
    Ok(Expression::new(
        ExprKind::Literal(parse_named_operand(literal)?),
        span,
    ))
}

/// The VM's simple path syntax: dot-separated lowercase keys and array indexes.
fn is_proof_path(path: &str) -> bool {
    path.len() <= 520
        && path
            .split('.')
            .all(|segment| match segment.as_bytes().first() {
                Some(b'0'..=b'9') => {
                    !(segment.len() > 1 && segment.starts_with('0'))
                        && segment
                            .parse::<u64>()
                            .is_ok_and(|index| index < 1024 * 1024)
                }
                Some(b'a'..=b'z' | b'_') => segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                _ => false,
            })
}

/// `this.tunnel(outputIndex, policy?, exceptions?)`, its policy a struct literal and its
/// exceptions a list literal.
fn parse_tunnel(args: &[Pair<Rule>], span: Span) -> Result<ExprKind, String> {
    let literals = tunnel_literals(args.get(1..).unwrap_or_default());
    let (Some(index), Some([policy, exceptions])) = (args.first(), literals) else {
        // Arguments no tunnel takes read as a call, which reports the signature.
        return parse_call("this.tunnel".to_string(), args.to_vec(), span).map(|call| call.kind);
    };
    let output_index = parse_general_expression(index.clone())?;
    tunnel(output_index, policy, exceptions, span)
}

/// The policy and the exceptions `literals` spell, a struct literal and then a list literal,
/// each optional; `None` for any other arguments.
fn tunnel_literals<'a>(literals: &[Pair<'a, Rule>]) -> Option<[Option<Pair<'a, Rule>>; 2]> {
    let literal = |at: usize, rules: &[Rule]| match literals.get(at).map(lone) {
        Some(literal) if rules.contains(&literal.as_rule()) => Some(Some(literal)),
        Some(_) => None,
        None => Some(None),
    };
    let policy = literal(0, &[Rule::struct_literal])?;
    let exceptions = literal(1, &[Rule::array_literal, Rule::empty_list])?;
    (literals.len() <= 2).then_some([policy, exceptions])
}

/// The tunnel that continues the current input at `output_index`, preserving what the `policy`
/// literal selects, or everything without one, apart from the `exceptions` literal's assets.
fn tunnel(
    output_index: Expression,
    policy: Option<Pair<Rule>>,
    exceptions: Option<Pair<Rule>>,
    span: Span,
) -> Result<ExprKind, String> {
    let policy = if let Some(policy) = policy {
        let ExprKind::StructLiteral { fields, .. } = parse_primary_expr(policy)?.kind else {
            return Err("tunnel policy must be a struct literal".to_string());
        };
        let mut values = [None, None, None];
        for (name, value) in fields {
            let index = match name.as_str() {
                "script" => 0,
                "value" => 1,
                "assets" => 2,
                _ => return Err(format!("unknown tunnel policy field '{name}'")),
            };
            if values[index].replace(value).is_some() {
                return Err(format!("duplicate tunnel policy field '{name}'"));
            }
        }
        let [script, value, assets] = values;
        [
            script.ok_or("missing tunnel policy field 'script'")?,
            value.ok_or("missing tunnel policy field 'value'")?,
            assets.ok_or("missing tunnel policy field 'assets'")?,
        ]
    } else {
        std::array::from_fn(|_| Expression::new(ExprKind::Literal("true".to_string()), span))
    };
    let exceptions = exceptions
        .map(|list| {
            list.into_inner()
                .map(parse_general_expression)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(ExprKind::Tunnel {
        output_index: Box::new(output_index),
        policy: Box::new(policy),
        exceptions,
    })
}

/// Seconds before expiry at which `this.renew` opens when it names no window.
const RENEWAL_WINDOW: &str = "86400";

/// The requirements `this.renew(window?, policy?, exceptions?)` stands for when `condition` is
/// that call alone: the window before expiry is open, the proof registers for a batch, it has no
/// onchain output, and the output it pairs with the current input tunnels it under the policy
/// and exceptions, which are `this.tunnel`'s. Each is a `require` of its own, since `&&` would
/// branch around the later ones.
pub(crate) fn parse_renew(
    condition: &Pair<Rule>,
    constants: &[Constant],
) -> Result<Option<[Expression; 4]>, CompileError> {
    let call = lone(condition);
    if call.as_rule() != Rule::primary_expr {
        return Ok(None);
    }
    let mut chain = call.into_inner();
    let this = chain.next().ok_or("Empty primary expression")?;
    let suffixes = suffixes(chain)?;
    let ("this", [Call("renew", args, end)]) = (this.as_str(), suffixes.as_slice()) else {
        return Ok(None);
    };
    let span = Span {
        start: this.as_span().start(),
        end: *end,
    };
    // A struct or list literal is the tunnel's, so only another first argument is the window.
    let tunnel_rules = [Rule::struct_literal, Rule::array_literal, Rule::empty_list];
    let (window, literals) = match args.split_first() {
        Some((window, literals)) if !tunnel_rules.contains(&lone(window).as_rule()) => {
            (Some(window), literals)
        }
        _ => (None, args.as_slice()),
    };
    let Some([policy, exceptions]) = tunnel_literals(literals) else {
        // Arguments no renewal takes read as a call, which reports the signature.
        return parse_call("this.renew".to_string(), args.clone(), span)
            .map(|_| None)
            .map_err(CompileError::from);
    };
    let at = |kind| Expression::new(kind, span);
    let window = match window {
        Some(window) => parse_general_expression(window.clone())?,
        None => at(ExprKind::Literal(RENEWAL_WINDOW.to_string())),
    };
    let mut constant = |path: &Path| constant_value(path, constants);
    let range = crate::validator::constant_domain_error("this.renew", 0, &window, &mut constant);
    if let Some(message) = range {
        return Err(CompileError::from(message).at(window.span));
    }
    let binary = |left, op, right: Expression| {
        let (left, right) = (Box::new(at(left)), Box::new(right));
        at(ExprKind::BinaryOp { left, op, right })
    };
    let text = |text: &str| at(ExprKind::Literal(bytes_literal(text)));
    let field = |path: &str, value: &str| {
        let (path, presence_only) = (Box::new(text(path)), false);
        let field = ExprKind::IntentInspect {
            path,
            presence_only,
        };
        binary(field, BinaryOperator::Eq, text(value))
    };
    let expiry = ExprKind::This(ThisProperty::Expiry);
    let builtin = crate::builtins::find("checkTime").expect("checkTime is a builtin");
    let args = vec![binary(expiry, BinaryOperator::Sub, window)];
    Ok(Some([
        at(ExprKind::Builtin { builtin, args }),
        field("type", "register"),
        field("onchain_output_indexes", "[]"),
        at(tunnel(proof_output_index(span), policy, exceptions, span)?),
    ]))
}

/// `this.activeInputIndex - 1`, the index of the output a proof pairs with the current input.
fn proof_output_index(span: Span) -> Expression {
    let at = |kind| Box::new(Expression::new(kind, span));
    let kind = ExprKind::BinaryOp {
        left: at(ExprKind::This(ThisProperty::ActiveInputIndex)),
        op: BinaryOperator::Sub,
        right: at(ExprKind::Literal("1".to_string())),
    };
    Expression::new(kind, span)
}

/// `tx.inputs[this.activeInputIndex].<property>`, which `tx.input.current.*` spells.
fn current_input(property: InputProperty, span: crate::diagnostics::Span) -> Expression {
    let index = Expression::new(ExprKind::This(ThisProperty::ActiveInputIndex), span);
    Expression::new(
        ExprKind::InputIntrospection {
            index: Box::new(index),
            property,
        },
        span,
    )
}
