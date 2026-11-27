//! Errors raised while mapping source text into the AST.

use std::{error, fmt, result};

use pest::error::Error as PestError;

use super::Rule;
use crate::models::Path;
use crate::properties::InputProperty;

pub(crate) type Result<T, E = ParseError> = result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    Syntax(Box<PestError<Rule>>),
    /// A grammar node the parse tree lacks.
    Missing {
        part: &'static str,
    },
    MissingInStatement {
        part: &'static str,
    },
    Empty {
        what: &'static str,
    },
    InvalidInStatement {
        what: &'static str,
    },
    RequireWithoutCondition {
        function: String,
    },
    UnexpectedUnaryOperator,
    UnexpectedKeyExpression {
        rule: Rule,
    },
    ParameterMissingType,
    StructFieldMissing {
        name: String,
        part: &'static str,
    },
    InvalidGroupIoSource,
    InvalidStringLiteral {
        message: String,
    },
    UnknownOperator {
        operator: String,
    },
    TapscriptOnlyCall {
        name: String,
        hint: &'static str,
    },
    WrongReservedArguments {
        name: String,
        signature: String,
    },
    EmptyListOutsideTunnel,
    UncallableSuffix {
        name: String,
    },
    WrongArgumentCount {
        name: &'static str,
        signature: String,
        got: usize,
    },
    CurrentInputMemberRequired {
        got: String,
    },
    InvalidProofPath {
        path: String,
    },
    TunnelPolicyNotStruct,
    UnknownTunnelPolicyField {
        name: String,
    },
    DuplicateTunnelPolicyField {
        name: String,
    },
    MissingTunnelPolicyField {
        name: &'static str,
    },
    PragmaUnsatisfied {
        alternatives: Vec<String>,
        version: String,
    },
    LibraryTapscript,
    StaticLibraryFunction,
    RangeLoopVariables,
    RangeLoopNotRange,
    CallStatement {
        name: String,
    },
    TapscriptVisibility {
        visibility: String,
    },
    HashOutsideComparison {
        callee: String,
    },
    TapscriptCallMisplaced {
        callee: String,
        signature: String,
    },
    ArkadeScriptOnly {
        name: String,
    },
    WitnessInputReused {
        tapscript: String,
        input: String,
    },
    TapscriptCheckUnsupported {
        expression: String,
    },
    TapscriptCheckRuleUnsupported {
        rule: Rule,
    },
    CompoundTapscriptRequire,
    UnknownHashFunction {
        name: String,
    },
    PreimageNotInput {
        preimage: String,
    },
    LocktimeInTapscript,
    UnsupportedTapscriptCall {
        name: String,
    },
    RequiresOneArgument {
        name: String,
    },
    UnknownTimeWrapper {
        call: String,
        wrapper: String,
    },
    TimelockNotOperand {
        value: String,
    },
    UnknownConstant {
        path: Path,
    },
    IndexNotConstant {
        binding: String,
    },
    TapscriptKeyWidth {
        key: Path,
        width: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Syntax(error) => write!(f, "Parse error: {error}"),
            ParseError::Missing { part } => write!(f, "Missing {part}"),
            ParseError::MissingInStatement { part } => write!(f, "Parse error: Missing {part}"),
            ParseError::Empty { what } => write!(f, "Empty {what}"),
            ParseError::InvalidInStatement { what } => write!(f, "Parse error: Invalid {what}"),
            ParseError::RequireWithoutCondition { function } => {
                write!(f, "Parse error: Invalid arguments to function {function}")
            }
            ParseError::UnexpectedUnaryOperator => f.write_str("Unexpected unary operator"),
            ParseError::UnexpectedKeyExpression { rule } => {
                write!(f, "unexpected key expression: {rule:?}")
            }
            ParseError::ParameterMissingType => f.write_str("Parameter is missing data type"),
            ParseError::StructFieldMissing { name, part } => {
                write!(f, "struct '{name}' field is missing a {part}")
            }
            ParseError::InvalidGroupIoSource => f.write_str("Invalid asset group io source"),
            ParseError::InvalidStringLiteral { message } => {
                write!(f, "Invalid string literal: {message}")
            }
            ParseError::UnknownOperator { operator } => write!(f, "unknown operator '{operator}'"),
            ParseError::TapscriptOnlyCall { name, hint } => {
                write!(
                    f,
                    "`{name}(...)` is only available in tapscript functions{hint}"
                )
            }
            ParseError::WrongReservedArguments { name, signature } => {
                write!(f, "wrong arguments to `{name}`: expected {signature}")
            }
            ParseError::EmptyListOutsideTunnel => f.write_str(
                "`[]` is an empty list, which only `this.tunnel` takes, for its exceptions",
            ),
            ParseError::UncallableSuffix { name } => write!(
                f,
                "cannot call `.{name}(...)` here; only library functions, `tx` and `this` \
                 members and `controlIs` on a group binding take arguments"
            ),
            ParseError::WrongArgumentCount {
                name,
                signature,
                got,
            } => write!(
                f,
                "wrong number of arguments to `{name}`: expected {signature}, got {got}"
            ),
            ParseError::CurrentInputMemberRequired { got } => {
                let members: Vec<_> = InputProperty::ALL.iter().map(|p| p.name()).collect();
                write!(
                    f,
                    "tx.input.current requires one of: {} (got '{got}')",
                    members.join(", ")
                )
            }
            ParseError::InvalidProofPath { path } => {
                write!(f, "invalid proof message path '{path}'")
            }
            ParseError::TunnelPolicyNotStruct => {
                f.write_str("tunnel policy must be a struct literal")
            }
            ParseError::UnknownTunnelPolicyField { name } => {
                write!(f, "unknown tunnel policy field '{name}'")
            }
            ParseError::DuplicateTunnelPolicyField { name } => {
                write!(f, "duplicate tunnel policy field '{name}'")
            }
            ParseError::MissingTunnelPolicyField { name } => {
                write!(f, "missing tunnel policy field '{name}'")
            }
            ParseError::PragmaUnsatisfied {
                alternatives,
                version,
            } => write!(
                f,
                "pragma requires arkade {}, but this compiler is version {version}",
                alternatives.join(" || ")
            ),
            ParseError::LibraryTapscript => {
                f.write_str("libraries cannot declare tapscript functions")
            }
            ParseError::StaticLibraryFunction => f.write_str(
                "`static` marks a contract's stateless helper; library functions need no modifier",
            ),
            ParseError::RangeLoopVariables => {
                f.write_str("a range binds one loop variable, as in `for (i) in 0..N`")
            }
            ParseError::RangeLoopNotRange => f.write_str(
                "one loop variable iterates a range, as in `for (i) in 0..N`; \
                 an array takes two, as in `for (i, x) in items`",
            ),
            ParseError::CallStatement { name } => {
                write!(
                    f,
                    "`{name}(...)` cannot be a statement; use it inside require()"
                )
            }
            ParseError::TapscriptVisibility { visibility } => {
                write!(f, "tapscript functions cannot be {visibility}")
            }
            ParseError::HashOutsideComparison { callee } => write!(
                f,
                "a tapscript function can use `{callee}` only as \
                 `require({callee}(preimage) == hash)`"
            ),
            ParseError::TapscriptCallMisplaced { callee, signature } => {
                write!(f, "a tapscript function can use `{callee}` only as ")?;
                match callee.as_str() {
                    "older" | "after" => write!(f, "`require({signature})`"),
                    "tweak" => f.write_str("a key inside checkSig or checkMultisig"),
                    _ => write!(f, "`older({signature})` or `after({signature})`"),
                }
            }
            ParseError::ArkadeScriptOnly { name } => {
                write!(f, "`{name}` is only available in Arkade Script functions")
            }
            ParseError::WitnessInputReused { tapscript, input } => write!(
                f,
                "tapscript `{tapscript}`: input `{input}` is used more than once, but the \
                 witness carries each input once; declare a separate input for each use"
            ),
            ParseError::TapscriptCheckUnsupported { expression } => write!(
                f,
                "a tapscript require can check only signatures, hashes and timelocks, not \
                 `{expression}`"
            ),
            ParseError::TapscriptCheckRuleUnsupported { rule } => write!(
                f,
                "a tapscript require can check only signatures, hashes and timelocks, not {}",
                super::rule_term(rule).unwrap_or_else(|| "this expression".to_string())
            ),
            ParseError::CompoundTapscriptRequire => {
                f.write_str("unsupported compound expression in tapscript require()")
            }
            ParseError::UnknownHashFunction { name } => write!(f, "unknown hash function {name}"),
            ParseError::PreimageNotInput { preimage } => {
                write!(f, "hash preimage `{preimage}` is not a tapscript input")
            }
            ParseError::LocktimeInTapscript => f.write_str(
                "`tx.locktime` is only available in Arkade Script functions; use `after(...)` in \
                 tapscript functions",
            ),
            ParseError::UnsupportedTapscriptCall { name } => {
                write!(f, "unsupported tapscript call `{name}(...)`")
            }
            ParseError::RequiresOneArgument { name } => write!(f, "{name}() requires one argument"),
            ParseError::UnknownTimeWrapper { call, wrapper } => write!(
                f,
                "{call}() takes blocks(n), seconds(n), or a value, not `{wrapper}(...)`"
            ),
            ParseError::TimelockNotOperand { value } => write!(
                f,
                "timelock `{value}` is not a literal or scalar constructor parameter"
            ),
            ParseError::UnknownConstant { path } => write!(f, "unknown constant '{path}'"),
            ParseError::IndexNotConstant { binding } => {
                write!(
                    f,
                    "`{binding}` must be indexed by an integer literal or constant"
                )
            }
            ParseError::TapscriptKeyWidth { key, width } => write!(
                f,
                "tapscript key '{key}' is {width} bytes; tapscript keys are 32-byte x-only public \
                 keys"
            ),
        }
    }
}

impl error::Error for ParseError {}
