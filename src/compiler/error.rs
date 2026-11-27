//! Errors raised while emitting Arkade Script and artifacts.

use std::{error, fmt};

use super::constants::ConstantError;
use super::{MAX_ELEMENT_SIZE, MAX_SCRIPT_SIZE, MAX_STACK_ITEMS};
use crate::imports::LoadError;
use crate::models::{Path, TypeName};
use crate::opcodes::Opcode;
use crate::operators::BinaryOperator;
use crate::parser::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompileErrorKind {
    Parse(ParseError),
    Load(Box<LoadError>),
    Constant(ConstantError),
    Internal(InternalError),
    /// An emission helper reached with an expression of the wrong shape.
    Expected {
        what: &'static str,
    },
    NotAnArray {
        array: Path,
    },
    LengthOfNonArray {
        array: Path,
    },
    UndefinedBinding {
        name: Path,
    },
    UndefinedArrayBinding {
        array: Path,
    },
    UndeclaredAssignment {
        name: Path,
    },
    ConstructorParameterAssigned {
        name: Path,
    },
    ImmutableConstructorParameter {
        name: Path,
    },
    InvalidMultisigThreshold,
    MultisigThresholdRange,
    MultisigKeysNotArray,
    MultisigKeyCount,
    MultisigCountMismatch,
    EcPairingArity,
    EcPairingPointsNotArray,
    CompositeArrayLiteral,
    CompositeStructLiteral,
    InvalidTunnelExceptionCount,
    LogicalBranchItems,
    UnclosedLogicalBranch,
    InvalidCallMarker,
    InvalidComparisonMarker,
    ExpressionItems {
        produced: usize,
        expected: usize,
    },
    UndefinedComparison {
        op: BinaryOperator,
        ty: TypeName,
    },
    MissingFunctionResult,
    FunctionResultNotTemporary,
    ExpectedArrayValue {
        ty: TypeName,
    },
    ArrayElementCount {
        length: usize,
    },
    ExpectedStructValue {
        ty: TypeName,
    },
    UnknownStruct {
        ty: TypeName,
    },
    MissingField {
        name: String,
    },
    UnknownFunction {
        name: String,
    },
    WrongArgumentCount {
        name: String,
    },
    ReturnOutsideFunction,
    ReturnMismatch,
    UnsupportedLoopIterable,
    LoopCountNotConstant,
    LoopRangeNotConstant,
    LoopRangeReversed {
        start: usize,
        end: usize,
    },
    IndexOutOfRange {
        index: String,
        array: String,
    },
    UnknownType {
        declared_type: TypeName,
    },
    RecursiveStruct {
        declared_type: TypeName,
    },
    StackLimit {
        function: String,
        peak: usize,
    },
    ScriptSizeLimit {
        function: String,
        size: usize,
    },
    ElementSizeLimit {
        function: String,
    },
    /// The validator's messages for the finished artifact.
    OutputValidation {
        messages: Vec<String>,
    },
    UnassignedTapscriptGroups,
    Serialize {
        message: String,
    },
}

/// A broken compiler invariant: a bug, never a problem in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InternalError {
    UnknownExpressionOpcode { opcode: Opcode },
    ValueOutsideExpression,
    ParameterInsideExpression,
    UnbalancedScope,
    UnfinishedScript,
    FinalUseDiverged,
    MissingPointLayout,
    ArrayIndexNotOnStack { array: Path },
    TemporaryOperands { opcode: Opcode, count: usize },
    StackUnderflow { opcode: Opcode },
    NoInitializerValue,
    InitializerNotTemporary,
    AliasedParameterAssigned { name: Path },
    NoAssignmentResult,
    AssignmentTargetMoved,
    InvalidAssignmentTarget { name: Path },
    ArrayAssignmentOperands { array: Path },
    ScopeUnderflow,
    ScopeEndedWithTemporary,
    TemporaryAtBranchJoin,
    MissingBranchBinding,
    StatementLeftTemporary,
    MissingDeclarationType,
    BranchChangedLayout,
    LoopIterationChangedLayout { iteration: usize },
    UnloweredControlFlow,
    LeavesMismatch,
    ContractNotLoaded { name: String },
}

impl fmt::Display for CompileErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const COMPOSITE: &str = "composite values are not supported";
        const IMMUTABLE: &str = "constructor parameters are immutable";
        match self {
            CompileErrorKind::Parse(error) => error.fmt(f),
            CompileErrorKind::Load(error) => error.fmt(f),
            CompileErrorKind::Constant(error) => error.fmt(f),
            CompileErrorKind::Internal(error) => write!(f, "internal compiler error: {error}"),
            CompileErrorKind::Expected { what } => write!(f, "expected {what}"),
            CompileErrorKind::NotAnArray { array } => write!(f, "'{array}' is not an array"),
            CompileErrorKind::LengthOfNonArray { array } => {
                write!(f, "'{array}' is not an array; '.length' is undefined")
            }
            CompileErrorKind::UndefinedBinding { name } => write!(f, "undefined binding '{name}'"),
            CompileErrorKind::UndefinedArrayBinding { array } => {
                write!(f, "undefined array binding '{array}'")
            }
            CompileErrorKind::UndeclaredAssignment { name } => {
                write!(f, "assignment to undeclared binding '{name}'")
            }
            CompileErrorKind::ConstructorParameterAssigned { name } => {
                write!(f, "cannot assign to constructor parameter '{name}'")
            }
            CompileErrorKind::ImmutableConstructorParameter { name } => {
                write!(
                    f,
                    "cannot assign to constructor parameter '{name}'; {IMMUTABLE}"
                )
            }
            CompileErrorKind::InvalidMultisigThreshold => f.write_str("invalid multisig threshold"),
            CompileErrorKind::MultisigThresholdRange => f.write_str(
                "checkMultisig threshold must be between 1 and the number of public keys",
            ),
            CompileErrorKind::MultisigKeysNotArray => {
                f.write_str("checkMultisig public keys must be an array")
            }
            CompileErrorKind::MultisigKeyCount => {
                f.write_str("checkMultisig needs between 1 and 999 public keys")
            }
            CompileErrorKind::MultisigCountMismatch => {
                f.write_str("checkMultisig key and signature counts must match")
            }
            CompileErrorKind::EcPairingArity => f.write_str("ecPairing takes three arguments"),
            CompileErrorKind::EcPairingPointsNotArray => {
                f.write_str("ecPairing G1 points must be an ECPoint array")
            }
            CompileErrorKind::CompositeArrayLiteral => write!(
                f,
                "array literals may only initialize an array declaration; {COMPOSITE}"
            ),
            CompileErrorKind::CompositeStructLiteral => write!(
                f,
                "struct literals may only initialize a typed struct declaration; {COMPOSITE}"
            ),
            CompileErrorKind::InvalidTunnelExceptionCount => {
                f.write_str("invalid tunnel exception count")
            }
            CompileErrorKind::LogicalBranchItems => {
                f.write_str("logical branch must produce exactly one stack item")
            }
            CompileErrorKind::UnclosedLogicalBranch => f.write_str("unclosed logical branch"),
            CompileErrorKind::InvalidCallMarker => f.write_str("invalid call marker"),
            CompileErrorKind::InvalidComparisonMarker => f.write_str("invalid comparison marker"),
            CompileErrorKind::ExpressionItems { produced, expected } => write!(
                f,
                "expression produces {produced} stack items; exactly {expected} required"
            ),
            CompileErrorKind::UndefinedComparison { op, ty } => {
                write!(f, "'{op}' is not defined for '{ty}' values")
            }
            CompileErrorKind::MissingFunctionResult => f.write_str("missing function result"),
            CompileErrorKind::FunctionResultNotTemporary => {
                f.write_str("function result is not a temporary")
            }
            CompileErrorKind::ExpectedArrayValue { ty } => {
                write!(f, "expected array value of type '{ty}'")
            }
            CompileErrorKind::ArrayElementCount { length } => {
                write!(f, "expected {length} array elements")
            }
            CompileErrorKind::ExpectedStructValue { ty } => {
                write!(f, "expected struct value of type '{ty}'")
            }
            CompileErrorKind::UnknownStruct { ty } => write!(f, "unknown struct '{ty}'"),
            CompileErrorKind::MissingField { name } => write!(f, "missing field '{name}'"),
            CompileErrorKind::UnknownFunction { name } => write!(f, "unknown function '{name}'"),
            CompileErrorKind::WrongArgumentCount { name } => {
                write!(f, "wrong argument count for '{name}'")
            }
            CompileErrorKind::ReturnOutsideFunction => {
                f.write_str("return outside private function")
            }
            CompileErrorKind::ReturnMismatch => {
                f.write_str("return value does not match function signature")
            }
            CompileErrorKind::UnsupportedLoopIterable => f.write_str("unsupported loop iterable"),
            CompileErrorKind::LoopCountNotConstant => {
                f.write_str("loop count must be a non-negative integer compile-time constant")
            }
            CompileErrorKind::LoopRangeNotConstant => {
                f.write_str("loop range bounds must be non-negative integer compile-time constants")
            }
            CompileErrorKind::LoopRangeReversed { start, end } => {
                write!(f, "loop range start {start} exceeds its end {end}")
            }
            CompileErrorKind::IndexOutOfRange { index, array } => {
                write!(f, "array index '{index}' is out of range for '{array}'")
            }
            CompileErrorKind::UnknownType { declared_type } => {
                write!(f, "unknown type '{declared_type}'")
            }
            CompileErrorKind::RecursiveStruct { declared_type } => {
                write!(f, "recursive struct layout: {declared_type}")
            }
            CompileErrorKind::StackLimit { function, peak } => write!(
                f,
                "function '{function}' can hold {peak} stack items, above the VM limit of \
                 {MAX_STACK_ITEMS}"
            ),
            CompileErrorKind::ScriptSizeLimit { function, size } => write!(
                f,
                "function '{function}' assembles to at least {size} bytes, above the VM limit of \
                 {MAX_SCRIPT_SIZE}"
            ),
            CompileErrorKind::ElementSizeLimit { function } => write!(
                f,
                "function '{function}' pushes a value above the VM element limit of \
                 {MAX_ELEMENT_SIZE}"
            ),
            CompileErrorKind::OutputValidation { messages } => {
                for (index, message) in messages.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(f, "output validation error: {message}")?;
                }
                Ok(())
            }
            CompileErrorKind::UnassignedTapscriptGroups => {
                f.write_str("unassigned tapscript groups (compiler bug)")
            }
            CompileErrorKind::Serialize { message } => f.write_str(message),
        }
    }
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalError::UnknownExpressionOpcode { opcode } => {
                write!(f, "unknown expression opcode {opcode}")
            }
            InternalError::ValueOutsideExpression => {
                f.write_str("extracted value outside an expression")
            }
            InternalError::ParameterInsideExpression => {
                f.write_str("constructor parameter inside an expression")
            }
            InternalError::UnbalancedScope => f.write_str("unbalanced generator scope"),
            InternalError::UnfinishedScript => f.write_str("Arkade Script did not finish cleanly"),
            InternalError::FinalUseDiverged => {
                f.write_str("final-use analysis diverged from emission")
            }
            InternalError::MissingPointLayout => f.write_str("missing native point layout"),
            InternalError::ArrayIndexNotOnStack { array } => {
                write!(f, "array index for '{array}' is not on the stack")
            }
            InternalError::TemporaryOperands { opcode, count } => {
                write!(f, "{opcode} expected {count} temporary stack operands")
            }
            InternalError::StackUnderflow { opcode } => write!(f, "{opcode} stack underflow"),
            InternalError::NoInitializerValue => f.write_str("local initializer produced no value"),
            InternalError::InitializerNotTemporary => {
                f.write_str("local initializer did not leave a temporary")
            }
            InternalError::AliasedParameterAssigned { name } => {
                write!(f, "aliased parameter '{name}' is assigned")
            }
            InternalError::NoAssignmentResult => f.write_str("assignment has no result value"),
            InternalError::AssignmentTargetMoved => {
                f.write_str("assignment target moved below the top slot")
            }
            InternalError::InvalidAssignmentTarget { name } => {
                write!(f, "invalid assignment target '{name}'")
            }
            InternalError::ArrayAssignmentOperands { array } => {
                write!(
                    f,
                    "array assignment operands for '{array}' are not on the stack"
                )
            }
            InternalError::ScopeUnderflow => f.write_str("scope stack underflow"),
            InternalError::ScopeEndedWithTemporary => f.write_str("scope ended with a temporary"),
            InternalError::TemporaryAtBranchJoin => f.write_str("temporary at branch join"),
            InternalError::MissingBranchBinding => f.write_str("missing branch binding"),
            InternalError::StatementLeftTemporary => {
                f.write_str("statement left a temporary stack value")
            }
            InternalError::MissingDeclarationType => f.write_str("missing declaration type"),
            InternalError::BranchChangedLayout => f.write_str("branch changed outer stack layout"),
            InternalError::LoopIterationChangedLayout { iteration } => {
                write!(f, "loop iteration {iteration} changed outer stack layout")
            }
            InternalError::UnloweredControlFlow => {
                f.write_str("control flow reached emission unlowered")
            }
            InternalError::LeavesMismatch => {
                f.write_str("checked leaves do not match the tapscripts")
            }
            InternalError::ContractNotLoaded { name } => {
                write!(f, "contract '{name}' is not loaded")
            }
        }
    }
}

impl error::Error for CompileErrorKind {}

impl error::Error for InternalError {}
