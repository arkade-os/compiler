//! Errors in the source, and self-check failures of the emitted artifact.

use std::{error, fmt};

use crate::compiler::constants::ConstantError;
use crate::compiler::error::CompileErrorKind;
use crate::compiler::MAX_LOOP_ITERATIONS;
use crate::diagnostics::{CompileError, Span};
use crate::errors::ErrorCode;
use crate::models::{Path, TypeName};
use crate::operators::{BinaryOperator, OperatorClass, UnaryOperator};

use super::ValidationIssue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidationError {
    EmptyContractName,
    NoEntrypoint,
    ReservedFunctionName {
        name: String,
    },
    DuplicateFunction {
        name: String,
    },
    DuplicateConstructorParameter {
        name: String,
    },
    DuplicateParameter {
        name: String,
        function: String,
    },
    DuplicateTapscript {
        name: String,
    },
    ReservedConstructorParameter {
        name: String,
    },
    ReservedTapscriptInput {
        tapscript: String,
        input: String,
    },
    ArrayTapscriptInput {
        tapscript: String,
        input: String,
        ty: TypeName,
    },
    StructTapscriptInput {
        tapscript: String,
        input: String,
        ty: TypeName,
    },
    DuplicateTapscriptInput {
        input: String,
        tapscript: String,
    },
    UnknownAttribute {
        name: String,
    },
    AttributeWithoutLint {
        name: String,
    },
    AttributeArguments {
        name: String,
    },
    AttributeWithoutReason {
        name: String,
    },
    CannotInferType {
        text: String,
    },
    StructCollidesWithBuiltin {
        name: String,
    },
    DuplicateStruct {
        name: String,
    },
    DuplicateStructField {
        field: String,
        name: String,
    },
    RecursiveStruct {
        cycle: Vec<String>,
    },
    UnknownType {
        context: Declared,
        base: String,
    },
    PlaceholderName {
        context: Declared,
        name: String,
    },
    ReservedName {
        context: Declared,
        name: String,
    },
    UnusedTapscriptInput {
        input: String,
        tapscript: String,
    },
    UnusedParameter {
        parameter: String,
        function: String,
    },
    EntrypointReturnType {
        function: String,
    },
    StaticReadsConstructorParameter {
        function: String,
        parameter: String,
    },
    RecursiveCall {
        cycle: Vec<String>,
    },
    MissingReturnPath {
        function: String,
    },
    UnenforcedPath {
        function: String,
    },
    ReturnInEntrypoint {
        function: String,
    },
    MissingReturnValue {
        function: String,
    },
    VoidReturnsValue {
        function: String,
    },
    RequireMessageNotString,
    UnknownFunction {
        name: String,
    },
    EntrypointCalled {
        name: String,
    },
    StaticCallsNonStatic {
        caller: String,
        callee: String,
    },
    UnusedReturnValue {
        name: String,
    },
    ArgumentCount {
        name: String,
        expected: usize,
        got: usize,
    },
    ArrayLiteralLength {
        context: ValueContext,
        expected: usize,
        got: usize,
    },
    ValueType {
        context: ValueContext,
        expected: TypeName,
        actual: TypeName,
    },
    DuplicateLiteralField {
        context: ValueContext,
        field: String,
    },
    UnknownLiteralField {
        context: ValueContext,
        field: String,
    },
    MissingLiteralField {
        context: ValueContext,
        field: String,
    },
    LoopRunsZeroTimes,
    LoopUnrollLimit {
        total: usize,
    },
    RequireConditionNotBool {
        actual: TypeName,
    },
    UntypedComparedLiterals,
    UndefinedComparison {
        op: BinaryOperator,
        left: TypeName,
        right: TypeName,
    },
    CompositeValue {
        what: &'static str,
    },
    NoReturnValue {
        name: String,
    },
    OutputRecordTxid,
    InputRecordTxid,
    LiteralAccess,
    BytewiseOperandType {
        op: BinaryOperator,
        actual: TypeName,
    },
    BytewiseLengths {
        op: BinaryOperator,
        left: usize,
        right: usize,
    },
    ConcatenateNonBytes {
        side: &'static str,
        actual: TypeName,
    },
    OperandType {
        op: BinaryOperator,
        actual: TypeName,
        expected: TypeName,
    },
    DivisionByZero {
        op: BinaryOperator,
    },
    NegativeShift,
    UnaryOperandType {
        op: UnaryOperator,
        actual: TypeName,
        expected: TypeName,
    },
    BuiltinElementType {
        builtin: &'static str,
        value: String,
        actual: TypeName,
        expected: TypeName,
    },
    BuiltinElementCount {
        builtin: &'static str,
        got: usize,
        expected: usize,
    },
    BuiltinOperandType {
        builtin: &'static str,
        actual: TypeName,
        expected: TypeName,
    },
    OperandDomain {
        builtin: &'static str,
        operand: &'static str,
        ranges: &'static [(i128, i128)],
        value: String,
    },
    ModExpOperandSize {
        operand: &'static str,
    },
    MultisigThreshold {
        value: String,
    },
    MessageWidth {
        builtin: &'static str,
        width: usize,
    },
    ProofWidth {
        builtin: &'static str,
        width: usize,
    },
    TooManyPairs {
        pairs: usize,
    },
    InvalidCast {
        actual: TypeName,
        target: String,
    },
    TunnelIndexType {
        actual: TypeName,
    },
    TunnelPolicyNotConstant,
    TunnelPolicyEmpty,
    TunnelExceptionsWithoutAssets,
    TunnelExceptionType,
    UntypedStructLiteral,
    UnknownMember {
        name: String,
        owner: String,
        members: Vec<String>,
    },
    NotAValue {
        text: String,
    },
    UndefinedField {
        text: String,
    },
    NoSuchField {
        ty: TypeName,
        field: String,
    },
    NotAnArrayValue {
        ty: TypeName,
    },
    RuntimeContractArgument {
        name: String,
    },
    ComputedContractArgument,
    LengthOfNonArray {
        array: String,
    },
    UndefinedArray {
        array: String,
    },
    NotAnArray {
        binding: String,
    },
    IndexType {
        actual: TypeName,
    },
    /// `array` is spelled with its length, as `values[3]`.
    IndexOutOfRange {
        value: String,
        array: String,
    },
    /// An untyped expression whose error is reported elsewhere; `validate_ast` drops it.
    Reported,
    UnnamedStructLiteral {
        name: String,
    },
    InitializerType {
        name: String,
        declared: TypeName,
        actual: TypeName,
    },
    UntypedArrayLiteral {
        name: String,
    },
    StructInitializer {
        name: String,
    },
    FieldAssignmentType {
        from: TypeName,
        to: TypeName,
    },
    AssignmentTargetNotBinding,
    LoopVariableAssigned,
    UndeclaredAssignment {
        name: Path,
    },
    NamedLoopVariableAssigned {
        name: Path,
    },
    AssignmentType {
        name: Path,
        from: TypeName,
        to: TypeName,
    },
    ElementAssignmentType {
        array: Path,
        from: TypeName,
        to: TypeName,
    },
    IfConditionNotBool {
        actual: TypeName,
    },
    IterableType {
        name: String,
        actual: TypeName,
    },
    UndefinedIterable {
        name: String,
    },
    AssetGroupsIteration,
    UntypedIterableLiteral,
    ComputedIterableType {
        actual: TypeName,
    },
    LoopCountNotConstant,
    LoopRange(CompileErrorKind),
    UndefinedName {
        label: &'static str,
        name: String,
    },
    Uninitialized {
        label: &'static str,
        name: String,
    },
    GidxOutOfRange {
        value: String,
    },
    GidxNotConstant {
        text: String,
        error: ConstantError,
    },
    InputShadowsParameter {
        input: String,
        tapscript: String,
    },
    InputShadowsConstant {
        input: String,
        tapscript: String,
    },
    ParameterShadowsParameter {
        parameter: String,
        function: String,
    },
    ParameterShadowsConstant {
        parameter: String,
        function: String,
    },
    ConstructorParameterAssigned {
        name: Path,
        function: String,
    },
    ConstantAssigned {
        name: Path,
        function: String,
    },
    ShadowsBinding {
        name: String,
        function: String,
    },
    SameLoopVariables {
        function: String,
        name: String,
    },
    LoopVariableShadows {
        name: String,
        function: String,
    },
    NoSpendGroups,
    GroupWithoutLeaves {
        group: String,
    },
    EmptyArkadeAsm {
        group: String,
    },
    InvalidTypeLayout {
        group: String,
        error: CompileError,
    },
    InvalidPlaceholder {
        group: String,
    },
    EmptyLeafAsm {
        leaf: String,
        group: String,
    },
    SignatureInLeafAsm {
        leaf: String,
        group: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Declared {
    Library,
    Contract,
    Constant,
    Function,
    Tapscript,
    ConstructorParameter,
    Struct,
    Parameter,
    ReturnType,
    FunctionParameter { function: String },
    TapscriptInput { tapscript: String },
    StructField { name: String },
    Field { name: String, field: String },
    FunctionBinding { function: String },
    LoopVariable { function: String },
    LocalDeclaration { function: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueContext {
    Return { function: String },
    Binding { name: String, function: String },
    Argument { parameter: String, function: String },
    Comparison { function: String },
    Assignment { function: String },
    LoopIterable { function: String },
    AssetId,
    Operand { builtin: &'static str },
    Literal { name: String },
    Element { of: Box<ValueContext>, index: usize },
    Field { of: Box<ValueContext>, name: String },
}

impl ValidationError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            ValidationError::CannotInferType { .. }
            | ValidationError::RequireConditionNotBool { .. }
            | ValidationError::UndefinedComparison { .. }
            | ValidationError::ConcatenateNonBytes { .. } => "type",
            ValidationError::UnknownFunction { .. } => ErrorCode::UnknownFunction.id(),
            ValidationError::UndefinedName { .. } => ErrorCode::UnknownName.id(),
            ValidationError::Reported => "reported",
            _ => "validation",
        }
    }

    pub(super) fn at(self, span: Span) -> ValidationIssue {
        ValidationIssue {
            span: Some(span),
            ..self.into()
        }
    }
}

impl From<CompileErrorKind> for ValidationError {
    fn from(error: CompileErrorKind) -> Self {
        ValidationError::LoopRange(error)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::EmptyContractName => f.write_str("contract name must not be empty"),
            ValidationError::NoEntrypoint => f.write_str(
                "contract must declare at least one Arkade Script or tapscript function",
            ),
            ValidationError::ReservedFunctionName { name } => {
                write!(f, "function name '{name}' is reserved")
            }
            ValidationError::DuplicateFunction { name } => write!(
                f,
                "duplicate function name '{name}'; each function must have a unique name"
            ),
            ValidationError::DuplicateConstructorParameter { name } => {
                write!(f, "duplicate constructor parameter '{name}'")
            }
            ValidationError::DuplicateParameter { name, function } => {
                write!(f, "duplicate parameter '{name}' in function '{function}'")
            }
            ValidationError::DuplicateTapscript { name } => write!(
                f,
                "duplicate tapscript name '{name}'; each tapscript must have a unique name"
            ),
            ValidationError::ReservedConstructorParameter { name } => {
                write!(
                    f,
                    "constructor parameter '{name}' collides with a reserved name"
                )
            }
            ValidationError::ReservedTapscriptInput { tapscript, input } => write!(
                f,
                "tapscript '{tapscript}' input '{input}' collides with a reserved name"
            ),
            ValidationError::ArrayTapscriptInput {
                tapscript,
                input,
                ty,
            } => write!(
                f,
                "tapscript '{tapscript}' input '{input}' has array type '{ty}'; array witnesses \
                 are not supported in tapscript functions"
            ),
            ValidationError::StructTapscriptInput {
                tapscript,
                input,
                ty,
            } => write!(
                f,
                "tapscript '{tapscript}' input '{input}' has struct type '{ty}'; struct witnesses \
                 are not supported in tapscript functions"
            ),
            ValidationError::DuplicateTapscriptInput { input, tapscript } => {
                write!(f, "duplicate input '{input}' in tapscript '{tapscript}'")
            }
            ValidationError::UnknownAttribute { name } => write!(
                f,
                "unknown attribute '@{name}'; expected @allow, @warn, @deny or @expect"
            ),
            ValidationError::AttributeWithoutLint { name } => {
                write!(f, "@{name} needs a lint to name")
            }
            ValidationError::AttributeArguments { name } => {
                write!(f, "@{name} takes lint names, then one reason")
            }
            ValidationError::AttributeWithoutReason { name } => {
                write!(f, "@{name} needs a reason: @{name}(lint, \"why\")")
            }
            ValidationError::CannotInferType { text } => {
                write!(f, "cannot infer the type of '{text}'")
            }
            ValidationError::StructCollidesWithBuiltin { name } => {
                write!(f, "struct '{name}' collides with a built-in type")
            }
            ValidationError::DuplicateStruct { name } => {
                write!(f, "duplicate struct definition '{name}'")
            }
            ValidationError::DuplicateStructField { field, name } => {
                write!(f, "duplicate field '{field}' in struct '{name}'")
            }
            ValidationError::RecursiveStruct { cycle } => {
                write!(f, "recursive struct layout: {}", cycle.join(" -> "))
            }
            ValidationError::UnknownType { context, base } => {
                write!(f, "{context} uses unknown type '{base}'")
            }
            ValidationError::PlaceholderName { context, name } => write!(
                f,
                "{context} '{name}' uses a compiler-reserved placeholder name"
            ),
            ValidationError::ReservedName { context, name } => {
                write!(f, "{context} '{name}' uses a reserved keyword or type name")
            }
            ValidationError::UnusedTapscriptInput { input, tapscript } => {
                write!(
                    f,
                    "input '{input}' in tapscript '{tapscript}' is never used"
                )
            }
            ValidationError::UnusedParameter {
                parameter,
                function,
            } => write!(
                f,
                "parameter '{parameter}' of function '{function}' is never used"
            ),
            ValidationError::EntrypointReturnType { function } => write!(
                f,
                "Arkade Script function '{function}' cannot declare a return type"
            ),
            ValidationError::StaticReadsConstructorParameter {
                function,
                parameter,
            } => write!(
                f,
                "static function '{function}' cannot reference constructor parameter \
                 '{parameter}'"
            ),
            ValidationError::RecursiveCall { cycle } => {
                write!(f, "recursive function call: {}", cycle.join(" -> "))
            }
            ValidationError::MissingReturnPath { function } => write!(
                f,
                "private function '{function}' must return a value on every path"
            ),
            ValidationError::UnenforcedPath { function } => write!(
                f,
                "function '{function}' has a spend path with no require(); every branch must \
                 enforce at least one condition"
            ),
            ValidationError::ReturnInEntrypoint { function } => write!(
                f,
                "return is only allowed in private functions: '{function}'"
            ),
            ValidationError::MissingReturnValue { function } => {
                write!(f, "function '{function}' must return a value")
            }
            ValidationError::VoidReturnsValue { function } => {
                write!(f, "void function '{function}' cannot return a value")
            }
            ValidationError::RequireMessageNotString => {
                f.write_str("the message of require must be a string")
            }
            ValidationError::UnknownFunction { name } => write!(f, "unknown function '{name}'"),
            ValidationError::EntrypointCalled { name } => write!(
                f,
                "Arkade Script function '{name}' is an entrypoint and cannot be called"
            ),
            ValidationError::StaticCallsNonStatic { caller, callee } => write!(
                f,
                "static function '{caller}' cannot call non-static function '{callee}'"
            ),
            ValidationError::UnusedReturnValue { name } => {
                write!(f, "return value of '{name}' must be used")
            }
            ValidationError::ArgumentCount {
                name,
                expected,
                got,
            } => write!(
                f,
                "function '{name}' expects {expected} arguments, got {got}"
            ),
            ValidationError::ArrayLiteralLength {
                context,
                expected,
                got,
            } => write!(
                f,
                "{context}: expected {expected} array elements, got {got}"
            ),
            ValidationError::ValueType {
                context,
                expected,
                actual,
            } => write!(f, "{context}: expected '{expected}', got '{actual}'"),
            ValidationError::DuplicateLiteralField { context, field } => {
                write!(f, "{context}: duplicate field '{field}'")
            }
            ValidationError::UnknownLiteralField { context, field } => {
                write!(f, "{context}: unknown field '{field}'")
            }
            ValidationError::MissingLiteralField { context, field } => {
                write!(f, "{context}: missing field '{field}'")
            }
            ValidationError::LoopRunsZeroTimes => f.write_str(
                "loop runs zero times, so its body never executes; remove the loop or make it \
                 run at least once",
            ),
            ValidationError::LoopUnrollLimit { total } => write!(
                f,
                "loop unrolls {total} iterations, nested loops and called helpers included, \
                 above the limit of {MAX_LOOP_ITERATIONS}"
            ),
            ValidationError::RequireConditionNotBool { actual } => {
                write!(f, "require condition has type '{actual}', expected bool")
            }
            ValidationError::UntypedComparedLiterals => f.write_str(
                "cannot determine the type of compared literals; declare one with a type first",
            ),
            ValidationError::UndefinedComparison { op, left, right } => write!(
                f,
                "comparison '{op}' is not defined between '{left}' and '{right}'"
            ),
            ValidationError::CompositeValue { what } => write!(
                f,
                "{what} expressions are composite values and cannot be used here"
            ),
            ValidationError::NoReturnValue { name } => {
                write!(f, "function '{name}' does not return a value")
            }
            ValidationError::OutputRecordTxid => {
                f.write_str("asset group output records have no txid")
            }
            ValidationError::InputRecordTxid => f.write_str(
                "asset group input records have no txid; read it with g.inputs[j].txid, which \
                 fails the spend on a local input",
            ),
            ValidationError::LiteralAccess => f.write_str(
                "cannot read a field or element of a literal; declare it with a type first",
            ),
            ValidationError::BytewiseOperandType { op, actual } => write!(
                f,
                "bytewise '{op}' operand has type '{actual}', expected 'bytes'"
            ),
            ValidationError::BytewiseLengths { op, left, right } => write!(
                f,
                "bytewise '{op}' operands must have equal lengths, got {left} and {right} bytes"
            ),
            ValidationError::ConcatenateNonBytes { side, actual } => {
                let hint = match actual.to_string().as_str() {
                    "int" => {
                        "convert it explicitly with bytes(value) for minimal Script-number \
                         encoding or int2bytes(value, width) for fixed-width encoding"
                    }
                    "bool" => {
                        "convert it explicitly with bytes(value) for minimal Script-number encoding"
                    }
                    _ => "both operands must be bytes-like",
                };
                write!(
                    f,
                    "cannot concatenate bytes with the {side} `{actual}` operand of `+`; {hint}"
                )
            }
            ValidationError::OperandType {
                op,
                actual,
                expected,
            } => {
                let kind = match op.class() {
                    OperatorClass::Logical => "logical",
                    OperatorClass::Shift => "shift",
                    _ => "arithmetic",
                };
                write!(
                    f,
                    "{kind} '{op}' operand has type '{actual}', expected '{expected}'"
                )
            }
            ValidationError::DivisionByZero { op } => {
                let what = if *op == BinaryOperator::Rem {
                    "modulo"
                } else {
                    "division"
                };
                write!(f, "{what} by zero")
            }
            ValidationError::NegativeShift => f.write_str("shift count must not be negative"),
            ValidationError::UnaryOperandType {
                op,
                actual,
                expected,
            } => write!(
                f,
                "unary '{}' operand has type '{actual}', expected '{expected}'",
                op.symbol()
            ),
            ValidationError::BuiltinElementType {
                builtin,
                value,
                actual,
                expected,
            } => write!(
                f,
                "{builtin} '{value}' has type '{actual}', expected '{expected}'"
            ),
            ValidationError::BuiltinElementCount {
                builtin,
                got,
                expected,
            } => write!(
                f,
                "{builtin} operand has {got} elements, expected {expected}"
            ),
            ValidationError::BuiltinOperandType {
                builtin,
                actual,
                expected,
            } => write!(
                f,
                "{builtin} operand has type '{actual}', expected '{expected}'"
            ),
            ValidationError::OperandDomain {
                builtin,
                operand,
                ranges,
                value,
            } => {
                write!(f, "{builtin} {operand} must be ")?;
                for (index, range) in ranges.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" or ")?;
                    }
                    match *range {
                        (low, i128::MAX) => write!(f, "at least {low}")?,
                        (low, high) if low == high => write!(f, "{low}")?,
                        (low, high) => write!(f, "{low} to {high}")?,
                    }
                }
                write!(f, ", got {value}")
            }
            ValidationError::ModExpOperandSize { operand } => {
                write!(f, "modExp {operand} must fit in 64 Script-number bytes")
            }
            ValidationError::MultisigThreshold { value } => write!(
                f,
                "checkMultisig threshold must be between 1 and the number of public keys, got \
                 {value}"
            ),
            ValidationError::MessageWidth { builtin, width } => {
                write!(f, "{builtin} message must be 32 bytes, got {width}")
            }
            ValidationError::ProofWidth { builtin, width } => write!(
                f,
                "{builtin} proof must be a multiple of 32 bytes, got {width}"
            ),
            ValidationError::TooManyPairs { pairs } => {
                write!(f, "ecPairing supports at most 16 pairs, got {pairs}")
            }
            ValidationError::InvalidCast { actual, target } => {
                let hint = match target.as_str() {
                    "int" => {
                        "only bool converts to int; use int(0x..) for a hex constant or bytes2int \
                         for bytes"
                    }
                    "bool" => "only int converts to bool",
                    "bytes" => "only int, bool or bytes-like values convert to bytes",
                    _ => "only bytes can be cast",
                };
                write!(f, "cannot cast '{actual}' to '{target}'; {hint}")
            }
            ValidationError::TunnelIndexType { actual } => {
                write!(f, "tunnel output index must be int, got '{actual}'")
            }
            ValidationError::TunnelPolicyNotConstant => {
                f.write_str("tunnel policy fields must be compile-time bool constants")
            }
            ValidationError::TunnelPolicyEmpty => {
                f.write_str("tunnel policy must preserve at least one property")
            }
            ValidationError::TunnelExceptionsWithoutAssets => {
                f.write_str("tunnel exceptions require asset preservation")
            }
            ValidationError::TunnelExceptionType => {
                f.write_str("tunnel exceptions must be AssetId values")
            }
            ValidationError::UntypedStructLiteral => {
                f.write_str("struct literals may only initialize typed struct declarations")
            }
            ValidationError::UnknownMember {
                name,
                owner,
                members,
            } => {
                write!(f, "unknown member '{name}' of '{owner}'")?;
                if !members.is_empty() {
                    write!(f, "; expected one of {}", members.join(", "))?;
                }
                Ok(())
            }
            ValidationError::NotAValue { text } => write!(f, "'{text}' is not a value on its own"),
            ValidationError::UndefinedField { text } => write!(f, "field '{text}' is undefined"),
            ValidationError::NoSuchField { ty, field } => {
                write!(f, "value of type '{ty}' has no field '{field}'")
            }
            ValidationError::NotAnArrayValue { ty } => {
                write!(f, "value of type '{ty}' is not an array")
            }
            ValidationError::RuntimeContractArgument { name } => write!(
                f,
                "contract instance argument '{name}' is a runtime value; only constructor \
                 parameters and literals are supported"
            ),
            ValidationError::ComputedContractArgument => {
                f.write_str("computed contract arguments are not supported")
            }
            ValidationError::LengthOfNonArray { array } => {
                write!(f, "'{array}' is not an array; '.length' is undefined")
            }
            ValidationError::UndefinedArray { array } => write!(f, "array '{array}' is undefined"),
            ValidationError::NotAnArray { binding } => {
                write!(f, "binding '{binding}' is not an array")
            }
            ValidationError::IndexType { actual } => {
                write!(f, "array index has type '{actual}', expected 'int'")
            }
            ValidationError::IndexOutOfRange { value, array } => {
                write!(f, "array index '{value}' is out of range for '{array}'")
            }
            ValidationError::Reported => Ok(()),
            ValidationError::UnnamedStructLiteral { name } => write!(
                f,
                "struct literal needs a struct type; name it, as in 'let {name} = Name {{ field: \
                 value }};'"
            ),
            ValidationError::InitializerType {
                name,
                declared,
                actual,
            } => write!(
                f,
                "binding '{name}' declares type '{declared}' but initializer has type '{actual}'"
            ),
            ValidationError::UntypedArrayLiteral { name } => write!(
                f,
                "array literal needs a declared array type, as in 'int[2] {name} = …'"
            ),
            ValidationError::StructInitializer { name } => write!(
                f,
                "struct binding '{name}' must be initialized with a matching struct value"
            ),
            ValidationError::FieldAssignmentType { from, to } => write!(
                f,
                "assignment to an indexed field changes its type from '{from}' to '{to}'"
            ),
            ValidationError::AssignmentTargetNotBinding => {
                f.write_str("assignment target is not a binding")
            }
            ValidationError::LoopVariableAssigned => {
                f.write_str("cannot assign to compile-time loop variable")
            }
            ValidationError::UndeclaredAssignment { name } => {
                write!(f, "assignment to undeclared variable '{name}'")
            }
            ValidationError::NamedLoopVariableAssigned { name } => {
                write!(f, "cannot assign to compile-time loop variable '{name}'")
            }
            ValidationError::AssignmentType { name, from, to } => write!(
                f,
                "assignment to '{name}' changes its type from '{from}' to '{to}'"
            ),
            ValidationError::ElementAssignmentType { array, from, to } => write!(
                f,
                "assignment to an element of '{array}' changes its type from '{from}' to '{to}'"
            ),
            ValidationError::IfConditionNotBool { actual } => write!(
                f,
                "if condition has type '{actual}', expected bool; use an explicit comparison"
            ),
            ValidationError::IterableType { name, actual } => {
                write!(
                    f,
                    "loop iterable '{name}' has type '{actual}', expected array"
                )
            }
            ValidationError::UndefinedIterable { name } => {
                write!(f, "loop iterable '{name}' is undefined")
            }
            ValidationError::AssetGroupsIteration => f.write_str(
                "cannot iterate 'tx.assetGroups'; the group count is not known at compile time. \
                 Iterate a declared array of group indices instead",
            ),
            ValidationError::UntypedIterableLiteral => f.write_str(
                "cannot infer the element type of the loop's array literal; iterate a typed \
                 array, as in 'T[n] items = …'",
            ),
            ValidationError::ComputedIterableType { actual } => {
                write!(f, "loop iterable has type '{actual}', expected array")
            }
            ValidationError::LoopCountNotConstant => {
                f.write_str("loop count must be a non-negative integer compile-time constant")
            }
            ValidationError::LoopRange(error) => error.fmt(f),
            ValidationError::UndefinedName { label, name } => {
                write!(f, "{label} '{name}' is undefined")
            }
            ValidationError::Uninitialized { label, name } => write!(
                f,
                "{label} '{name}' may be uninitialized; assign it a value before use (initialize \
                 arrays and structs as a whole)"
            ),
            ValidationError::GidxOutOfRange { value } => {
                write!(f, "asset id gidx {value} is out of range 0..65535")
            }
            ValidationError::GidxNotConstant { text, error } => {
                write!(f, "asset id gidx '{text}': {error}")
            }
            ValidationError::InputShadowsParameter { input, tapscript } => write!(
                f,
                "input '{input}' in tapscript '{tapscript}' shadows constructor parameter \
                 '{input}'"
            ),
            ValidationError::InputShadowsConstant { input, tapscript } => write!(
                f,
                "input '{input}' in tapscript '{tapscript}' shadows constant '{input}'"
            ),
            ValidationError::ParameterShadowsParameter {
                parameter,
                function,
            } => write!(
                f,
                "parameter '{parameter}' in function '{function}' shadows constructor parameter \
                 '{parameter}'"
            ),
            ValidationError::ParameterShadowsConstant {
                parameter,
                function,
            } => write!(
                f,
                "parameter '{parameter}' in function '{function}' shadows constant '{parameter}'"
            ),
            ValidationError::ConstructorParameterAssigned { name, function } => write!(
                f,
                "cannot assign to constructor parameter '{name}' in function '{function}'; \
                 constructor parameters are immutable"
            ),
            ValidationError::ConstantAssigned { name, function } => write!(
                f,
                "cannot assign to constant '{name}' in function '{function}'"
            ),
            ValidationError::ShadowsBinding { name, function } => write!(
                f,
                "binding '{name}' in function '{function}' shadows an in-scope binding"
            ),
            ValidationError::SameLoopVariables { function, name } => write!(
                f,
                "loop variables in function '{function}' must differ; both are named '{name}'"
            ),
            ValidationError::LoopVariableShadows { name, function } => write!(
                f,
                "loop variable '{name}' in function '{function}' shadows an in-scope binding"
            ),
            ValidationError::NoSpendGroups => f.write_str("contract produced no spend groups"),
            ValidationError::GroupWithoutLeaves { group } => {
                write!(f, "spend group '{group}' has no leaves (compiler bug)")
            }
            ValidationError::EmptyArkadeAsm { group } => {
                write!(f, "group '{group}' Arkade Script has empty asm")
            }
            ValidationError::InvalidTypeLayout { group, error } => {
                write!(f, "group '{group}' has an invalid type layout: {error}")
            }
            ValidationError::InvalidPlaceholder { group } => write!(
                f,
                "group '{group}' Arkade Script has an invalid constructor placeholder"
            ),
            ValidationError::EmptyLeafAsm { leaf, group } => {
                write!(f, "leaf '{leaf}' in group '{group}' has empty asm")
            }
            ValidationError::SignatureInLeafAsm { leaf, group } => write!(
                f,
                "leaf '{leaf}' in group '{group}' has a signature in asm (must be witness-only)"
            ),
        }
    }
}

impl error::Error for ValidationError {}

impl fmt::Display for Declared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Declared::Library => f.write_str("library"),
            Declared::Contract => f.write_str("contract"),
            Declared::Constant => f.write_str("constant"),
            Declared::Function => f.write_str("function"),
            Declared::Tapscript => f.write_str("tapscript"),
            Declared::ConstructorParameter => f.write_str("constructor parameter"),
            Declared::Struct => f.write_str("struct"),
            Declared::Parameter => f.write_str("parameter"),
            Declared::ReturnType => f.write_str("return type"),
            Declared::FunctionParameter { function } => {
                write!(f, "parameter in function '{function}'")
            }
            Declared::TapscriptInput { tapscript } => write!(f, "input in tapscript '{tapscript}'"),
            Declared::StructField { name } => write!(f, "struct '{name}' field"),
            Declared::Field { name, field } => write!(f, "field '{name}.{field}'"),
            Declared::FunctionBinding { function } => write!(f, "binding in function '{function}'"),
            Declared::LoopVariable { function } => {
                write!(f, "loop variable in function '{function}'")
            }
            Declared::LocalDeclaration { function } => {
                write!(f, "local declaration in function '{function}'")
            }
        }
    }
}

impl fmt::Display for ValueContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueContext::Return { function } => write!(f, "return from '{function}'"),
            ValueContext::Binding { name, function } => {
                write!(f, "binding '{name}' in '{function}'")
            }
            ValueContext::Argument {
                parameter,
                function,
            } => write!(f, "argument '{parameter}' to '{function}'"),
            ValueContext::Comparison { function } => write!(f, "comparison in '{function}'"),
            ValueContext::Assignment { function } => write!(f, "assignment in '{function}'"),
            ValueContext::LoopIterable { function } => {
                write!(f, "loop iterable in '{function}'")
            }
            ValueContext::AssetId => f.write_str("asset id"),
            ValueContext::Operand { builtin } => write!(f, "{builtin} operand"),
            ValueContext::Literal { name } => write!(f, "{name} literal"),
            ValueContext::Element { of, index } => write!(f, "{of}, element {index}"),
            ValueContext::Field { of, name } => write!(f, "{of}, field '{name}'"),
        }
    }
}
