//! What each lint finding says; the variant fixes the lint that reports it.

use std::fmt;

use super::functions::OutputIndex;
use super::Lint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FindingKind {
    UnsignedSpendPath {
        function: String,
    },
    OutputScriptUnchecked {
        function: String,
        index: OutputIndex,
    },
    OutputValueUnchecked {
        function: String,
        index: OutputIndex,
    },
    OutputsSharedAcrossInputs {
        function: String,
    },
    OracleMessageUnbound {
        function: String,
        message: String,
    },
    SignerFromWitness {
        function: String,
        key: String,
    },
    ThresholdFromWitness {
        function: String,
        threshold: String,
    },
    /// `key` is spelled as the diagnostic shows it, quoted only when it is a name.
    DuplicateMultisigKey {
        key: String,
    },
    AmbiguousHashConcat {
        hash: &'static str,
        parts: Vec<String>,
    },
    OffchainLocktime {
        function: String,
    },
    DivideBeforeMultiply,
    SelfComparison,
    UnusedParameter {
        name: String,
    },
    UnusedVariable {
        name: String,
        function: String,
    },
    RawSequence {
        tapscript: String,
        value: String,
    },
    RawLockTime {
        tapscript: String,
        value: String,
    },
    RepeatedInspection {
        whole: String,
        function: String,
        fields: &'static str,
    },
    SignatureMayFail {
        check: &'static str,
    },
    UnknownLint {
        name: String,
    },
    UnfulfilledExpectation {
        lint: Lint,
    },
}

impl FindingKind {
    pub(crate) fn lint(&self) -> Lint {
        match self {
            FindingKind::UnsignedSpendPath { .. } => Lint::UnsignedSpendPath,
            FindingKind::OutputScriptUnchecked { .. } => Lint::OutputScriptUnchecked,
            FindingKind::OutputValueUnchecked { .. } => Lint::OutputValueUnchecked,
            FindingKind::OutputsSharedAcrossInputs { .. } => Lint::OutputsSharedAcrossInputs,
            FindingKind::OracleMessageUnbound { .. } => Lint::OracleMessageUnbound,
            FindingKind::SignerFromWitness { .. } | FindingKind::ThresholdFromWitness { .. } => {
                Lint::SignerFromWitness
            }
            FindingKind::DuplicateMultisigKey { .. } => Lint::DuplicateMultisigKey,
            FindingKind::AmbiguousHashConcat { .. } => Lint::AmbiguousHashConcat,
            FindingKind::OffchainLocktime { .. } => Lint::OffchainLocktime,
            FindingKind::DivideBeforeMultiply => Lint::DivideBeforeMultiply,
            FindingKind::SelfComparison => Lint::SelfComparison,
            FindingKind::UnusedParameter { .. } => Lint::UnusedParameter,
            FindingKind::UnusedVariable { .. } => Lint::UnusedVariable,
            FindingKind::RawSequence { .. } | FindingKind::RawLockTime { .. } => {
                Lint::TimelockWithoutUnit
            }
            FindingKind::RepeatedInspection { .. } => Lint::RepeatedInspection,
            FindingKind::SignatureMayFail { .. } => Lint::SignatureMayFail,
            FindingKind::UnknownLint { .. } => Lint::UnknownLint,
            FindingKind::UnfulfilledExpectation { .. } => Lint::UnfulfilledExpectation,
        }
    }
}

impl fmt::Display for FindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingKind::UnsignedSpendPath { function } => write!(
                f,
                "function '{function}' has a spending path with no transaction signature, so its \
                 other conditions alone authorize the spend"
            ),
            FindingKind::OutputScriptUnchecked { function, index } => write!(
                f,
                "function '{function}' checks the value of tx.outputs[{index}] but not its \
                 scriptPubKey, so that value can be paid to any script"
            ),
            FindingKind::OutputValueUnchecked { function, index } => write!(
                f,
                "function '{function}' checks the scriptPubKey of tx.outputs[{index}] but not \
                 its value or assets, so it can receive a dust amount while the rest goes \
                 elsewhere"
            ),
            FindingKind::OutputsSharedAcrossInputs { function } => write!(
                f,
                "function '{function}' constrains outputs by index without bounding tx.numInputs \
                 or the active input, so two inputs locked by this contract can be satisfied by \
                 the same outputs"
            ),
            FindingKind::OracleMessageUnbound { function, message } => write!(
                f,
                "function '{function}' accepts a signature over the witness '{message}' as \
                 given, so one signed message authorizes any spend; derive the message from what \
                 the spend must match, such as its outputs or tx.input.current.outpoint"
            ),
            FindingKind::SignerFromWitness { function, key } => write!(
                f,
                "function '{function}' takes '{key}' from the witness and checks a signature \
                 against it, so the spender chooses who must sign; use a constructor parameter, \
                 or bind it, for example with hash160({key}) == hash"
            ),
            FindingKind::ThresholdFromWitness {
                function,
                threshold,
            } => write!(
                f,
                "function '{function}' takes the multisig threshold '{threshold}' from the \
                 witness, so the spender chooses how many must sign; use a constructor parameter"
            ),
            FindingKind::DuplicateMultisigKey { key } => write!(
                f,
                "checkMultisig lists {key} more than once, so its one signature counts for each"
            ),
            FindingKind::AmbiguousHashConcat { hash, parts } => write!(
                f,
                "{hash} hashes {} joined together, which vary in length, so other values joined \
                 the same way can give the same bytes; give them a fixed length, such as bytes32",
                parts.join(" + ")
            ),
            FindingKind::OffchainLocktime { function } => write!(
                f,
                "function '{function}' reads tx.locktime, which the operator sets to 0 when it \
                 rebuilds an offchain spend; use checkTime(t) for time"
            ),
            FindingKind::DivideBeforeMultiply => f.write_str(
                "this divides before it multiplies, so the remainder is lost before it is \
                 scaled; multiply first",
            ),
            FindingKind::SelfComparison => f.write_str(
                "both sides of this comparison are the same, so its result never depends on them",
            ),
            FindingKind::UnusedParameter { name } => {
                write!(f, "constructor parameter '{name}' is never used")
            }
            FindingKind::UnusedVariable { name, function } => {
                write!(
                    f,
                    "variable '{name}' in function '{function}' is never used"
                )
            }
            FindingKind::RawSequence { tapscript, value } => write!(
                f,
                "tapscript '{tapscript}': older({value}) is a raw BIP68 sequence; write \
                 blocks(n) or seconds(n) to state its unit"
            ),
            FindingKind::RawLockTime { tapscript, value } => write!(
                f,
                "tapscript '{tapscript}': after({value}) is a raw nLockTime; write blocks(n) or \
                 seconds(n) to state its unit"
            ),
            FindingKind::RepeatedInspection {
                whole,
                function,
                fields,
            } => write!(
                f,
                "`{whole}` is inspected more than once in function '{function}'; bind `let x = \
                 {whole};` once and read {fields}"
            ),
            FindingKind::SignatureMayFail { check } => write!(
                f,
                "{check} fails the spend on an invalid non-empty signature instead of returning \
                 false; pass an empty signature where the check may fail"
            ),
            FindingKind::UnknownLint { name } => write!(f, "unknown lint '{name}'"),
            FindingKind::UnfulfilledExpectation { lint } => {
                write!(f, "'{}' is expected here but does not fire", lint.id())
            }
        }
    }
}
