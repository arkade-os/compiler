//! Script opcodes. Each one is listed once, with the items it pops and pushes; the
//! covenant generator models the stack from these.

macro_rules! opcodes {
    ($($variant:ident = $name:ident $(=> ($pops:literal, $pushes:literal))?),* $(,)?) => {
        $(pub const $name: &str = stringify!($name);)*

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Opcode {
            $($variant),*
        }

        impl Opcode {
            #[cfg(test)]
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),*];

            /// The assembly spelling, such as `OP_EQUAL`.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),*
                }
            }

            /// Items the opcode pops and pushes; `None` when that depends on an operand
            /// (`OP_PICK`, `OP_ROLL`, `OP_TUNNEL`) or the opcode is not modelled.
            pub(crate) fn stack_effect(self) -> Option<(usize, usize)> {
                #[allow(unreachable_patterns)]
                match self {
                    $($(Self::$variant => Some(($pops, $pushes)),)?)*
                    _ => None,
                }
            }
        }

        impl std::fmt::Display for Opcode {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

opcodes! {
    // Numeric pushes
    Int0 = OP_0 => (0, 1),
    Int1 = OP_1 => (0, 1),
    Int2 = OP_2 => (0, 1),
    Int3 = OP_3 => (0, 1),
    Int4 = OP_4 => (0, 1),
    Int5 = OP_5 => (0, 1),
    Int6 = OP_6 => (0, 1),
    Int7 = OP_7 => (0, 1),
    Int8 = OP_8 => (0, 1),
    Int9 = OP_9 => (0, 1),
    Int10 = OP_10 => (0, 1),
    Int11 = OP_11 => (0, 1),
    Int12 = OP_12 => (0, 1),
    Int13 = OP_13 => (0, 1),
    Int14 = OP_14 => (0, 1),
    Int15 = OP_15 => (0, 1),
    Int16 = OP_16 => (0, 1),

    // Absolute and relative timelock verification
    CheckLockTimeVerify = OP_CHECKLOCKTIMEVERIFY,
    CheckSequenceVerify = OP_CHECKSEQUENCEVERIFY,

    // Signature verification
    CheckMultiSig = OP_CHECKMULTISIG,
    CheckSig = OP_CHECKSIG => (2, 1),
    CheckSigVerify = OP_CHECKSIGVERIFY => (2, 0),
    CheckSigFromStack = OP_CHECKSIGFROMSTACK => (3, 1),
    CheckSigAdd = OP_CHECKSIGADD => (3, 1),
    SigHash = OP_SIGHASH => (1, 1),

    // Comparisons
    Equal = OP_EQUAL => (2, 1),
    NumEqual = OP_NUMEQUAL => (2, 1),
    GreaterThanOrEqual = OP_GREATERTHANOREQUAL => (2, 1),
    LessThanOrEqual = OP_LESSTHANOREQUAL => (2, 1),
    GreaterThan = OP_GREATERTHAN => (2, 1),
    LessThan = OP_LESSTHAN => (2, 1),

    // Cryptography
    Sha256 = OP_SHA256 => (1, 1),
    Sha256Update = OP_SHA256UPDATE => (2, 1),
    Sha256Initialize = OP_SHA256INITIALIZE => (1, 1),
    Sha256Finalize = OP_SHA256FINALIZE => (2, 1),
    Hash160 = OP_HASH160 => (1, 1),
    Hash256 = OP_HASH256 => (1, 1),
    Ripemd160 = OP_RIPEMD160 => (1, 1),
    Digest = OP_DIGEST => (2, 1),

    // Byte-string manipulation
    Cat = OP_CAT => (2, 1),

    // Stack manipulation
    Drop = OP_DROP => (1, 0),
    Nip = OP_NIP => (2, 1),
    Swap = OP_SWAP => (2, 2),
    ToAltStack = OP_TOALTSTACK,
    FromAltStack = OP_FROMALTSTACK,

    // Elliptic curve
    EcAdd = OP_ECADD => (5, 2),
    EcMul = OP_ECMUL => (4, 2),
    EcPairing = OP_ECPAIRING,
    EcMulScalarVerify = OP_ECMULSCALARVERIFY => (3, 0),
    TweakVerify = OP_TWEAKVERIFY => (3, 0),

    // Conditionals
    BoolAnd = OP_BOOLAND => (2, 1),
    Not = OP_NOT => (1, 1),
    False = OP_FALSE,
    If = OP_IF,
    EndIf = OP_ENDIF,
    Else = OP_ELSE,

    // Condition verification
    Verify = OP_VERIFY => (1, 0),

    // Arithmetic (BigNum)
    Add1 = OP_1ADD => (1, 1),
    Sub1 = OP_1SUB,
    Negate = OP_NEGATE => (1, 1),
    Abs = OP_ABS => (1, 1),
    NotEqual0 = OP_0NOTEQUAL => (1, 1),
    Add = OP_ADD => (2, 1),
    Sub = OP_SUB => (2, 1),
    Mul = OP_MUL => (2, 1),
    Div = OP_DIV => (2, 1),
    Mod = OP_MOD => (2, 1),
    LShift = OP_LSHIFT => (2, 1),
    RShift = OP_RSHIFT => (2, 1),
    Mul2 = OP_2MUL,
    Div2 = OP_2DIV,
    Min = OP_MIN => (2, 1),
    Max = OP_MAX => (2, 1),
    Within = OP_WITHIN => (3, 1),
    ModExp = OP_MODEXP => (3, 1),

    // Verify variants
    EqualVerify = OP_EQUALVERIFY => (2, 0),
    NumEqualVerify = OP_NUMEQUALVERIFY => (2, 0),
    NumNotEqual = OP_NUMNOTEQUAL,
    BoolOr = OP_BOOLOR,

    // Stack manipulation (extended)
    Negate1 = OP_1NEGATE,
    Dup = OP_DUP => (1, 2),
    Rot = OP_ROT => (3, 3),
    Over = OP_OVER => (2, 3),
    Pick = OP_PICK,
    Put = OP_PUT,
    Roll = OP_ROLL,
    Tuck = OP_TUCK,
    IfDup = OP_IFDUP,
    Depth = OP_DEPTH,
    Drop2 = OP_2DROP => (2, 0),
    Dup2 = OP_2DUP => (2, 4),
    Dup3 = OP_3DUP => (3, 6),
    Over2 = OP_2OVER => (4, 6),
    Rot2 = OP_2ROT => (6, 6),
    Swap2 = OP_2SWAP => (4, 4),

    // Byte-string manipulation (introspector extensions)
    Substr = OP_SUBSTR => (3, 1),
    Left = OP_LEFT => (2, 1),
    Right = OP_RIGHT => (2, 1),
    Size = OP_SIZE => (1, 2),

    // Bitwise (introspector extensions)
    Invert = OP_INVERT => (1, 1),
    And = OP_AND => (2, 1),
    Or = OP_OR => (2, 1),
    Xor = OP_XOR => (2, 1),

    // Numeric conversion (introspector extensions)
    Bin2Num = OP_BIN2NUM => (1, 1),
    Num2Bin = OP_NUM2BIN => (2, 1),
    ReverseBytes = OP_REVERSEBYTES => (1, 1),

    // Hashing (additional)
    Sha1 = OP_SHA1 => (1, 1),

    // Merkle proof verification (introspector extension)
    MerkleBranchVerify = OP_MERKLEBRANCHVERIFY => (4, 1),

    // Introspection (transaction global)
    Txid = OP_TXID => (0, 1),
    TxWeight = OP_TXWEIGHT => (0, 1),
    InspectVersion = OP_INSPECTVERSION => (0, 1),
    InspectLockTime = OP_INSPECTLOCKTIME => (0, 1),
    InspectNumInputs = OP_INSPECTNUMINPUTS => (0, 1),
    InspectNumOutputs = OP_INSPECTNUMOUTPUTS => (0, 1),

    // Introspection (input metadata)
    PushCurrentInputIndex = OP_PUSHCURRENTINPUTINDEX => (0, 1),
    PushExpiry = OP_PUSHEXPIRY => (0, 1),
    CheckTime = OP_CHECKTIME => (1, 1),
    Tunnel = OP_TUNNEL,
    InspectInputOutpoint = OP_INSPECTINPUTOUTPOINT => (1, 2),
    InspectInputScriptPubKey = OP_INSPECTINPUTSCRIPTPUBKEY => (1, 2),
    InspectInputValue = OP_INSPECTINPUTVALUE => (1, 1),
    InspectInputSequence = OP_INSPECTINPUTSEQUENCE => (1, 1),
    InspectInputArkadeScriptHash = OP_INSPECTINPUTARKADESCRIPTHASH => (1, 1),
    InspectInputArkadeWitnessHash = OP_INSPECTINPUTARKADEWITNESSHASH => (1, 1),

    // Introspection (output metadata)
    InspectOutputValue = OP_INSPECTOUTPUTVALUE => (1, 1),
    InspectOutputScriptPubKey = OP_INSPECTOUTPUTSCRIPTPUBKEY => (1, 2),

    // Introspection (packet)
    InspectPacket = OP_INSPECTPACKET => (1, 2),
    InspectIntentMessage = OP_INSPECTINTENTMESSAGE => (1, 2),
    InspectInputPacket = OP_INSPECTINPUTPACKET => (2, 2),

    // Introspection (asset groups)
    InspectAssetGroup = OP_INSPECTASSETGROUP => (3, 3),
    InspectAssetGroupNum = OP_INSPECTASSETGROUPNUM => (2, 1),
    InspectAssetGroupSum = OP_INSPECTASSETGROUPSUM => (2, 1),
    InspectNumAssetGroups = OP_INSPECTNUMASSETGROUPS => (0, 1),
    FindAssetGroupByAssetId = OP_FINDASSETGROUPBYASSETID => (2, 2),
    InspectAssetGroupCtrl = OP_INSPECTASSETGROUPCTRL => (1, 3),
    InspectAssetGroupMetadataHash = OP_INSPECTASSETGROUPMETADATAHASH => (1, 1),
    InspectAssetGroupAssetId = OP_INSPECTASSETGROUPASSETID => (1, 2),

    // Introspection (asset cross-input/output)
    InspectInAssetLookup = OP_INSPECTINASSETLOOKUP => (3, 2),
    InspectOutAssetLookup = OP_INSPECTOUTASSETLOOKUP => (3, 2),
    InspectInAssetCount = OP_INSPECTINASSETCOUNT => (1, 1),
    InspectOutAssetCount = OP_INSPECTOUTASSETCOUNT => (1, 1),
    InspectInAssetAt = OP_INSPECTINASSETAT => (2, 3),
    InspectOutAssetAt = OP_INSPECTOUTASSETAT => (2, 3),
}

#[cfg(test)]
mod tests {
    use crate::builtins::{Lowering, BUILTINS};
    use crate::operators::{BinaryOperator, UnaryOperator};

    #[test]
    fn every_table_opcode_has_a_stack_effect() {
        let builtins = BUILTINS
            .iter()
            .filter_map(|builtin| match builtin.lowering {
                Lowering::Opcodes(opcodes) => Some(opcodes),
                _ => None,
            });
        let binary = BinaryOperator::ALL.map(BinaryOperator::opcodes);
        let unary = [
            UnaryOperator::Neg,
            UnaryOperator::Not,
            UnaryOperator::Invert,
        ]
        .map(UnaryOperator::opcode);
        for opcode in builtins.chain(binary).flatten().chain(&unary) {
            assert!(opcode.stack_effect().is_some(), "{opcode}");
        }
    }
}
