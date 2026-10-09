//! Script opcodes. Each one is listed once, with the items it pops and pushes; the
//! covenant generator models the stack from these.

macro_rules! opcodes {
    ($($name:ident $(=> ($pops:literal, $pushes:literal))?),* $(,)?) => {
        $(pub const $name: &str = stringify!($name);)*

        /// Items an opcode pops and pushes; `None` when that depends on an operand
        /// (`OP_PICK`, `OP_ROLL`, `OP_TUNNEL`) or the opcode is not modelled.
        pub(crate) fn stack_effect(opcode: &str) -> Option<(usize, usize)> {
            match opcode {
                $($(stringify!($name) => Some(($pops, $pushes)),)?)*
                _ => None,
            }
        }
    };
}

opcodes! {
    // Numeric pushes
    OP_0 => (0, 1),
    OP_1 => (0, 1),
    OP_2 => (0, 1),
    OP_3 => (0, 1),
    OP_4 => (0, 1),
    OP_5 => (0, 1),
    OP_6 => (0, 1),
    OP_7 => (0, 1),
    OP_8 => (0, 1),
    OP_9 => (0, 1),
    OP_10 => (0, 1),
    OP_11 => (0, 1),
    OP_12 => (0, 1),
    OP_13 => (0, 1),
    OP_14 => (0, 1),
    OP_15 => (0, 1),
    OP_16 => (0, 1),

    // Absolute and relative timelock verification
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,

    // Signature verification
    OP_CHECKMULTISIG,
    OP_CHECKSIG => (2, 1),
    OP_CHECKSIGVERIFY => (2, 0),
    OP_CHECKSIGFROMSTACK => (3, 1),
    OP_CHECKSIGADD => (3, 1),
    OP_SIGHASH => (1, 1),

    // Comparisons
    OP_EQUAL => (2, 1),
    OP_NUMEQUAL => (2, 1),
    OP_GREATERTHANOREQUAL => (2, 1),
    OP_LESSTHANOREQUAL => (2, 1),
    OP_GREATERTHAN => (2, 1),
    OP_LESSTHAN => (2, 1),

    // Cryptography
    OP_SHA256 => (1, 1),
    OP_SHA256UPDATE => (2, 1),
    OP_SHA256INITIALIZE => (1, 1),
    OP_SHA256FINALIZE => (2, 1),
    OP_HASH160 => (1, 1),
    OP_HASH256 => (1, 1),
    OP_RIPEMD160 => (1, 1),
    OP_DIGEST => (2, 1),

    // Byte-string manipulation
    OP_CAT => (2, 1),

    // Stack manipulation
    OP_DROP => (1, 0),
    OP_NIP => (2, 1),
    OP_SWAP => (2, 2),
    OP_TOALTSTACK,
    OP_FROMALTSTACK,

    // Elliptic curve
    OP_ECADD => (5, 2),
    OP_ECMUL => (4, 2),
    OP_ECPAIRING,
    OP_ECMULSCALARVERIFY => (3, 0),
    OP_TWEAKVERIFY => (3, 0),

    // Conditionals
    OP_BOOLAND => (2, 1),
    OP_NOT => (1, 1),
    OP_FALSE,
    OP_IF,
    OP_ENDIF,
    OP_ELSE,

    // Condition verification
    OP_VERIFY => (1, 0),

    // Arithmetic (BigNum)
    OP_1ADD => (1, 1),
    OP_1SUB,
    OP_NEGATE => (1, 1),
    OP_ABS => (1, 1),
    OP_0NOTEQUAL => (1, 1),
    OP_ADD => (2, 1),
    OP_SUB => (2, 1),
    OP_MUL => (2, 1),
    OP_DIV => (2, 1),
    OP_MOD => (2, 1),
    OP_LSHIFT => (2, 1),
    OP_RSHIFT => (2, 1),
    OP_2MUL,
    OP_2DIV,
    OP_MIN => (2, 1),
    OP_MAX => (2, 1),
    OP_WITHIN => (3, 1),
    OP_MODEXP => (3, 1),

    // Verify variants
    OP_EQUALVERIFY => (2, 0),
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_BOOLOR,

    // Stack manipulation (extended)
    OP_1NEGATE,
    OP_DUP => (1, 2),
    OP_ROT => (3, 3),
    OP_OVER => (2, 3),
    OP_PICK,
    OP_PUT,
    OP_ROLL,
    OP_TUCK,
    OP_IFDUP,
    OP_DEPTH,
    OP_2DROP => (2, 0),
    OP_2DUP,
    OP_3DUP,
    OP_2OVER,
    OP_2ROT,
    OP_2SWAP,

    // Byte-string manipulation (introspector extensions)
    OP_SUBSTR => (3, 1),
    OP_LEFT => (2, 1),
    OP_RIGHT => (2, 1),
    OP_SIZE => (1, 2),

    // Bitwise (introspector extensions)
    OP_INVERT => (1, 1),
    OP_AND => (2, 1),
    OP_OR => (2, 1),
    OP_XOR => (2, 1),

    // Numeric conversion (introspector extensions)
    OP_BIN2NUM => (1, 1),
    OP_NUM2BIN => (2, 1),
    OP_REVERSEBYTES => (1, 1),

    // Hashing (additional)
    OP_SHA1 => (1, 1),

    // Merkle proof verification (introspector extension)
    OP_MERKLEBRANCHVERIFY => (4, 1),

    // Introspection (transaction global)
    OP_TXID => (0, 1),
    OP_TXWEIGHT => (0, 1),
    OP_INSPECTVERSION => (0, 1),
    OP_INSPECTLOCKTIME => (0, 1),
    OP_INSPECTNUMINPUTS => (0, 1),
    OP_INSPECTNUMOUTPUTS => (0, 1),

    // Introspection (input metadata)
    OP_PUSHCURRENTINPUTINDEX => (0, 1),
    OP_PUSHEXPIRY => (0, 1),
    OP_CHECKTIME => (1, 1),
    OP_TUNNEL,
    OP_INSPECTINPUTOUTPOINT => (1, 2),
    OP_INSPECTINPUTSCRIPTPUBKEY => (1, 2),
    OP_INSPECTINPUTVALUE => (1, 1),
    OP_INSPECTINPUTSEQUENCE => (1, 1),
    OP_INSPECTINPUTARKADESCRIPTHASH => (1, 1),
    OP_INSPECTINPUTARKADEWITNESSHASH => (1, 1),

    // Introspection (output metadata)
    OP_INSPECTOUTPUTVALUE => (1, 1),
    OP_INSPECTOUTPUTSCRIPTPUBKEY => (1, 2),

    // Introspection (packet)
    OP_INSPECTPACKET => (1, 2),
    OP_INSPECTINTENTMESSAGE => (1, 2),
    OP_INSPECTINPUTPACKET => (2, 2),

    // Introspection (asset groups)
    OP_INSPECTASSETGROUP => (3, 3),
    OP_INSPECTASSETGROUPNUM => (2, 1),
    OP_INSPECTASSETGROUPSUM => (2, 1),
    OP_INSPECTNUMASSETGROUPS => (0, 1),
    OP_FINDASSETGROUPBYASSETID => (2, 2),
    OP_INSPECTASSETGROUPCTRL => (1, 3),
    OP_INSPECTASSETGROUPMETADATAHASH => (1, 1),
    OP_INSPECTASSETGROUPASSETID => (1, 2),

    // Introspection (asset cross-input/output)
    OP_INSPECTINASSETLOOKUP => (3, 2),
    OP_INSPECTOUTASSETLOOKUP => (3, 2),
    OP_INSPECTINASSETCOUNT => (1, 1),
    OP_INSPECTOUTASSETCOUNT => (1, 1),
    OP_INSPECTINASSETAT => (2, 3),
    OP_INSPECTOUTASSETAT => (2, 3),
}

#[cfg(test)]
mod tests {
    use super::stack_effect;
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
            assert!(stack_effect(opcode).is_some(), "{opcode}");
        }
    }
}
