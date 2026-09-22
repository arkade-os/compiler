// Numeric pushes
pub const OP_0: &str = "OP_0";
pub const OP_1: &str = "OP_1";
pub const OP_2: &str = "OP_2";
pub const OP_3: &str = "OP_3";
pub const OP_4: &str = "OP_4";
pub const OP_5: &str = "OP_5";
pub const OP_6: &str = "OP_6";
pub const OP_7: &str = "OP_7";
pub const OP_8: &str = "OP_8";
pub const OP_9: &str = "OP_9";
pub const OP_10: &str = "OP_10";
pub const OP_11: &str = "OP_11";
pub const OP_12: &str = "OP_12";
pub const OP_13: &str = "OP_13";
pub const OP_14: &str = "OP_14";
pub const OP_15: &str = "OP_15";
pub const OP_16: &str = "OP_16";

// Absolute and relative timelock verification
pub const OP_CHECKLOCKTIMEVERIFY: &str = "OP_CHECKLOCKTIMEVERIFY";
pub const OP_CHECKSEQUENCEVERIFY: &str = "OP_CHECKSEQUENCEVERIFY";

// Signature verification
pub const OP_CHECKMULTISIG: &str = "OP_CHECKMULTISIG";
pub const OP_CHECKSIG: &str = "OP_CHECKSIG";
pub const OP_CHECKSIGVERIFY: &str = "OP_CHECKSIGVERIFY";
pub const OP_CHECKSIGFROMSTACK: &str = "OP_CHECKSIGFROMSTACK";
pub const OP_CHECKSIGADD: &str = "OP_CHECKSIGADD";
pub const OP_SIGHASH: &str = "OP_SIGHASH";

// Comparisons
pub const OP_EQUAL: &str = "OP_EQUAL";
pub const OP_NUMEQUAL: &str = "OP_NUMEQUAL";
pub const OP_GREATERTHANOREQUAL: &str = "OP_GREATERTHANOREQUAL";
pub const OP_LESSTHANOREQUAL: &str = "OP_LESSTHANOREQUAL";
pub const OP_GREATERTHAN: &str = "OP_GREATERTHAN";
pub const OP_LESSTHAN: &str = "OP_LESSTHAN";

// Cryptography
pub const OP_SHA256: &str = "OP_SHA256";
pub const OP_SHA256UPDATE: &str = "OP_SHA256UPDATE";
pub const OP_SHA256INITIALIZE: &str = "OP_SHA256INITIALIZE";
pub const OP_SHA256FINALIZE: &str = "OP_SHA256FINALIZE";
pub const OP_HASH160: &str = "OP_HASH160";
pub const OP_HASH256: &str = "OP_HASH256";
pub const OP_RIPEMD160: &str = "OP_RIPEMD160";
pub const OP_DIGEST: &str = "OP_DIGEST";

// Byte-string manipulation
pub const OP_CAT: &str = "OP_CAT";

// Stack manipulation
pub const OP_DROP: &str = "OP_DROP";
pub const OP_NIP: &str = "OP_NIP";
pub const OP_SWAP: &str = "OP_SWAP";
pub const OP_TOALTSTACK: &str = "OP_TOALTSTACK";
pub const OP_FROMALTSTACK: &str = "OP_FROMALTSTACK";

// Elliptic curve
pub const OP_ECADD: &str = "OP_ECADD";
pub const OP_ECMUL: &str = "OP_ECMUL";
pub const OP_ECPAIRING: &str = "OP_ECPAIRING";
pub const OP_ECMULSCALARVERIFY: &str = "OP_ECMULSCALARVERIFY";
pub const OP_TWEAKVERIFY: &str = "OP_TWEAKVERIFY";

// Conditionals
pub const OP_BOOLAND: &str = "OP_BOOLAND";
pub const OP_NOT: &str = "OP_NOT";
pub const OP_FALSE: &str = "OP_FALSE";
pub const OP_IF: &str = "OP_IF";
pub const OP_ENDIF: &str = "OP_ENDIF";
pub const OP_ELSE: &str = "OP_ELSE";

// Condition verification
pub const OP_VERIFY: &str = "OP_VERIFY";

// Arithmetic (BigNum)
pub const OP_1ADD: &str = "OP_1ADD";
pub const OP_1SUB: &str = "OP_1SUB";
pub const OP_NEGATE: &str = "OP_NEGATE";
pub const OP_ABS: &str = "OP_ABS";
pub const OP_0NOTEQUAL: &str = "OP_0NOTEQUAL";
pub const OP_ADD: &str = "OP_ADD";
pub const OP_SUB: &str = "OP_SUB";
pub const OP_MUL: &str = "OP_MUL";
pub const OP_DIV: &str = "OP_DIV";
pub const OP_MOD: &str = "OP_MOD";
pub const OP_LSHIFT: &str = "OP_LSHIFT";
pub const OP_RSHIFT: &str = "OP_RSHIFT";
pub const OP_2MUL: &str = "OP_2MUL";
pub const OP_2DIV: &str = "OP_2DIV";
pub const OP_MIN: &str = "OP_MIN";
pub const OP_MAX: &str = "OP_MAX";
pub const OP_MODEXP: &str = "OP_MODEXP";

// Verify variants
pub const OP_EQUALVERIFY: &str = "OP_EQUALVERIFY";
pub const OP_NUMEQUALVERIFY: &str = "OP_NUMEQUALVERIFY";
pub const OP_NUMNOTEQUAL: &str = "OP_NUMNOTEQUAL";
pub const OP_BOOLOR: &str = "OP_BOOLOR";

// Stack manipulation (extended)
pub const OP_1NEGATE: &str = "OP_1NEGATE";
pub const OP_DUP: &str = "OP_DUP";
pub const OP_ROT: &str = "OP_ROT";
pub const OP_OVER: &str = "OP_OVER";
pub const OP_PICK: &str = "OP_PICK";
pub const OP_PUT: &str = "OP_PUT";
pub const OP_ROLL: &str = "OP_ROLL";
pub const OP_TUCK: &str = "OP_TUCK";
pub const OP_IFDUP: &str = "OP_IFDUP";
pub const OP_DEPTH: &str = "OP_DEPTH";
pub const OP_2DROP: &str = "OP_2DROP";
pub const OP_2DUP: &str = "OP_2DUP";
pub const OP_3DUP: &str = "OP_3DUP";
pub const OP_2OVER: &str = "OP_2OVER";
pub const OP_2ROT: &str = "OP_2ROT";
pub const OP_2SWAP: &str = "OP_2SWAP";

// Byte-string manipulation (introspector extensions)
pub const OP_SUBSTR: &str = "OP_SUBSTR";
pub const OP_LEFT: &str = "OP_LEFT";
pub const OP_RIGHT: &str = "OP_RIGHT";
pub const OP_SIZE: &str = "OP_SIZE";

// Bitwise (introspector extensions)
pub const OP_INVERT: &str = "OP_INVERT";
pub const OP_AND: &str = "OP_AND";
pub const OP_OR: &str = "OP_OR";
pub const OP_XOR: &str = "OP_XOR";

// Numeric conversion (introspector extensions)
pub const OP_BIN2NUM: &str = "OP_BIN2NUM";
pub const OP_NUM2BIN: &str = "OP_NUM2BIN";
pub const OP_REVERSEBYTES: &str = "OP_REVERSEBYTES";

// Hashing (additional)
pub const OP_SHA1: &str = "OP_SHA1";

// Merkle proof verification (introspector extension)
pub const OP_MERKLEBRANCHVERIFY: &str = "OP_MERKLEBRANCHVERIFY";

// Introspection (transaction global)
pub const OP_TXID: &str = "OP_TXID";
pub const OP_TXWEIGHT: &str = "OP_TXWEIGHT";
pub const OP_INSPECTVERSION: &str = "OP_INSPECTVERSION";
pub const OP_INSPECTLOCKTIME: &str = "OP_INSPECTLOCKTIME";
pub const OP_INSPECTNUMINPUTS: &str = "OP_INSPECTNUMINPUTS";
pub const OP_INSPECTNUMOUTPUTS: &str = "OP_INSPECTNUMOUTPUTS";

// Introspection (input metadata)
pub const OP_PUSHCURRENTINPUTINDEX: &str = "OP_PUSHCURRENTINPUTINDEX";
pub const OP_PUSHEXPIRY: &str = "OP_PUSHEXPIRY";
pub const OP_CHECKTIME: &str = "OP_CHECKTIME";
pub const OP_TUNNEL: &str = "OP_TUNNEL";
pub const OP_INSPECTINPUTOUTPOINT: &str = "OP_INSPECTINPUTOUTPOINT";
pub const OP_INSPECTINPUTSCRIPTPUBKEY: &str = "OP_INSPECTINPUTSCRIPTPUBKEY";
pub const OP_INSPECTINPUTVALUE: &str = "OP_INSPECTINPUTVALUE";
pub const OP_INSPECTINPUTSEQUENCE: &str = "OP_INSPECTINPUTSEQUENCE";
pub const OP_INSPECTINPUTARKADESCRIPTHASH: &str = "OP_INSPECTINPUTARKADESCRIPTHASH";
pub const OP_INSPECTINPUTARKADEWITNESSHASH: &str = "OP_INSPECTINPUTARKADEWITNESSHASH";

// Introspection (output metadata)
pub const OP_INSPECTOUTPUTVALUE: &str = "OP_INSPECTOUTPUTVALUE";
pub const OP_INSPECTOUTPUTSCRIPTPUBKEY: &str = "OP_INSPECTOUTPUTSCRIPTPUBKEY";

// Introspection (packet)
pub const OP_INSPECTPACKET: &str = "OP_INSPECTPACKET";
pub const OP_INSPECTINTENTMESSAGE: &str = "OP_INSPECTINTENTMESSAGE";
pub const OP_INSPECTINPUTPACKET: &str = "OP_INSPECTINPUTPACKET";

// Introspection (asset groups)
pub const OP_INSPECTASSETGROUP: &str = "OP_INSPECTASSETGROUP";
pub const OP_INSPECTASSETGROUPNUM: &str = "OP_INSPECTASSETGROUPNUM";
pub const OP_INSPECTASSETGROUPSUM: &str = "OP_INSPECTASSETGROUPSUM";
pub const OP_INSPECTNUMASSETGROUPS: &str = "OP_INSPECTNUMASSETGROUPS";
pub const OP_FINDASSETGROUPBYASSETID: &str = "OP_FINDASSETGROUPBYASSETID";
pub const OP_INSPECTASSETGROUPCTRL: &str = "OP_INSPECTASSETGROUPCTRL";
pub const OP_INSPECTASSETGROUPMETADATAHASH: &str = "OP_INSPECTASSETGROUPMETADATAHASH";
pub const OP_INSPECTASSETGROUPASSETID: &str = "OP_INSPECTASSETGROUPASSETID";

// Introspection (asset cross-input/output)
pub const OP_INSPECTINASSETLOOKUP: &str = "OP_INSPECTINASSETLOOKUP";
pub const OP_INSPECTOUTASSETLOOKUP: &str = "OP_INSPECTOUTASSETLOOKUP";
pub const OP_INSPECTINASSETCOUNT: &str = "OP_INSPECTINASSETCOUNT";
pub const OP_INSPECTOUTASSETCOUNT: &str = "OP_INSPECTOUTASSETCOUNT";
pub const OP_INSPECTINASSETAT: &str = "OP_INSPECTINASSETAT";
pub const OP_INSPECTOUTASSETAT: &str = "OP_INSPECTOUTASSETAT";

/// `Some` when `name` is an opcode this compiler emits, with the canonical spelling.
pub fn opcode(name: &str) -> Option<&'static str> {
    const OPCODES: &[&str] = &[
        OP_0,
        OP_1,
        OP_2,
        OP_3,
        OP_4,
        OP_5,
        OP_6,
        OP_7,
        OP_8,
        OP_9,
        OP_10,
        OP_11,
        OP_12,
        OP_13,
        OP_14,
        OP_15,
        OP_16,
        OP_CHECKLOCKTIMEVERIFY,
        OP_CHECKSEQUENCEVERIFY,
        OP_CHECKMULTISIG,
        OP_CHECKSIG,
        OP_CHECKSIGVERIFY,
        OP_CHECKSIGFROMSTACK,
        OP_CHECKSIGADD,
        OP_SIGHASH,
        OP_EQUAL,
        OP_NUMEQUAL,
        OP_GREATERTHANOREQUAL,
        OP_LESSTHANOREQUAL,
        OP_GREATERTHAN,
        OP_LESSTHAN,
        OP_SHA256,
        OP_SHA256UPDATE,
        OP_SHA256INITIALIZE,
        OP_SHA256FINALIZE,
        OP_HASH160,
        OP_HASH256,
        OP_RIPEMD160,
        OP_DIGEST,
        OP_CAT,
        OP_DROP,
        OP_NIP,
        OP_SWAP,
        OP_TOALTSTACK,
        OP_FROMALTSTACK,
        OP_ECADD,
        OP_ECMUL,
        OP_ECPAIRING,
        OP_ECMULSCALARVERIFY,
        OP_TWEAKVERIFY,
        OP_BOOLAND,
        OP_NOT,
        OP_FALSE,
        OP_IF,
        OP_ENDIF,
        OP_ELSE,
        OP_VERIFY,
        OP_1ADD,
        OP_1SUB,
        OP_NEGATE,
        OP_ABS,
        OP_0NOTEQUAL,
        OP_ADD,
        OP_SUB,
        OP_MUL,
        OP_DIV,
        OP_MOD,
        OP_LSHIFT,
        OP_RSHIFT,
        OP_2MUL,
        OP_2DIV,
        OP_MIN,
        OP_MAX,
        OP_MODEXP,
        OP_EQUALVERIFY,
        OP_NUMEQUALVERIFY,
        OP_NUMNOTEQUAL,
        OP_BOOLOR,
        OP_1NEGATE,
        OP_DUP,
        OP_ROT,
        OP_OVER,
        OP_PICK,
        OP_PUT,
        OP_ROLL,
        OP_TUCK,
        OP_IFDUP,
        OP_DEPTH,
        OP_2DROP,
        OP_2DUP,
        OP_3DUP,
        OP_2OVER,
        OP_2ROT,
        OP_2SWAP,
        OP_SUBSTR,
        OP_LEFT,
        OP_RIGHT,
        OP_SIZE,
        OP_INVERT,
        OP_AND,
        OP_OR,
        OP_XOR,
        OP_BIN2NUM,
        OP_NUM2BIN,
        OP_REVERSEBYTES,
        OP_SHA1,
        OP_MERKLEBRANCHVERIFY,
        OP_TXID,
        OP_TXWEIGHT,
        OP_INSPECTVERSION,
        OP_INSPECTLOCKTIME,
        OP_INSPECTNUMINPUTS,
        OP_INSPECTNUMOUTPUTS,
        OP_PUSHCURRENTINPUTINDEX,
        OP_PUSHEXPIRY,
        OP_CHECKTIME,
        OP_TUNNEL,
        OP_INSPECTINPUTOUTPOINT,
        OP_INSPECTINPUTSCRIPTPUBKEY,
        OP_INSPECTINPUTVALUE,
        OP_INSPECTINPUTSEQUENCE,
        OP_INSPECTINPUTARKADESCRIPTHASH,
        OP_INSPECTINPUTARKADEWITNESSHASH,
        OP_INSPECTOUTPUTVALUE,
        OP_INSPECTOUTPUTSCRIPTPUBKEY,
        OP_INSPECTPACKET,
        OP_INSPECTINTENTMESSAGE,
        OP_INSPECTINPUTPACKET,
        OP_INSPECTASSETGROUP,
        OP_INSPECTASSETGROUPNUM,
        OP_INSPECTASSETGROUPSUM,
        OP_INSPECTNUMASSETGROUPS,
        OP_FINDASSETGROUPBYASSETID,
        OP_INSPECTASSETGROUPCTRL,
        OP_INSPECTASSETGROUPMETADATAHASH,
        OP_INSPECTASSETGROUPASSETID,
        OP_INSPECTINASSETLOOKUP,
        OP_INSPECTOUTASSETLOOKUP,
        OP_INSPECTINASSETCOUNT,
        OP_INSPECTOUTASSETCOUNT,
        OP_INSPECTINASSETAT,
        OP_INSPECTOUTASSETAT,
    ];
    OPCODES.iter().copied().find(|op| *op == name)
}

#[cfg(test)]
mod tests {
    use super::opcode;

    #[test]
    fn opcode_table_lists_every_constant() {
        for line in include_str!("mod.rs").lines() {
            let Some(rest) = line.trim().strip_prefix("pub const OP_") else {
                continue;
            };
            let name = rest.split(':').next().unwrap().trim();
            let full = format!("OP_{name}");
            assert_eq!(opcode(&full).map(str::to_string), Some(full));
        }
    }
}
