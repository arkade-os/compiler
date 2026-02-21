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
pub const OP_1NEGATE: &str = "OP_1NEGATE";

// Absolute and relative timelock verification
pub const OP_CHECKLOCKTIMEVERIFY: &str = "OP_CHECKLOCKTIMEVERIFY";
pub const OP_CHECKSEQUENCEVERIFY: &str = "OP_CHECKSEQUENCEVERIFY";

// Signature verification
pub const OP_CHECKMULTISIG: &str = "OP_CHECKMULTISIG";
pub const OP_CHECKSIG: &str = "OP_CHECKSIG";
pub const OP_CHECKSIGVERIFY: &str = "OP_CHECKSIGVERIFY";
pub const OP_CHECKSIGFROMSTACK: &str = "OP_CHECKSIGFROMSTACK";
pub const OP_CHECKSIGFROMSTACKVERIFY: &str = "OP_CHECKSIGFROMSTACKVERIFY";
pub const OP_CHECKSIGADD: &str = "OP_CHECKSIGADD";

// Comparisons
pub const OP_EQUAL: &str = "OP_EQUAL";
pub const OP_GREATERTHANOREQUAL: &str = "OP_GREATERTHANOREQUAL";
pub const OP_GREATERTHANOREQUAL64: &str = "OP_GREATERTHANOREQUAL64";
pub const OP_LESSTHANOREQUAL: &str = "OP_LESSTHANOREQUAL";
pub const OP_LESSTHANOREQUAL64: &str = "OP_LESSTHANOREQUAL64";
pub const OP_GREATERTHAN: &str = "OP_GREATERTHAN";
pub const OP_GREATERTHAN64: &str = "OP_GREATERTHAN64";
pub const OP_LESSTHAN: &str = "OP_LESSTHAN";
pub const OP_LESSTHAN64: &str = "OP_LESSTHAN64";

// Cryptography
pub const OP_SHA256: &str = "OP_SHA256";
pub const OP_SHA256UPDATE: &str = "OP_SHA256UPDATE";
pub const OP_SHA256INITIALIZE: &str = "OP_SHA256INITIALIZE";
pub const OP_SHA256FINALIZE: &str = "OP_SHA256FINALIZE";

// Stack manipulation
pub const OP_DROP: &str = "OP_DROP";
pub const OP_DUP: &str = "OP_DUP";
pub const OP_NIP: &str = "OP_NIP";

// Type conversions
pub const OP_LE64TOSCRIPTNUM: &str = "OP_LE64TOSCRIPTNUM";
pub const OP_SCRIPTNUMTOLE64: &str = "OP_SCRIPTNUMTOLE64";
pub const OP_LE32TOLE64: &str = "OP_LE32TOLE64";

// Elliptic curve (secp256k1)
pub const OP_ECMULSCALARVERIFY: &str = "OP_ECMULSCALARVERIFY";
pub const OP_TWEAKVERIFY: &str = "OP_TWEAKVERIFY";

// Conditionals
pub const OP_NOT: &str = "OP_NOT";
pub const OP_FALSE: &str = "OP_FALSE";
pub const OP_IF: &str = "OP_IF";
pub const OP_ENDIF: &str = "OP_ENDIF";
pub const OP_ELSE: &str = "OP_ELSE";

// Condition verification
pub const OP_VERIFY: &str = "OP_VERIFY";

// Arithmetic
pub const OP_ADD64: &str = "OP_ADD64";
pub const OP_SUB64: &str = "OP_SUB64";
pub const OP_MUL64: &str = "OP_MUL64";
pub const OP_DIV64: &str = "OP_DIV64";
pub const OP_NEG64: &str = "OP_NEG64";

// Introspection
pub const OP_TXHASH: &str = "OP_TXHASH";
pub const OP_TXWEIGHT: &str = "OP_TXWEIGHT";
pub const OP_INSPECTASSETGROUP: &str = "OP_INSPECTASSETGROUP";
pub const OP_INSPECTASSETGROUPNUM: &str = "OP_INSPECTASSETGROUPNUM";
pub const OP_INSPECTASSETGROUPSUM: &str = "OP_INSPECTASSETGROUPSUM";
pub const OP_INSPECTNUMASSETGROUPS: &str = "OP_INSPECTNUMASSETGROUPS";
pub const OP_FINDASSETGROUPBYASSETID: &str = "OP_FINDASSETGROUPBYASSETID";
pub const OP_INSPECTASSETGROUPCTRL: &str = "OP_INSPECTASSETGROUPCTRL";
pub const OP_INSPECTASSETGROUPMETADATAHASH: &str = "OP_INSPECTASSETGROUPMETADATAHASH";
pub const OP_INSPECTASSETGROUPASSETID: &str = "OP_INSPECTASSETGROUPASSETID";
pub const OP_PUSHCURRENTINPUTINDEX: &str = "OP_PUSHCURRENTINPUTINDEX";
pub const OP_INSPECTINPUTSCRIPTPUBKEY: &str = "OP_INSPECTINPUTSCRIPTPUBKEY";
pub const OP_INSPECTINPUTVALUE: &str = "OP_INSPECTINPUTVALUE";
pub const OP_INSPECTINPUTSEQUENCE: &str = "OP_INSPECTINPUTSEQUENCE";
pub const OP_INSPECTINPUTOUTPOINT: &str = "OP_INSPECTINPUTOUTPOINT";
pub const OP_INSPECTINASSETLOOKUP: &str = "OP_INSPECTINASSETLOOKUP";
pub const OP_INSPECTOUTASSETLOOKUP: &str = "OP_INSPECTOUTASSETLOOKUP";
pub const OP_INSPECTINASSETCOUNT: &str = "OP_INSPECTINASSETCOUNT";
pub const OP_INSPECTOUTASSETCOUNT: &str = "OP_INSPECTOUTASSETCOUNT";
pub const OP_INSPECTINASSETAT: &str = "OP_INSPECTINASSETAT";
pub const OP_INSPECTOUTASSETAT: &str = "OP_INSPECTOUTASSETAT";
pub const OP_INSPECTVERSION: &str = "OP_INSPECTVERSION";
pub const OP_INSPECTLOCKTIME: &str = "OP_INSPECTLOCKTIME";
pub const OP_INSPECTNUMINPUTS: &str = "OP_INSPECTNUMINPUTS";
pub const OP_INSPECTNUMOUTPUTS: &str = "OP_INSPECTNUMOUTPUTS";
pub const OP_INSPECTINPUTISSUANCE: &str = "OP_INSPECTINPUTISSUANCE";
pub const OP_INSPECTOUTPUTVALUE: &str = "OP_INSPECTOUTPUTVALUE";
pub const OP_INSPECTOUTPUTSCRIPTPUBKEY: &str = "OP_INSPECTOUTPUTSCRIPTPUBKEY";
pub const OP_INSPECTOUTPUTNONCE: &str = "OP_INSPECTOUTPUTNONCE";
pub const OP_INPUTBYTECODE: &str = "OP_INPUTBYTECODE";
pub const OP_INPUTVALUE: &str = "OP_INPUTVALUE";
pub const OP_INPUTSEQUENCE: &str = "OP_INPUTSEQUENCE";
pub const OP_INPUTOUTPOINT: &str = "OP_INPUTOUTPOINT";
