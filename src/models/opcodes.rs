// Opcodes for Elements Taproot
// This file defines the OP_SUCCESS opcodes (196-228) for Elements Taproot

use std::fmt;

/// Represents an opcode in the Elements Taproot script language
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opcode {
    // Standard Bitcoin opcodes
    OP_0,      // Push empty array onto stack
    OP_1,      // Push 1 onto stack
    // ... other standard opcodes can be added as needed

    // Streaming SHA256 opcodes
    SHA256INITIALIZE,  // OP_SUCCESS196
    SHA256UPDATE,      // OP_SUCCESS197
    SHA256FINALIZE,    // OP_SUCCESS198

    // Transaction introspection opcodes - inputs
    INSPECTINPUTOUTPOINT,     // OP_SUCCESS199
    INSPECTINPUTASSET,        // OP_SUCCESS200
    INSPECTINPUTVALUE,        // OP_SUCCESS201
    INSPECTINPUTSCRIPTPUBKEY, // OP_SUCCESS202
    INSPECTINPUTSEQUENCE,     // OP_SUCCESS203
    INSPECTINPUTISSUANCE,     // OP_SUCCESS204
    PUSHCURRENTINPUTINDEX,    // OP_SUCCESS205

    // Transaction introspection opcodes - outputs
    INSPECTOUTPUTASSET,       // OP_SUCCESS206
    INSPECTOUTPUTVALUE,       // OP_SUCCESS207
    INSPECTOUTPUTNONCE,       // OP_SUCCESS208
    INSPECTOUTPUTSCRIPTPUBKEY,// OP_SUCCESS209

    // Transaction introspection opcodes - transaction
    INSPECTVERSION,           // OP_SUCCESS210
    INSPECTLOCKTIME,          // OP_SUCCESS211
    INSPECTNUMINPUTS,         // OP_SUCCESS212
    INSPECTNUMOUTPUTS,        // OP_SUCCESS213
    TXWEIGHT,                 // OP_SUCCESS214

    // 64-bit arithmetic opcodes
    ADD64,                    // OP_SUCCESS215
    SUB64,                    // OP_SUCCESS216
    MUL64,                    // OP_SUCCESS217
    DIV64,                    // OP_SUCCESS218
    NEG64,                    // OP_SUCCESS219
    LESSTHAN64,               // OP_SUCCESS220
    LESSTHANOREQUAL64,        // OP_SUCCESS221
    GREATERTHAN64,            // OP_SUCCESS222
    GREATERTHANOREQUAL64,     // OP_SUCCESS223

    // Conversion opcodes
    SCRIPTNUMTOLE64,          // OP_SUCCESS224
    LE64TOSCRIPTNUM,          // OP_SUCCESS225
    LE32TOLE64,               // OP_SUCCESS226

    // Crypto opcodes
    ECMULSCALARVERIFY,        // OP_SUCCESS227
    TWEAKVERIFY,              // OP_SUCCESS228

    // Modified existing opcodes
    CHECKSIGFROMSTACK,        // Modified for BIP340 semantics
    CHECKSIGFROMSTACKVERIFY,  // Modified for BIP340 semantics
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Standard Bitcoin opcodes
            Opcode::OP_0 => write!(f, "OP_0"),
            Opcode::OP_1 => write!(f, "OP_1"),

            // Streaming SHA256 opcodes
            Opcode::SHA256INITIALIZE => write!(f, "OP_SHA256INITIALIZE"),
            Opcode::SHA256UPDATE => write!(f, "OP_SHA256UPDATE"),
            Opcode::SHA256FINALIZE => write!(f, "OP_SHA256FINALIZE"),

            // Transaction introspection opcodes - inputs
            Opcode::INSPECTINPUTOUTPOINT => write!(f, "OP_INSPECTINPUTOUTPOINT"),
            Opcode::INSPECTINPUTASSET => write!(f, "OP_INSPECTINPUTASSET"),
            Opcode::INSPECTINPUTVALUE => write!(f, "OP_INSPECTINPUTVALUE"),
            Opcode::INSPECTINPUTSCRIPTPUBKEY => write!(f, "OP_INSPECTINPUTSCRIPTPUBKEY"),
            Opcode::INSPECTINPUTSEQUENCE => write!(f, "OP_INSPECTINPUTSEQUENCE"),
            Opcode::INSPECTINPUTISSUANCE => write!(f, "OP_INSPECTINPUTISSUANCE"),
            Opcode::PUSHCURRENTINPUTINDEX => write!(f, "OP_PUSHCURRENTINPUTINDEX"),

            // Transaction introspection opcodes - outputs
            Opcode::INSPECTOUTPUTASSET => write!(f, "OP_INSPECTOUTPUTASSET"),
            Opcode::INSPECTOUTPUTVALUE => write!(f, "OP_INSPECTOUTPUTVALUE"),
            Opcode::INSPECTOUTPUTNONCE => write!(f, "OP_INSPECTOUTPUTNONCE"),
            Opcode::INSPECTOUTPUTSCRIPTPUBKEY => write!(f, "OP_INSPECTOUTPUTSCRIPTPUBKEY"),

            // Transaction introspection opcodes - transaction
            Opcode::INSPECTVERSION => write!(f, "OP_INSPECTVERSION"),
            Opcode::INSPECTLOCKTIME => write!(f, "OP_INSPECTLOCKTIME"),
            Opcode::INSPECTNUMINPUTS => write!(f, "OP_INSPECTNUMINPUTS"),
            Opcode::INSPECTNUMOUTPUTS => write!(f, "OP_INSPECTNUMOUTPUTS"),
            Opcode::TXWEIGHT => write!(f, "OP_TXWEIGHT"),

            // 64-bit arithmetic opcodes
            Opcode::ADD64 => write!(f, "OP_ADD64"),
            Opcode::SUB64 => write!(f, "OP_SUB64"),
            Opcode::MUL64 => write!(f, "OP_MUL64"),
            Opcode::DIV64 => write!(f, "OP_DIV64"),
            Opcode::NEG64 => write!(f, "OP_NEG64"),
            Opcode::LESSTHAN64 => write!(f, "OP_LESSTHAN64"),
            Opcode::LESSTHANOREQUAL64 => write!(f, "OP_LESSTHANOREQUAL64"),
            Opcode::GREATERTHAN64 => write!(f, "OP_GREATERTHAN64"),
            Opcode::GREATERTHANOREQUAL64 => write!(f, "OP_GREATERTHANOREQUAL64"),

            // Conversion opcodes
            Opcode::SCRIPTNUMTOLE64 => write!(f, "OP_SCRIPTNUMTOLE64"),
            Opcode::LE64TOSCRIPTNUM => write!(f, "OP_LE64TOSCRIPTNUM"),
            Opcode::LE32TOLE64 => write!(f, "OP_LE32TOLE64"),

            // Crypto opcodes
            Opcode::ECMULSCALARVERIFY => write!(f, "OP_ECMULSCALARVERIFY"),
            Opcode::TWEAKVERIFY => write!(f, "OP_TWEAKVERIFY"),

            // Modified existing opcodes
            Opcode::CHECKSIGFROMSTACK => write!(f, "OP_CHECKSIGFROMSTACK"),
            Opcode::CHECKSIGFROMSTACKVERIFY => write!(f, "OP_CHECKSIGFROMSTACKVERIFY"),
        }
    }
}

impl Opcode {
    /// Get the numeric value of the opcode
    pub fn value(&self) -> u8 {
        match self {
            // Standard Bitcoin opcodes
            Opcode::OP_0 => 0,
            Opcode::OP_1 => 1,

            // Streaming SHA256 opcodes
            Opcode::SHA256INITIALIZE => 196,
            Opcode::SHA256UPDATE => 197,
            Opcode::SHA256FINALIZE => 198,

            // Transaction introspection opcodes - inputs
            Opcode::INSPECTINPUTOUTPOINT => 199,
            Opcode::INSPECTINPUTASSET => 200,
            Opcode::INSPECTINPUTVALUE => 201,
            Opcode::INSPECTINPUTSCRIPTPUBKEY => 202,
            Opcode::INSPECTINPUTSEQUENCE => 203,
            Opcode::INSPECTINPUTISSUANCE => 204,
            Opcode::PUSHCURRENTINPUTINDEX => 205,

            // Transaction introspection opcodes - outputs
            Opcode::INSPECTOUTPUTASSET => 206,
            Opcode::INSPECTOUTPUTVALUE => 207,
            Opcode::INSPECTOUTPUTNONCE => 208,
            Opcode::INSPECTOUTPUTSCRIPTPUBKEY => 209,

            // Transaction introspection opcodes - transaction
            Opcode::INSPECTVERSION => 210,
            Opcode::INSPECTLOCKTIME => 211,
            Opcode::INSPECTNUMINPUTS => 212,
            Opcode::INSPECTNUMOUTPUTS => 213,
            Opcode::TXWEIGHT => 214,

            // 64-bit arithmetic opcodes
            Opcode::ADD64 => 215,
            Opcode::SUB64 => 216,
            Opcode::MUL64 => 217,
            Opcode::DIV64 => 218,
            Opcode::NEG64 => 219,
            Opcode::LESSTHAN64 => 220,
            Opcode::LESSTHANOREQUAL64 => 221,
            Opcode::GREATERTHAN64 => 222,
            Opcode::GREATERTHANOREQUAL64 => 223,

            // Conversion opcodes
            Opcode::SCRIPTNUMTOLE64 => 224,
            Opcode::LE64TOSCRIPTNUM => 225,
            Opcode::LE32TOLE64 => 226,

            // Crypto opcodes
            Opcode::ECMULSCALARVERIFY => 227,
            Opcode::TWEAKVERIFY => 228,

            // Modified existing opcodes
            Opcode::CHECKSIGFROMSTACK => 186,
            Opcode::CHECKSIGFROMSTACKVERIFY => 187,
        }
    }

    /// Get the opcode from its numeric value
    pub fn from_value(value: u8) -> Option<Opcode> {
        match value {
            // Standard Bitcoin opcodes
            0 => Some(Opcode::OP_0),
            1 => Some(Opcode::OP_1),

            // Streaming SHA256 opcodes
            196 => Some(Opcode::SHA256INITIALIZE),
            197 => Some(Opcode::SHA256UPDATE),
            198 => Some(Opcode::SHA256FINALIZE),

            // Transaction introspection opcodes - inputs
            199 => Some(Opcode::INSPECTINPUTOUTPOINT),
            200 => Some(Opcode::INSPECTINPUTASSET),
            201 => Some(Opcode::INSPECTINPUTVALUE),
            202 => Some(Opcode::INSPECTINPUTSCRIPTPUBKEY),
            203 => Some(Opcode::INSPECTINPUTSEQUENCE),
            204 => Some(Opcode::INSPECTINPUTISSUANCE),
            205 => Some(Opcode::PUSHCURRENTINPUTINDEX),

            // Transaction introspection opcodes - outputs
            206 => Some(Opcode::INSPECTOUTPUTASSET),
            207 => Some(Opcode::INSPECTOUTPUTVALUE),
            208 => Some(Opcode::INSPECTOUTPUTNONCE),
            209 => Some(Opcode::INSPECTOUTPUTSCRIPTPUBKEY),

            // Transaction introspection opcodes - transaction
            210 => Some(Opcode::INSPECTVERSION),
            211 => Some(Opcode::INSPECTLOCKTIME),
            212 => Some(Opcode::INSPECTNUMINPUTS),
            213 => Some(Opcode::INSPECTNUMOUTPUTS),
            214 => Some(Opcode::TXWEIGHT),

            // 64-bit arithmetic opcodes
            215 => Some(Opcode::ADD64),
            216 => Some(Opcode::SUB64),
            217 => Some(Opcode::MUL64),
            218 => Some(Opcode::DIV64),
            219 => Some(Opcode::NEG64),
            220 => Some(Opcode::LESSTHAN64),
            221 => Some(Opcode::LESSTHANOREQUAL64),
            222 => Some(Opcode::GREATERTHAN64),
            223 => Some(Opcode::GREATERTHANOREQUAL64),

            // Conversion opcodes
            224 => Some(Opcode::SCRIPTNUMTOLE64),
            225 => Some(Opcode::LE64TOSCRIPTNUM),
            226 => Some(Opcode::LE32TOLE64),

            // Crypto opcodes
            227 => Some(Opcode::ECMULSCALARVERIFY),
            228 => Some(Opcode::TWEAKVERIFY),

            // Modified existing opcodes
            186 => Some(Opcode::CHECKSIGFROMSTACK),
            187 => Some(Opcode::CHECKSIGFROMSTACKVERIFY),

            // Default case for other opcodes
            _ => None,
        }
    }

    /// Check if the opcode is a crypto opcode that counts towards sigops budget
    pub fn is_sigops_opcode(&self) -> bool {
        match self {
            Opcode::ECMULSCALARVERIFY | 
            Opcode::TWEAKVERIFY | 
            Opcode::CHECKSIGFROMSTACK | 
            Opcode::CHECKSIGFROMSTACKVERIFY => true,
            _ => false,
        }
    }
} 