// Implementation of OP_SUCCESS opcodes (196-228) for Elements Taproot

use crate::models::Opcode;

/// Represents a script operation with an opcode and optional data
#[derive(Debug, Clone)]
pub struct ScriptOp {
    pub opcode: Opcode,
    pub data: Option<Vec<u8>>,
}

impl ScriptOp {
    /// Create a new script operation with just an opcode
    pub fn new(opcode: Opcode) -> Self {
        ScriptOp {
            opcode,
            data: None,
        }
    }

    /// Create a new script operation with an opcode and data
    pub fn with_data(opcode: Opcode, data: Vec<u8>) -> Self {
        ScriptOp {
            opcode,
            data: Some(data),
        }
    }

    /// Convert the script operation to an assembly string
    pub fn to_asm(&self) -> String {
        match &self.data {
            Some(data) => format!("{} {}", self.opcode, hex::encode(data)),
            None => format!("{}", self.opcode),
        }
    }
}

/// Streaming SHA256 opcodes implementation
pub mod sha256 {
    use super::*;

    /// Create a SHA256INITIALIZE operation
    pub fn initialize(data: Vec<u8>) -> ScriptOp {
        ScriptOp::with_data(Opcode::SHA256INITIALIZE, data)
    }

    /// Create a SHA256UPDATE operation
    pub fn update(data: Vec<u8>) -> ScriptOp {
        ScriptOp::with_data(Opcode::SHA256UPDATE, data)
    }

    /// Create a SHA256FINALIZE operation
    pub fn finalize(data: Vec<u8>) -> ScriptOp {
        ScriptOp::with_data(Opcode::SHA256FINALIZE, data)
    }

    /// Create a sequence of operations to hash data larger than 520 bytes
    pub fn hash_large_data(data: &[u8]) -> Vec<ScriptOp> {
        const CHUNK_SIZE: usize = 500; // Slightly less than 520 to be safe
        let mut ops = Vec::new();
        
        // Split the data into chunks
        let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
        
        if chunks.is_empty() {
            // Empty data case
            ops.push(initialize(Vec::new()));
            ops.push(finalize(Vec::new()));
            return ops;
        }
        
        // Initialize with the first chunk
        ops.push(initialize(chunks[0].to_vec()));
        
        // Update with middle chunks
        for chunk in chunks.iter().skip(1).take(chunks.len() - 2) {
            ops.push(update(chunk.to_vec()));
        }
        
        // Finalize with the last chunk
        if chunks.len() > 1 {
            ops.push(finalize(chunks.last().unwrap().to_vec()));
        } else {
            // Only one chunk, so we need to finalize with empty data
            ops.push(finalize(Vec::new()));
        }
        
        ops
    }
}

/// Transaction introspection opcodes implementation
pub mod tx_introspection {
    use super::*;

    /// Create an INSPECTINPUTOUTPOINT operation
    pub fn inspect_input_outpoint(input_index: i32) -> ScriptOp {
        // Convert input_index to a minimal push
        let data = input_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTINPUTOUTPOINT, data)
    }

    /// Create an INSPECTINPUTASSET operation
    pub fn inspect_input_asset(input_index: i32) -> ScriptOp {
        let data = input_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTINPUTASSET, data)
    }

    /// Create an INSPECTINPUTVALUE operation
    pub fn inspect_input_value(input_index: i32) -> ScriptOp {
        let data = input_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTINPUTVALUE, data)
    }

    /// Create an INSPECTINPUTSCRIPTPUBKEY operation
    pub fn inspect_input_scriptpubkey(input_index: i32) -> ScriptOp {
        let data = input_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTINPUTSCRIPTPUBKEY, data)
    }

    /// Create an INSPECTINPUTSEQUENCE operation
    pub fn inspect_input_sequence(input_index: i32) -> ScriptOp {
        let data = input_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTINPUTSEQUENCE, data)
    }

    /// Create an INSPECTINPUTISSUANCE operation
    pub fn inspect_input_issuance(input_index: i32) -> ScriptOp {
        let data = input_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTINPUTISSUANCE, data)
    }

    /// Create a PUSHCURRENTINPUTINDEX operation
    pub fn push_current_input_index() -> ScriptOp {
        ScriptOp::new(Opcode::PUSHCURRENTINPUTINDEX)
    }

    /// Create an INSPECTOUTPUTASSET operation
    pub fn inspect_output_asset(output_index: i32) -> ScriptOp {
        let data = output_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTOUTPUTASSET, data)
    }

    /// Create an INSPECTOUTPUTVALUE operation
    pub fn inspect_output_value(output_index: i32) -> ScriptOp {
        let data = output_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTOUTPUTVALUE, data)
    }

    /// Create an INSPECTOUTPUTNONCE operation
    pub fn inspect_output_nonce(output_index: i32) -> ScriptOp {
        let data = output_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTOUTPUTNONCE, data)
    }

    /// Create an INSPECTOUTPUTSCRIPTPUBKEY operation
    pub fn inspect_output_scriptpubkey(output_index: i32) -> ScriptOp {
        let data = output_index.to_le_bytes().to_vec();
        ScriptOp::with_data(Opcode::INSPECTOUTPUTSCRIPTPUBKEY, data)
    }

    /// Create an INSPECTVERSION operation
    pub fn inspect_version() -> ScriptOp {
        ScriptOp::new(Opcode::INSPECTVERSION)
    }

    /// Create an INSPECTLOCKTIME operation
    pub fn inspect_locktime() -> ScriptOp {
        ScriptOp::new(Opcode::INSPECTLOCKTIME)
    }

    /// Create an INSPECTNUMINPUTS operation
    pub fn inspect_num_inputs() -> ScriptOp {
        ScriptOp::new(Opcode::INSPECTNUMINPUTS)
    }

    /// Create an INSPECTNUMOUTPUTS operation
    pub fn inspect_num_outputs() -> ScriptOp {
        ScriptOp::new(Opcode::INSPECTNUMOUTPUTS)
    }

    /// Create a TXWEIGHT operation
    pub fn tx_weight() -> ScriptOp {
        ScriptOp::new(Opcode::TXWEIGHT)
    }
}

/// 64-bit arithmetic opcodes implementation
pub mod arithmetic {
    use super::*;

    /// Create an ADD64 operation
    pub fn add64() -> ScriptOp {
        ScriptOp::new(Opcode::ADD64)
    }

    /// Create a SUB64 operation
    pub fn sub64() -> ScriptOp {
        ScriptOp::new(Opcode::SUB64)
    }

    /// Create a MUL64 operation
    pub fn mul64() -> ScriptOp {
        ScriptOp::new(Opcode::MUL64)
    }

    /// Create a DIV64 operation
    pub fn div64() -> ScriptOp {
        ScriptOp::new(Opcode::DIV64)
    }

    /// Create a NEG64 operation
    pub fn neg64() -> ScriptOp {
        ScriptOp::new(Opcode::NEG64)
    }

    /// Create a LESSTHAN64 operation
    pub fn less_than64() -> ScriptOp {
        ScriptOp::new(Opcode::LESSTHAN64)
    }

    /// Create a LESSTHANOREQUAL64 operation
    pub fn less_than_or_equal64() -> ScriptOp {
        ScriptOp::new(Opcode::LESSTHANOREQUAL64)
    }

    /// Create a GREATERTHAN64 operation
    pub fn greater_than64() -> ScriptOp {
        ScriptOp::new(Opcode::GREATERTHAN64)
    }

    /// Create a GREATERTHANOREQUAL64 operation
    pub fn greater_than_or_equal64() -> ScriptOp {
        ScriptOp::new(Opcode::GREATERTHANOREQUAL64)
    }
}

/// Conversion opcodes implementation
pub mod conversion {
    use super::*;

    /// Create a SCRIPTNUMTOLE64 operation
    pub fn scriptnum_to_le64() -> ScriptOp {
        ScriptOp::new(Opcode::SCRIPTNUMTOLE64)
    }

    /// Create a LE64TOSCRIPTNUM operation
    pub fn le64_to_scriptnum() -> ScriptOp {
        ScriptOp::new(Opcode::LE64TOSCRIPTNUM)
    }

    /// Create a LE32TOLE64 operation
    pub fn le32_to_le64() -> ScriptOp {
        ScriptOp::new(Opcode::LE32TOLE64)
    }
}

/// Crypto opcodes implementation
pub mod crypto {
    use super::*;

    /// Create an ECMULSCALARVERIFY operation
    pub fn ecmulscalar_verify() -> ScriptOp {
        ScriptOp::new(Opcode::ECMULSCALARVERIFY)
    }

    /// Create a TWEAKVERIFY operation
    pub fn tweak_verify() -> ScriptOp {
        ScriptOp::new(Opcode::TWEAKVERIFY)
    }

    /// Create a CHECKSIGFROMSTACK operation
    pub fn checksig_from_stack() -> ScriptOp {
        ScriptOp::new(Opcode::CHECKSIGFROMSTACK)
    }

    /// Create a CHECKSIGFROMSTACKVERIFY operation
    pub fn checksig_from_stack_verify() -> ScriptOp {
        ScriptOp::new(Opcode::CHECKSIGFROMSTACKVERIFY)
    }
} 