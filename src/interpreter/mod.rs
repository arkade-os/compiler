use crate::models::opcodes::Opcode;
use std::collections::HashMap;

/// Result of script execution
#[derive(Debug, PartialEq)]
pub enum ExecutionResult {
    /// Script executed successfully
    Success,
    /// Script failed with error
    Failure(String),
}

/// Stack item type
#[derive(Debug, Clone)]
pub enum StackItem {
    /// Boolean value
    Bool(bool),
    /// Integer value
    Int(i64),
    /// Bytes value
    Bytes(Vec<u8>),
    /// SHA256 context for streaming operations
    Sha256Context(Vec<u8>),
}

impl StackItem {
    /// Convert stack item to boolean
    pub fn to_bool(&self) -> bool {
        match self {
            StackItem::Bool(b) => *b,
            StackItem::Int(i) => *i != 0,
            StackItem::Bytes(b) => !b.is_empty() && b.iter().any(|&x| x != 0),
            StackItem::Sha256Context(_) => true,
        }
    }

    /// Convert stack item to integer
    pub fn to_int(&self) -> Option<i64> {
        match self {
            StackItem::Bool(b) => Some(if *b { 1 } else { 0 }),
            StackItem::Int(i) => Some(*i),
            StackItem::Bytes(b) => {
                if b.len() <= 8 {
                    let mut val: i64 = 0;
                    for (i, &byte) in b.iter().enumerate() {
                        val |= (byte as i64) << (8 * i);
                    }
                    Some(val)
                } else {
                    None
                }
            },
            StackItem::Sha256Context(_) => None,
        }
    }

    /// Convert stack item to bytes
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        match self {
            StackItem::Bool(b) => Some(vec![if *b { 1 } else { 0 }]),
            StackItem::Int(i) => {
                let mut bytes = Vec::new();
                let mut val = *i;
                for _ in 0..8 {
                    bytes.push((val & 0xff) as u8);
                    val >>= 8;
                }
                Some(bytes)
            },
            StackItem::Bytes(b) => Some(b.clone()),
            StackItem::Sha256Context(c) => Some(c.clone()),
        }
    }
}

/// Script execution context
pub struct ExecutionContext {
    /// Main stack
    pub stack: Vec<StackItem>,
    /// Alt stack
    pub alt_stack: Vec<StackItem>,
    /// Transaction data
    pub tx_data: HashMap<String, StackItem>,
    /// Execution flags
    pub flags: u32,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            tx_data: HashMap::new(),
            flags: 0,
        }
    }

    /// Push item to stack
    pub fn push(&mut self, item: StackItem) {
        self.stack.push(item);
    }

    /// Pop item from stack
    pub fn pop(&mut self) -> Option<StackItem> {
        self.stack.pop()
    }

    /// Execute a single opcode
    pub fn execute_opcode(&mut self, opcode: &Opcode, data: Option<&[u8]>) -> ExecutionResult {
        match opcode {
            // Elements opcodes - Streaming SHA256
            Opcode::SHA256INITIALIZE => {
                if let Some(Some(data)) = self.pop().map(|item| item.to_bytes()) {
                    // Initialize SHA256 context with data
                    // In a real implementation, this would create a proper SHA256 context
                    self.push(StackItem::Sha256Context(data));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid data for SHA256INITIALIZE".to_string())
                }
            },
            Opcode::SHA256UPDATE => {
                if let (Some(Some(data)), Some(Some(context))) = (
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes())
                ) {
                    // Update SHA256 context with data
                    // In a real implementation, this would update the SHA256 context
                    let mut new_context = context;
                    new_context.extend_from_slice(&data);
                    self.push(StackItem::Sha256Context(new_context));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid data for SHA256UPDATE".to_string())
                }
            },
            Opcode::SHA256FINALIZE => {
                if let (Some(Some(data)), Some(Some(context))) = (
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes())
                ) {
                    // Finalize SHA256 hash
                    // In a real implementation, this would finalize the SHA256 hash
                    let mut new_context = context;
                    new_context.extend_from_slice(&data);
                    // Placeholder for actual SHA256 hash calculation
                    let hash = vec![0; 32]; // 32 bytes for SHA256
                    self.push(StackItem::Bytes(hash));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid data for SHA256FINALIZE".to_string())
                }
            },

            // Elements opcodes - Transaction Introspection - Inputs
            Opcode::INSPECTINPUTOUTPOINT => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get input outpoint
                    // In a real implementation, this would get the outpoint from the transaction
                    let outpoint = vec![0; 36]; // 32 bytes for txid + 4 bytes for vout
                    self.push(StackItem::Bytes(outpoint));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTINPUTOUTPOINT".to_string())
                }
            },
            Opcode::INSPECTINPUTASSET => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get input asset
                    // In a real implementation, this would get the asset from the transaction
                    let asset = vec![0; 32]; // 32 bytes for asset
                    self.push(StackItem::Bytes(asset));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTINPUTASSET".to_string())
                }
            },
            Opcode::INSPECTINPUTVALUE => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get input value
                    // In a real implementation, this would get the value from the transaction
                    let value = vec![0; 8]; // 8 bytes for value
                    self.push(StackItem::Bytes(value));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTINPUTVALUE".to_string())
                }
            },
            Opcode::INSPECTINPUTSCRIPTPUBKEY => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get input scriptPubKey
                    // In a real implementation, this would get the scriptPubKey from the transaction
                    let script = vec![0; 32]; // Placeholder for scriptPubKey
                    self.push(StackItem::Bytes(script));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTINPUTSCRIPTPUBKEY".to_string())
                }
            },
            Opcode::INSPECTINPUTSEQUENCE => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get input sequence
                    // In a real implementation, this would get the sequence from the transaction
                    let sequence = vec![0; 4]; // 4 bytes for sequence
                    self.push(StackItem::Bytes(sequence));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTINPUTSEQUENCE".to_string())
                }
            },
            Opcode::INSPECTINPUTISSUANCE => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get input issuance
                    // In a real implementation, this would get the issuance from the transaction
                    let issuance = vec![0; 32]; // Placeholder for issuance
                    self.push(StackItem::Bytes(issuance));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTINPUTISSUANCE".to_string())
                }
            },
            Opcode::PUSHCURRENTINPUTINDEX => {
                // Get current input index
                // In a real implementation, this would get the current input index from the transaction
                self.push(StackItem::Int(0)); // Placeholder for current input index
                ExecutionResult::Success
            },

            // Elements opcodes - Transaction Introspection - Outputs
            Opcode::INSPECTOUTPUTASSET => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get output asset
                    // In a real implementation, this would get the asset from the transaction
                    let asset = vec![0; 32]; // 32 bytes for asset
                    self.push(StackItem::Bytes(asset));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTOUTPUTASSET".to_string())
                }
            },
            Opcode::INSPECTOUTPUTVALUE => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get output value
                    // In a real implementation, this would get the value from the transaction
                    let value = vec![0; 8]; // 8 bytes for value
                    self.push(StackItem::Bytes(value));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTOUTPUTVALUE".to_string())
                }
            },
            Opcode::INSPECTOUTPUTNONCE => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get output nonce
                    // In a real implementation, this would get the nonce from the transaction
                    let nonce = vec![0; 32]; // Placeholder for nonce
                    self.push(StackItem::Bytes(nonce));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTOUTPUTNONCE".to_string())
                }
            },
            Opcode::INSPECTOUTPUTSCRIPTPUBKEY => {
                if let Some(Some(index)) = self.pop().map(|item| item.to_int()) {
                    // Get output scriptPubKey
                    // In a real implementation, this would get the scriptPubKey from the transaction
                    let script = vec![0; 32]; // Placeholder for scriptPubKey
                    self.push(StackItem::Bytes(script));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid index for INSPECTOUTPUTSCRIPTPUBKEY".to_string())
                }
            },

            // Elements opcodes - Transaction Introspection - Transaction
            Opcode::INSPECTVERSION => {
                // Get transaction version
                // In a real implementation, this would get the version from the transaction
                let version = vec![0; 4]; // 4 bytes for version
                self.push(StackItem::Bytes(version));
                ExecutionResult::Success
            },
            Opcode::INSPECTLOCKTIME => {
                // Get transaction locktime
                // In a real implementation, this would get the locktime from the transaction
                let locktime = vec![0; 4]; // 4 bytes for locktime
                self.push(StackItem::Bytes(locktime));
                ExecutionResult::Success
            },
            Opcode::INSPECTNUMINPUTS => {
                // Get number of inputs
                // In a real implementation, this would get the number of inputs from the transaction
                let num_inputs = vec![0; 4]; // 4 bytes for number of inputs
                self.push(StackItem::Bytes(num_inputs));
                ExecutionResult::Success
            },
            Opcode::INSPECTNUMOUTPUTS => {
                // Get number of outputs
                // In a real implementation, this would get the number of outputs from the transaction
                let num_outputs = vec![0; 4]; // 4 bytes for number of outputs
                self.push(StackItem::Bytes(num_outputs));
                ExecutionResult::Success
            },
            Opcode::TXWEIGHT => {
                // Get transaction weight
                // In a real implementation, this would get the weight from the transaction
                let weight = vec![0; 4]; // 4 bytes for weight
                self.push(StackItem::Bytes(weight));
                ExecutionResult::Success
            },

            // Elements opcodes - 64-bit Arithmetic
            Opcode::ADD64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Add two 64-bit integers
                    match a.checked_add(b) {
                        Some(result) => {
                            self.push(StackItem::Int(result));
                            self.push(StackItem::Bool(true)); // Success bit
                            ExecutionResult::Success
                        },
                        None => {
                            // Overflow
                            self.push(StackItem::Int(a));
                            self.push(StackItem::Int(b));
                            self.push(StackItem::Bool(false)); // Failure bit
                            ExecutionResult::Success
                        }
                    }
                } else {
                    ExecutionResult::Failure("Invalid operands for ADD64".to_string())
                }
            },
            Opcode::SUB64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Subtract two 64-bit integers
                    match a.checked_sub(b) {
                        Some(result) => {
                            self.push(StackItem::Int(result));
                            self.push(StackItem::Bool(true)); // Success bit
                            ExecutionResult::Success
                        },
                        None => {
                            // Underflow
                            self.push(StackItem::Int(a));
                            self.push(StackItem::Int(b));
                            self.push(StackItem::Bool(false)); // Failure bit
                            ExecutionResult::Success
                        }
                    }
                } else {
                    ExecutionResult::Failure("Invalid operands for SUB64".to_string())
                }
            },
            Opcode::MUL64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Multiply two 64-bit integers
                    match a.checked_mul(b) {
                        Some(result) => {
                            self.push(StackItem::Int(result));
                            self.push(StackItem::Bool(true)); // Success bit
                            ExecutionResult::Success
                        },
                        None => {
                            // Overflow
                            self.push(StackItem::Int(a));
                            self.push(StackItem::Int(b));
                            self.push(StackItem::Bool(false)); // Failure bit
                            ExecutionResult::Success
                        }
                    }
                } else {
                    ExecutionResult::Failure("Invalid operands for MUL64".to_string())
                }
            },
            Opcode::DIV64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Divide two 64-bit integers
                    if b == 0 {
                        // Division by zero
                        self.push(StackItem::Int(a));
                        self.push(StackItem::Int(b));
                        self.push(StackItem::Bool(false)); // Failure bit
                        ExecutionResult::Success
                    } else {
                        match a.checked_div(b) {
                            Some(result) => {
                                self.push(StackItem::Int(result));
                                self.push(StackItem::Bool(true)); // Success bit
                                ExecutionResult::Success
                            },
                            None => {
                                // Overflow (only possible for INT64_MIN / -1)
                                self.push(StackItem::Int(a));
                                self.push(StackItem::Int(b));
                                self.push(StackItem::Bool(false)); // Failure bit
                                ExecutionResult::Success
                            }
                        }
                    }
                } else {
                    ExecutionResult::Failure("Invalid operands for DIV64".to_string())
                }
            },
            Opcode::NEG64 => {
                if let Some(Some(a)) = self.pop().map(|item| item.to_int()) {
                    // Negate 64-bit integer
                    match a.checked_neg() {
                        Some(result) => {
                            self.push(StackItem::Int(result));
                            self.push(StackItem::Bool(true)); // Success bit
                            ExecutionResult::Success
                        },
                        None => {
                            // Overflow (only possible for INT64_MIN)
                            self.push(StackItem::Int(a));
                            self.push(StackItem::Bool(false)); // Failure bit
                            ExecutionResult::Success
                        }
                    }
                } else {
                    ExecutionResult::Failure("Invalid operand for NEG64".to_string())
                }
            },
            Opcode::LESSTHAN64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Check if a < b
                    self.push(StackItem::Bool(a < b));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for LESSTHAN64".to_string())
                }
            },
            Opcode::LESSTHANOREQUAL64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Check if a <= b
                    self.push(StackItem::Bool(a <= b));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for LESSTHANOREQUAL64".to_string())
                }
            },
            Opcode::GREATERTHAN64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Check if a > b
                    self.push(StackItem::Bool(a > b));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for GREATERTHAN64".to_string())
                }
            },
            Opcode::GREATERTHANOREQUAL64 => {
                if let (Some(Some(b)), Some(Some(a))) = (
                    self.pop().map(|item| item.to_int()),
                    self.pop().map(|item| item.to_int())
                ) {
                    // Check if a >= b
                    self.push(StackItem::Bool(a >= b));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for GREATERTHANOREQUAL64".to_string())
                }
            },

            // Elements opcodes - Conversion
            Opcode::SCRIPTNUMTOLE64 => {
                if let Some(Some(num)) = self.pop().map(|item| item.to_int()) {
                    // Convert script number to 64-bit LE
                    let mut bytes = Vec::new();
                    let mut val = num;
                    for _ in 0..8 {
                        bytes.push((val & 0xff) as u8);
                        val >>= 8;
                    }
                    self.push(StackItem::Bytes(bytes));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operand for SCRIPTNUMTOLE64".to_string())
                }
            },
            Opcode::LE64TOSCRIPTNUM => {
                if let Some(Some(bytes)) = self.pop().map(|item| item.to_bytes()) {
                    // Convert 64-bit LE to script number
                    if bytes.len() != 8 {
                        return ExecutionResult::Failure("Invalid operand size for LE64TOSCRIPTNUM".to_string());
                    }
                    let mut val: i64 = 0;
                    for (i, &byte) in bytes.iter().enumerate() {
                        val |= (byte as i64) << (8 * i);
                    }
                    self.push(StackItem::Int(val));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operand for LE64TOSCRIPTNUM".to_string())
                }
            },
            Opcode::LE32TOLE64 => {
                if let Some(Some(bytes)) = self.pop().map(|item| item.to_bytes()) {
                    // Convert 32-bit LE to 64-bit LE
                    if bytes.len() != 4 {
                        return ExecutionResult::Failure("Invalid operand size for LE32TOLE64".to_string());
                    }
                    let mut val: i32 = 0;
                    for (i, &byte) in bytes.iter().enumerate() {
                        val |= (byte as i32) << (8 * i);
                    }
                    let val64 = val as i64;
                    let mut bytes64 = Vec::new();
                    let mut val_copy = val64;
                    for _ in 0..8 {
                        bytes64.push((val_copy & 0xff) as u8);
                        val_copy >>= 8;
                    }
                    self.push(StackItem::Bytes(bytes64));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operand for LE32TOLE64".to_string())
                }
            },

            // Elements opcodes - Crypto
            Opcode::ECMULSCALARVERIFY => {
                if let (Some(Some(q)), Some(Some(p)), Some(Some(k))) = (
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes())
                ) {
                    // Verify EC scalar multiplication
                    // In a real implementation, this would verify that Q = k*P
                    // For now, we'll just return success
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for ECMULSCALARVERIFY".to_string())
                }
            },
            Opcode::TWEAKVERIFY => {
                if let (Some(Some(output_key)), Some(Some(tweak)), Some(Some(internal_key))) = (
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes())
                ) {
                    // Verify key tweaking
                    // In a real implementation, this would verify that output_key = internal_key + tweak*G
                    // For now, we'll just return success
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for TWEAKVERIFY".to_string())
                }
            },

            // Modified existing opcodes
            Opcode::CHECKSIGFROMSTACK => {
                if let (Some(Some(pubkey)), Some(Some(message)), Some(Some(signature))) = (
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes())
                ) {
                    // Verify signature
                    // In a real implementation, this would verify the signature
                    // For now, we'll just return success
                    self.push(StackItem::Bool(true));
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for CHECKSIGFROMSTACK".to_string())
                }
            },
            Opcode::CHECKSIGFROMSTACKVERIFY => {
                if let (Some(Some(pubkey)), Some(Some(message)), Some(Some(signature))) = (
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes()),
                    self.pop().map(|item| item.to_bytes())
                ) {
                    // Verify signature
                    // In a real implementation, this would verify the signature
                    // For now, we'll just return success
                    ExecutionResult::Success
                } else {
                    ExecutionResult::Failure("Invalid operands for CHECKSIGFROMSTACKVERIFY".to_string())
                }
            },

            // Default case for unimplemented opcodes
            _ => ExecutionResult::Failure(format!("Opcode {:?} not implemented", opcode)),
        }
    }

    /// Execute a script
    pub fn execute_script(&mut self, script: &[u8]) -> ExecutionResult {
        // Parse script into opcodes and execute them
        // This is a simplified implementation
        let mut i = 0;
        while i < script.len() {
            let opcode_value = script[i];
            i += 1;

            // Convert opcode value to Opcode enum
            if let Some(opcode) = Opcode::from_value(opcode_value) {
                // Handle push opcodes (OP_1 to OP_16 and OP_PUSHDATA)
                let data = if opcode_value >= 1 && opcode_value <= 75 {
                    // Direct push of N bytes
                    let n = opcode_value as usize;
                    if i + n <= script.len() {
                        let data = &script[i..i+n];
                        i += n;
                        Some(data)
                    } else {
                        return ExecutionResult::Failure("Script truncated".to_string());
                    }
                } else {
                    None
                };

                // Execute the opcode
                match self.execute_opcode(&opcode, data.map(|d| d)) {
                    ExecutionResult::Success => {},
                    ExecutionResult::Failure(err) => return ExecutionResult::Failure(err),
                }
            } else {
                return ExecutionResult::Failure(format!("Unknown opcode: {}", opcode_value));
            }
        }

        // Check if execution was successful (stack has at least one item and top item is true)
        if let Some(top) = self.stack.last() {
            if top.to_bool() {
                ExecutionResult::Success
            } else {
                ExecutionResult::Failure("Script returned false".to_string())
            }
        } else {
            ExecutionResult::Failure("Empty stack".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_stack_operations() {
        let mut ctx = ExecutionContext::new();
        
        // Push items to stack
        ctx.push(StackItem::Int(42));
        ctx.push(StackItem::Bool(true));
        
        // Pop items from stack
        assert_eq!(ctx.pop().unwrap().to_bool(), true);
        assert_eq!(ctx.pop().unwrap().to_int(), Some(42));
        assert!(ctx.pop().is_none());
    }

    #[test]
    fn test_execute_opcode() {
        let mut ctx = ExecutionContext::new();
        
        // Test OP_1
        assert_eq!(ctx.execute_opcode(&Opcode::OP_1, None), ExecutionResult::Success);
        assert_eq!(ctx.pop().unwrap().to_int(), Some(1));
        
        // Test ADD64
        ctx.push(StackItem::Int(40));
        ctx.push(StackItem::Int(2));
        assert_eq!(ctx.execute_opcode(&Opcode::ADD64, None), ExecutionResult::Success);
        assert_eq!(ctx.pop().unwrap().to_bool(), true); // Success bit
        assert_eq!(ctx.pop().unwrap().to_int(), Some(42)); // Result
    }
} 