use super::*;
use crate::models::*;

/// Generate assembly for expression (for use in if conditions)
pub(crate) fn generate_expression_asm(expr: &Expression, asm: &mut Vec<String>) {
    match expr {
        Expression::Variable(var) => {
            asm.push(format!("<{}>", var));
        }
        Expression::Literal(lit) => match lit.as_str() {
            "true" => asm.push(OP_1.to_string()),
            "false" => asm.push(OP_0.to_string()),
            _ => asm.push(lit.clone()),
        },
        Expression::Property(prop) => {
            // Map the introspector "this" properties to their dedicated opcodes
            // (the parser stores them as Property strings; resolving them here
            // keeps the placeholder pipeline untouched for everything else).
            match prop.as_str() {
                "this.activeInputIndex" => asm.push(OP_PUSHCURRENTINPUTINDEX.to_string()),
                "this.activeBytecode" => asm.push(OP_INPUTBYTECODE.to_string()),
                _ => asm.push(format!("<{}>", prop)),
            }
        }
        Expression::BinaryOp { left, op, right } => {
            if matches!(op.as_str(), "==" | "!=" | ">=" | "<=" | ">" | "<") {
                emit_comparison_asm(left, op, right, asm);
                return;
            }

            generate_expression_asm(left, asm);
            generate_expression_asm(right, asm);

            match op.as_str() {
                "+" => asm.push(OP_ADD.to_string()),
                "-" => asm.push(OP_SUB.to_string()),
                "*" => asm.push(OP_MUL.to_string()),
                "/" => asm.push(OP_DIV.to_string()),
                _ => asm.push(OP_FALSE.to_string()),
            }
        }
        Expression::CurrentInput(property) => {
            if let Some(prop) = property {
                match prop.as_str() {
                    "scriptPubKey" => asm.push(OP_INPUTBYTECODE.to_string()),
                    "value" => asm.push(OP_INPUTVALUE.to_string()),
                    "sequence" => asm.push(OP_INPUTSEQUENCE.to_string()),
                    "outpoint" => asm.push(OP_INPUTOUTPOINT.to_string()),
                    _ => asm.push(OP_INPUTBYTECODE.to_string()),
                }
            } else {
                asm.push(OP_INPUTBYTECODE.to_string());
            }
        }
        Expression::CheckSigExpr { signature, pubkey } => {
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIG.to_string());
        }
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIGFROMSTACK.to_string());
        }
        // Streaming SHA256
        Expression::Sha256 { data } => {
            generate_expression_asm(data, asm);
            asm.push(OP_SHA256.to_string());
        }
        Expression::Sha256Initialize { data } => {
            generate_expression_asm(data, asm);
            asm.push(OP_SHA256INITIALIZE.to_string());
        }
        Expression::Sha256Update { context, chunk } => {
            generate_expression_asm(context, asm);
            generate_expression_asm(chunk, asm);
            asm.push(OP_SHA256UPDATE.to_string());
        }
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => {
            generate_expression_asm(context, asm);
            generate_expression_asm(last_chunk, asm);
            asm.push(OP_SHA256FINALIZE.to_string());
        }
        // Byte-string concatenation: bytes-like + value → OP_CAT
        // Coercion flags decide whether to convert a scriptnum side to LE64
        // before the cat (so off-chain hashing uses fixed 8-byte ints).
        Expression::Concat {
            left,
            right,
            coerce_left,
            coerce_right,
        } => {
            generate_expression_asm(left, asm);
            if *coerce_left {
                asm.push(OP_SCRIPTNUMTOLE64.to_string());
            }
            generate_expression_asm(right, asm);
            if *coerce_right {
                asm.push(OP_SCRIPTNUMTOLE64.to_string());
            }
            asm.push(OP_CAT.to_string());
        }
        // Conversion & Arithmetic
        Expression::Neg64 { value } => {
            generate_expression_asm(value, asm);
            asm.push(OP_NEG64.to_string());
        }
        Expression::Le64ToScriptNum { value } => {
            generate_expression_asm(value, asm);
            asm.push(OP_LE64TOSCRIPTNUM.to_string());
        }
        Expression::Le32ToLe64 { value } => {
            generate_expression_asm(value, asm);
            asm.push(OP_LE32TOLE64.to_string());
        }
        // Crypto Opcodes
        Expression::EcMulScalarVerify {
            scalar,
            point_p,
            point_q,
        } => {
            generate_expression_asm(point_q, asm);
            generate_expression_asm(point_p, asm);
            generate_expression_asm(scalar, asm);
            asm.push(OP_ECMULSCALARVERIFY.to_string());
        }
        Expression::TweakVerify {
            point_p,
            tweak,
            point_q,
        } => {
            generate_expression_asm(point_q, asm);
            generate_expression_asm(tweak, asm);
            generate_expression_asm(point_p, asm);
            asm.push(OP_TWEAKVERIFY.to_string());
        }
        Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIGFROMSTACKVERIFY.to_string());
        }
        Expression::AssetLookup {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_lookup_asm(source, index, asset_txid, asset_gidx, asm);
        }
        Expression::AssetHas {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_has_asm(source, index, asset_txid, asset_gidx, asm);
        }
        Expression::AssetCount { source, index } => {
            emit_asset_count_asm(source, index, asm);
        }
        Expression::AssetAt {
            source,
            io_index,
            asset_index,
            property,
        } => {
            emit_asset_at_asm(source, io_index, asset_index, property, asm);
        }
        Expression::TxIntrospection { property } => {
            emit_tx_introspection_asm(property, asm);
        }
        Expression::InputIntrospection { index, property } => {
            emit_input_introspection_asm(index, property, asm);
        }
        Expression::OutputIntrospection { index, property } => {
            emit_output_introspection_asm(index, property, asm);
        }
        Expression::GroupFind {
            asset_txid,
            asset_gidx,
        } => {
            emit_group_find_asm(asset_txid, asset_gidx, asm);
        }
        Expression::GroupHas {
            asset_txid,
            asset_gidx,
        } => {
            emit_group_has_asm(asset_txid, asset_gidx, asm);
        }
        Expression::GroupControlIs {
            group,
            asset_txid,
            asset_gidx,
        } => {
            emit_group_control_is_asm(group, asset_txid, asset_gidx, asm);
        }
        Expression::GroupProperty { group, property } => {
            emit_group_property_asm(group, property, asm);
        }
        Expression::AssetGroupsLength => {
            asm.push(OP_INSPECTNUMASSETGROUPS.to_string());
        }
        Expression::GroupSum { index, source } => {
            generate_expression_asm(index, asm);
            match source {
                GroupSumSource::Inputs => asm.push(OP_0.to_string()),
                GroupSumSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUPSUM.to_string());
        }
        Expression::GroupNumIO { index, source } => {
            generate_expression_asm(index, asm);
            match source {
                GroupIOSource::Inputs => asm.push(OP_0.to_string()),
                GroupIOSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUPNUM.to_string());
        }
        Expression::GroupIOAccess {
            group_index,
            io_index,
            source,
            property,
        } => {
            generate_expression_asm(group_index, asm);
            generate_expression_asm(io_index, asm);
            match source {
                GroupIOSource::Inputs => asm.push(OP_0.to_string()),
                GroupIOSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUP.to_string());
            // Extract property if specified
            // Stack after opcode: type_u8, data..., amount_u64 (top)
            if let Some(prop) = property {
                match prop.as_str() {
                    "amount" => {
                        // Keep only amount (top of stack)
                        // Need to handle based on type, but for now just keep top
                    }
                    "type" => {
                        // Drop everything except type
                        asm.push(OP_DROP.to_string()); // amount
                        asm.push(OP_DROP.to_string()); // data (varies)
                    }
                    _ => {}
                }
            }
        }
        Expression::ContractInstance {
            contract_name,
            args,
        } => {
            emit_contract_instance_asm(contract_name, args, asm);
        }
        // Byte-string manipulation (introspector extensions)
        Expression::Substr { data, offset, size } => {
            generate_expression_asm(data, asm);
            generate_expression_asm(offset, asm);
            generate_expression_asm(size, asm);
            asm.push(OP_SUBSTR.to_string());
        }
        Expression::Cat { left, right } => {
            generate_expression_asm(left, asm);
            generate_expression_asm(right, asm);
            asm.push(OP_CAT.to_string());
        }
        Expression::Bin2Num { data } => {
            generate_expression_asm(data, asm);
            asm.push(OP_BIN2NUM.to_string());
        }
        Expression::Num2Bin { value, size } => {
            generate_expression_asm(value, asm);
            generate_expression_asm(size, asm);
            asm.push(OP_NUM2BIN.to_string());
        }
        Expression::SizeOf { data } => {
            generate_expression_asm(data, asm);
            // OP_SIZE pushes len next to original bytes; OP_NIP drops the
            // original so only the size remains on the stack.
            asm.push(OP_SIZE.to_string());
            asm.push(OP_NIP.to_string());
        }
        // Packet introspection
        Expression::PacketInspect { packet_type } => {
            generate_expression_asm(packet_type, asm);
            asm.push(OP_INSPECTPACKET.to_string());
            // OP_INSPECTPACKET returns (content, 1) on hit, () then 0 on miss.
            // Assert present and discard the bool, leaving content on the stack.
            asm.push(OP_1.to_string());
            asm.push(OP_EQUALVERIFY.to_string());
        }
        Expression::InputPacketInspect { index, packet_type } => {
            generate_expression_asm(packet_type, asm);
            generate_expression_asm(index, asm);
            asm.push(OP_INSPECTINPUTPACKET.to_string());
            asm.push(OP_1.to_string());
            asm.push(OP_EQUALVERIFY.to_string());
        }
    }
}

/// Emit assembly for an expression (push its value onto the stack)
pub(crate) fn emit_expression_asm(expr: &Expression, asm: &mut Vec<String>) {
    match expr {
        Expression::Variable(var) => {
            asm.push(format!("<{}>", var));
        }
        Expression::Literal(lit) => match lit.as_str() {
            "true" => asm.push(OP_1.to_string()),
            "false" => asm.push(OP_0.to_string()),
            _ => asm.push(lit.clone()),
        },
        Expression::Property(prop) => {
            // Map the introspector "this" properties to their dedicated opcodes
            // (the parser stores them as Property strings; resolving them here
            // keeps the placeholder pipeline untouched for everything else).
            match prop.as_str() {
                "this.activeInputIndex" => asm.push(OP_PUSHCURRENTINPUTINDEX.to_string()),
                "this.activeBytecode" => asm.push(OP_INPUTBYTECODE.to_string()),
                _ => asm.push(format!("<{}>", prop)),
            }
        }
        Expression::CurrentInput(property) => {
            emit_current_input_asm(property.as_deref(), asm);
        }
        Expression::AssetLookup {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_lookup_asm(source, index, asset_txid, asset_gidx, asm);
        }
        Expression::AssetHas {
            source,
            index,
            asset_txid,
            asset_gidx,
        } => {
            emit_asset_has_asm(source, index, asset_txid, asset_gidx, asm);
        }
        Expression::AssetCount { source, index } => {
            emit_asset_count_asm(source, index, asm);
        }
        Expression::AssetAt {
            source,
            io_index,
            asset_index,
            property,
        } => {
            emit_asset_at_asm(source, io_index, asset_index, property, asm);
        }
        Expression::TxIntrospection { property } => {
            emit_tx_introspection_asm(property, asm);
        }
        Expression::InputIntrospection { index, property } => {
            emit_input_introspection_asm(index, property, asm);
        }
        Expression::OutputIntrospection { index, property } => {
            emit_output_introspection_asm(index, property, asm);
        }
        Expression::BinaryOp { left, op, right } => {
            if matches!(op.as_str(), "==" | "!=" | ">=" | "<=" | ">" | "<") {
                emit_comparison_asm(left, op, right, asm);
            } else {
                emit_binary_op_asm(left, op, right, asm);
            }
        }
        Expression::GroupFind {
            asset_txid,
            asset_gidx,
        } => {
            emit_group_find_asm(asset_txid, asset_gidx, asm);
        }
        Expression::GroupHas {
            asset_txid,
            asset_gidx,
        } => {
            emit_group_has_asm(asset_txid, asset_gidx, asm);
        }
        Expression::GroupControlIs {
            group,
            asset_txid,
            asset_gidx,
        } => {
            emit_group_control_is_asm(group, asset_txid, asset_gidx, asm);
        }
        Expression::GroupProperty { group, property } => {
            emit_group_property_asm(group, property, asm);
        }
        Expression::AssetGroupsLength => {
            asm.push(OP_INSPECTNUMASSETGROUPS.to_string());
        }
        Expression::GroupSum { index, source } => {
            emit_expression_asm(index, asm);
            match source {
                GroupSumSource::Inputs => asm.push(OP_0.to_string()),
                GroupSumSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUPSUM.to_string());
        }
        Expression::GroupNumIO { index, source } => {
            emit_expression_asm(index, asm);
            match source {
                GroupIOSource::Inputs => asm.push(OP_0.to_string()),
                GroupIOSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUPNUM.to_string());
        }
        Expression::GroupIOAccess {
            group_index,
            io_index,
            source,
            property,
        } => {
            emit_expression_asm(group_index, asm);
            emit_expression_asm(io_index, asm);
            match source {
                GroupIOSource::Inputs => asm.push(OP_0.to_string()),
                GroupIOSource::Outputs => asm.push(OP_1.to_string()),
            }
            asm.push(OP_INSPECTASSETGROUP.to_string());
            // Extract property if specified
            if let Some(prop) = property {
                match prop.as_str() {
                    "amount" => {
                        // Amount is on top, no extraction needed for amount
                    }
                    "type" => {
                        asm.push(OP_DROP.to_string()); // amount
                        asm.push(OP_DROP.to_string()); // data
                    }
                    _ => {}
                }
            }
        }
        Expression::ContractInstance {
            contract_name,
            args,
        } => {
            emit_contract_instance_asm(contract_name, args, asm);
        }
        Expression::CheckSigExpr { signature, pubkey } => {
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIG.to_string());
        }
        Expression::CheckSigFromStackExpr {
            signature,
            pubkey,
            message,
        } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIGFROMSTACK.to_string());
        }
        // Streaming SHA256
        Expression::Sha256 { data } => {
            emit_expression_asm(data, asm);
            asm.push(OP_SHA256.to_string());
        }
        Expression::Sha256Initialize { data } => {
            emit_expression_asm(data, asm);
            asm.push(OP_SHA256INITIALIZE.to_string());
        }
        Expression::Sha256Update { context, chunk } => {
            emit_expression_asm(context, asm);
            emit_expression_asm(chunk, asm);
            asm.push(OP_SHA256UPDATE.to_string());
        }
        Expression::Sha256Finalize {
            context,
            last_chunk,
        } => {
            emit_expression_asm(context, asm);
            emit_expression_asm(last_chunk, asm);
            asm.push(OP_SHA256FINALIZE.to_string());
        }
        // Byte-string concatenation: bytes-like + value → OP_CAT
        Expression::Concat {
            left,
            right,
            coerce_left,
            coerce_right,
        } => {
            emit_expression_asm(left, asm);
            if *coerce_left {
                asm.push(OP_SCRIPTNUMTOLE64.to_string());
            }
            emit_expression_asm(right, asm);
            if *coerce_right {
                asm.push(OP_SCRIPTNUMTOLE64.to_string());
            }
            asm.push(OP_CAT.to_string());
        }
        // Conversion & Arithmetic
        Expression::Neg64 { value } => {
            emit_expression_asm(value, asm);
            asm.push(OP_NEG64.to_string());
        }
        Expression::Le64ToScriptNum { value } => {
            emit_expression_asm(value, asm);
            asm.push(OP_LE64TOSCRIPTNUM.to_string());
        }
        Expression::Le32ToLe64 { value } => {
            emit_expression_asm(value, asm);
            asm.push(OP_LE32TOLE64.to_string());
        }
        // Crypto Opcodes
        Expression::EcMulScalarVerify {
            scalar,
            point_p,
            point_q,
        } => {
            emit_expression_asm(point_q, asm);
            emit_expression_asm(point_p, asm);
            emit_expression_asm(scalar, asm);
            asm.push(OP_ECMULSCALARVERIFY.to_string());
        }
        Expression::TweakVerify {
            point_p,
            tweak,
            point_q,
        } => {
            emit_expression_asm(point_q, asm);
            emit_expression_asm(tweak, asm);
            emit_expression_asm(point_p, asm);
            asm.push(OP_TWEAKVERIFY.to_string());
        }
        Expression::CheckSigFromStackVerify {
            signature,
            pubkey,
            message,
        } => {
            asm.push(format!("<{}>", message));
            asm.push(format!("<{}>", pubkey));
            asm.push(format!("<{}>", signature));
            asm.push(OP_CHECKSIGFROMSTACKVERIFY.to_string());
        }
        // Byte-string manipulation (introspector extensions)
        Expression::Substr { data, offset, size } => {
            emit_expression_asm(data, asm);
            emit_expression_asm(offset, asm);
            emit_expression_asm(size, asm);
            asm.push(OP_SUBSTR.to_string());
        }
        Expression::Cat { left, right } => {
            emit_expression_asm(left, asm);
            emit_expression_asm(right, asm);
            asm.push(OP_CAT.to_string());
        }
        Expression::Bin2Num { data } => {
            emit_expression_asm(data, asm);
            asm.push(OP_BIN2NUM.to_string());
        }
        Expression::Num2Bin { value, size } => {
            emit_expression_asm(value, asm);
            emit_expression_asm(size, asm);
            asm.push(OP_NUM2BIN.to_string());
        }
        Expression::SizeOf { data } => {
            emit_expression_asm(data, asm);
            asm.push(OP_SIZE.to_string());
            asm.push(OP_NIP.to_string());
        }
        // Packet introspection
        Expression::PacketInspect { packet_type } => {
            emit_expression_asm(packet_type, asm);
            asm.push(OP_INSPECTPACKET.to_string());
            asm.push(OP_1.to_string());
            asm.push(OP_EQUALVERIFY.to_string());
        }
        Expression::InputPacketInspect { index, packet_type } => {
            emit_expression_asm(packet_type, asm);
            emit_expression_asm(index, asm);
            asm.push(OP_INSPECTINPUTPACKET.to_string());
            asm.push(OP_1.to_string());
            asm.push(OP_EQUALVERIFY.to_string());
        }
    }
}

/// Emit assembly for tx.input.current property access
pub(crate) fn emit_current_input_asm(property: Option<&str>, asm: &mut Vec<String>) {
    match property {
        Some("scriptPubKey") => {
            asm.push(OP_PUSHCURRENTINPUTINDEX.to_string());
            asm.push(OP_INSPECTINPUTSCRIPTPUBKEY.to_string());
        }
        Some("value") => {
            asm.push(OP_PUSHCURRENTINPUTINDEX.to_string());
            asm.push(OP_INSPECTINPUTVALUE.to_string());
        }
        Some("sequence") => {
            asm.push(OP_PUSHCURRENTINPUTINDEX.to_string());
            asm.push(OP_INSPECTINPUTSEQUENCE.to_string());
        }
        Some("outpoint") => {
            asm.push(OP_PUSHCURRENTINPUTINDEX.to_string());
            asm.push(OP_INSPECTINPUTOUTPOINT.to_string());
        }
        _ => {
            asm.push(OP_PUSHCURRENTINPUTINDEX.to_string());
            asm.push(OP_INSPECTINPUTSCRIPTPUBKEY.to_string());
        }
    }
}

/// Emit assembly for a contract instantiation: `new ContractName(arg1, arg2, ...)`
///
/// Produces a single placeholder token `<VTXO:ContractName(<arg1>,<arg2>)>` that
/// the runtime resolves to the Taproot scriptPubKey (34-byte P2TR output script)
/// of the named contract instantiated with the given constructor arguments.
///
/// Options (server key, exit timelock) are inherited from the enclosing contract
/// and must be applied by the runtime when computing the child contract's taproot
/// key.
///
/// Typical usage (recursion / self-referential contract enforcement):
/// ```text
/// require(tx.outputs[0].scriptPubKey == new SingleSig(ownerPk));
/// ```
/// compiles to:
/// ```text
/// 0 OP_INSPECTOUTPUTSCRIPTPUBKEY <VTXO:SingleSig(<ownerPk>)> OP_EQUAL
/// ```
pub(crate) fn emit_contract_instance_asm(
    contract_name: &str,
    args: &[Expression],
    asm: &mut Vec<String>,
) {
    let args_str = args
        .iter()
        .map(|a| match a {
            Expression::Variable(v) => format!("<{}>", v),
            Expression::Literal(l) => l.clone(),
            _ => {
                // For complex arg expressions, emit a nested representation
                let mut nested = Vec::new();
                emit_expression_asm(a, &mut nested);
                nested.join(" ")
            }
        })
        .collect::<Vec<_>>()
        .join(",");

    asm.push(format!("<VTXO:{}({})>", contract_name, args_str));
}

/// Emit assembly for a binary arithmetic operation (64-bit)
pub(crate) fn emit_binary_op_asm(
    left: &Expression,
    op: &str,
    right: &Expression,
    asm: &mut Vec<String>,
) {
    emit_expression_asm(left, asm);
    emit_expression_asm(right, asm);

    match op {
        "+" => asm.push(OP_ADD.to_string()),
        "-" => asm.push(OP_SUB.to_string()),
        "*" => asm.push(OP_MUL.to_string()),
        "/" => asm.push(OP_DIV.to_string()),
        _ => asm.push(format!("OP_{}", op.to_uppercase())),
    }
}
