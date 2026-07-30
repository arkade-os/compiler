//! Feature/language tests exercising compiler behavior via inline snippets.
#[path = "common/mod.rs"]
mod common;

#[path = "features/asset_id_explicit.rs"]
mod asset_id_explicit;
#[path = "features/asset_introspection.rs"]
mod asset_introspection;
#[path = "features/bare_vtxo.rs"]
mod bare_vtxo;
#[path = "features/beacon.rs"]
mod beacon;
#[path = "features/concat_op.rs"]
mod concat_op;
#[path = "features/contract_import_instantiation.rs"]
mod contract_import_instantiation;
#[path = "features/epoch_limiter.rs"]
mod epoch_limiter;
#[path = "features/general_comparisons.rs"]
mod general_comparisons;
#[path = "features/group_properties.rs"]
mod group_properties;
#[path = "features/io_introspection.rs"]
mod io_introspection;
#[path = "features/no_shadowing.rs"]
mod no_shadowing;
#[path = "features/opcode_functions.rs"]
mod opcode_functions;
#[path = "features/packet_primitives.rs"]
mod packet_primitives;
#[path = "features/symbolic_stack.rs"]
mod symbolic_stack;
#[path = "features/tapscript_abi.rs"]
mod tapscript_abi;
#[path = "features/tapscript_golden.rs"]
mod tapscript_golden;
#[path = "features/tapscript_validation.rs"]
mod tapscript_validation;
#[path = "features/threshold_multisig.rs"]
mod threshold_multisig;
#[path = "features/tx_introspection.rs"]
mod tx_introspection;
#[path = "features/type_system.rs"]
mod type_system;
#[path = "features/validation_error.rs"]
mod validation_error;
