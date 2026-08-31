//! Integration tests that compile real .ark contracts from examples/.
#[path = "common/mod.rs"]
mod common;

#[path = "examples/arkade_kitties.rs"]
mod arkade_kitties;
#[path = "examples/asm_structural.rs"]
mod asm_structural;
#[path = "examples/bond_mint.rs"]
mod bond_mint;
#[path = "examples/cash_secured_put.rs"]
mod cash_secured_put;
#[path = "examples/compilation_roundtrip.rs"]
mod compilation_roundtrip;
#[path = "examples/controlled_mint.rs"]
mod controlled_mint;
#[path = "examples/covered_call.rs"]
mod covered_call;
#[path = "examples/fee_adapter.rs"]
mod fee_adapter;
#[path = "examples/fuji_safe.rs"]
mod fuji_safe;
#[path = "examples/htlc.rs"]
mod htlc;
#[path = "examples/layerzero.rs"]
mod layerzero;
#[path = "examples/mining_margin.rs"]
mod mining_margin;
#[path = "examples/repayment_pool.rs"]
mod repayment_pool;
#[path = "examples/stability_vault.rs"]
mod stability_vault;
#[path = "examples/threshold_oracle.rs"]
mod threshold_oracle;
#[path = "examples/token_vault.rs"]
mod token_vault;
