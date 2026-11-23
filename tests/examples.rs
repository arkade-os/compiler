//! Integration tests that compile real .ark contracts from examples/.
#[path = "common/mod.rs"]
mod common;

#[path = "examples/asm_structural.rs"]
mod asm_structural;
#[path = "examples/bond_mint.rs"]
mod bond_mint;
#[path = "examples/compilation_roundtrip.rs"]
mod compilation_roundtrip;
#[path = "examples/constant_product.rs"]
mod constant_product;
#[path = "examples/controlled_mint.rs"]
mod controlled_mint;
#[path = "examples/escrow.rs"]
mod escrow;
#[path = "examples/htlc.rs"]
mod htlc;
#[path = "examples/layerzero.rs"]
mod layerzero;
#[path = "examples/option.rs"]
mod option;
#[path = "examples/threshold_oracle.rs"]
mod threshold_oracle;
