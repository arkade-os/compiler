use crate::compiler::tapscript::{validate_arkd_rules, validate_closure_shape, Closure};
use crate::models::{AbiLeaf, NamedTapscript};
use crate::ContractJson;

pub fn analyze_output(contract: &ContractJson) -> Result<(), String> {
    check_tap_leaves(contract)
}

fn check_tap_leaves(contract: &ContractJson) -> Result<(), String> {
    for f in &contract.functions {
        for leaf in &f.leaves {
            let closure = Closure::from_leaf(&leaf)?;
            let tapscript = NamedTapscript::from_leaf(leaf, &closure);

            validate_closure_shape(&closure, &leaf.name)?;
            validate_arkd_rules(
                &contract.parameters,
                &contract.structs,
                &tapscript,
                &closure,
                None,
            )?;
        }
    }
    Ok(())
}
