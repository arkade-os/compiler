use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

pub(crate) fn parse_multisig_threshold(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<u16, String> {
    let name = pair.as_str();
    let text = if pair.as_rule() != Rule::number_literal {
        let constant = constants
            .iter()
            .find(|constant| constant.name == name)
            .ok_or_else(|| format!("multisig threshold '{name}' must be an int constant"))?;
        match (&constant.value.kind, constant.const_type.as_str()) {
            (ExprKind::Literal(text), "int") => text.as_str(),
            _ => {
                return Err(format!(
                    "multisig threshold '{name}' must be an int literal constant"
                ))
            }
        }
    } else {
        name
    };
    text.parse::<u16>()
        .map_err(|e| format!("invalid multisig threshold '{name}': {e}"))
}
