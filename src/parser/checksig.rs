use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;

/// Parse checkSig(sig, pubkey) → CheckSig requirement
pub(crate) fn parse_check_sig(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let signature = inner
        .next()
        .ok_or("Missing signature")?
        .as_str()
        .to_string();
    let pubkey = inner
        .next()
        .ok_or("Missing public key")?
        .as_str()
        .to_string();
    Ok(Requirement::CheckSig { signature, pubkey })
}

/// Parse checkSigFromStack(sig, pubkey, message) → CheckSigFromStack requirement
pub(crate) fn parse_check_sig_from_stack(pair: Pair<Rule>) -> Result<Requirement, String> {
    let mut inner = pair.into_inner();
    let signature = inner
        .next()
        .ok_or("Missing signature")?
        .as_str()
        .to_string();
    let pubkey = inner
        .next()
        .ok_or("Missing public key")?
        .as_str()
        .to_string();
    let message = inner.next().ok_or("Missing message")?.as_str().to_string();
    Ok(Requirement::CheckSigFromStack {
        signature,
        pubkey,
        message,
    })
}

/// Parse checkMultisig([pubkeys], [sigs], threshold?) → CheckMultisig requirement
pub(crate) fn parse_check_multisig(
    pair: Pair<Rule>,
    constants: &[Constant],
) -> Result<Requirement, String> {
    let mut inner = pair
        .into_inner()
        .next()
        .ok_or("Missing checkMultisig definition")?
        .into_inner();
    let pubkeys_array = inner.next().ok_or("Missing public keys")?;

    let pubkeys: Vec<String> = pubkeys_array
        .into_inner()
        .map(|p| p.as_str().to_string())
        .collect();

    let signatures = inner
        .next()
        .ok_or("Missing signatures")?
        .into_inner()
        .map(|p| p.as_str().to_string())
        .collect();

    let threshold = match inner.next() {
        Some(next_pair) => parse_multisig_threshold(next_pair, constants)?,
        None => pubkeys.len() as u16,
    };

    Ok(Requirement::CheckMultisig {
        pubkeys,
        signatures,
        threshold,
    })
}

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
        match (&constant.value, constant.const_type.as_str()) {
            (Expression::Literal(text), "int") => text.as_str(),
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
