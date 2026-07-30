use super::Rule;
#[allow(unused_imports)]
use super::*;
use crate::models::*;
use pest::iterators::Pair;
use std::str::FromStr;

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
pub(crate) fn parse_check_multisig(pair: Pair<Rule>) -> Result<Requirement, String> {
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
        Some(next_pair) => match u16::from_str(next_pair.as_str()) {
            Ok(threshold) => threshold,
            Err(e) => return Err(format!("{}", e)),
        },
        None => pubkeys.len() as u16,
    };

    Ok(Requirement::CheckMultisig {
        pubkeys,
        signatures,
        threshold,
    })
}
