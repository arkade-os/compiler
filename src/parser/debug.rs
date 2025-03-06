use pest::Parser;
use pest_derive::Parser;
use pest::iterators::Pair;

#[derive(Parser)]
#[grammar = "parser/grammar.pest"]
pub struct TapLangParser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source_code = r#"contract HTLC(
  pubkey sender,
  pubkey receiver,
  bytes32 hash,
  int timelock
) {
  function together(signature senderSig, signature receiverSig) {
    require(checkMultisig([sender, receiver], [senderSig, receiverSig]));
  }
  
  function refund(signature senderSig) {
    require(checkSig(senderSig, sender));
    require(tx.time >= timelock);
  }
  
  function claim(signature receiverSig, bytes32 preimage) {
    require(checkSig(receiverSig, receiver));
    require(sha256(preimage) == hash);
  }
}"#;

    // Try to parse the contract
    let pairs = TapLangParser::parse(Rule::contract, source_code)?;
    
    // Print the parse tree
    for pair in pairs {
        print_pair(pair, 0);
    }
    
    Ok(())
}

fn print_pair(pair: Pair<Rule>, indent: usize) {
    let indent_str = " ".repeat(indent);
    println!("{}Rule: {:?}, Span: {:?}, Text: {}", indent_str, pair.as_rule(), pair.as_span(), pair.as_str());
    
    for inner_pair in pair.into_inner() {
        print_pair(inner_pair, indent + 2);
    }
} 