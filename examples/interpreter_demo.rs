use taplang::interpreter::{ExecutionContext, StackItem, ExecutionResult};
use taplang::models::opcodes::Opcode;

fn main() {
    println!("TapLang Interpreter Demo");
    println!("------------------------");

    // Create a new execution context
    let mut ctx = ExecutionContext::new();

    // Example 1: Basic arithmetic
    println!("\nExample 1: Basic arithmetic");
    println!("Push 40 and 2 onto the stack");
    ctx.push(StackItem::Int(40));
    ctx.push(StackItem::Int(2));
    
    println!("Execute ADD64");
    match ctx.execute_opcode(&Opcode::ADD64, None) {
        ExecutionResult::Success => {
            let success = ctx.pop().unwrap().to_bool();
            let result = ctx.pop().unwrap().to_int().unwrap();
            println!("Result: {}, Success: {}", result, success);
        },
        ExecutionResult::Failure(err) => {
            println!("Error: {}", err);
        }
    }

    // Example 2: Streaming SHA256
    println!("\nExample 2: Streaming SHA256");
    println!("Push 'Hello' onto the stack");
    ctx.push(StackItem::Bytes("Hello".as_bytes().to_vec()));
    
    println!("Execute SHA256INITIALIZE");
    match ctx.execute_opcode(&Opcode::SHA256INITIALIZE, None) {
        ExecutionResult::Success => {
            println!("SHA256 context initialized");
        },
        ExecutionResult::Failure(err) => {
            println!("Error: {}", err);
        }
    }
    
    println!("Push ' World' onto the stack");
    ctx.push(StackItem::Bytes(" World".as_bytes().to_vec()));
    
    println!("Execute SHA256UPDATE");
    match ctx.execute_opcode(&Opcode::SHA256UPDATE, None) {
        ExecutionResult::Success => {
            println!("SHA256 context updated");
        },
        ExecutionResult::Failure(err) => {
            println!("Error: {}", err);
        }
    }
    
    println!("Push empty string onto the stack");
    ctx.push(StackItem::Bytes(vec![]));
    
    println!("Execute SHA256FINALIZE");
    match ctx.execute_opcode(&Opcode::SHA256FINALIZE, None) {
        ExecutionResult::Success => {
            let hash = ctx.pop().unwrap().to_bytes().unwrap();
            println!("SHA256 hash: {:?}", hash);
        },
        ExecutionResult::Failure(err) => {
            println!("Error: {}", err);
        }
    }

    // Example 3: Transaction introspection
    println!("\nExample 3: Transaction introspection");
    println!("Push input index 0 onto the stack");
    ctx.push(StackItem::Int(0));
    
    println!("Execute INSPECTINPUTOUTPOINT");
    match ctx.execute_opcode(&Opcode::INSPECTINPUTOUTPOINT, None) {
        ExecutionResult::Success => {
            let outpoint = ctx.pop().unwrap().to_bytes().unwrap();
            println!("Outpoint: {:?}", outpoint);
        },
        ExecutionResult::Failure(err) => {
            println!("Error: {}", err);
        }
    }

    println!("\nInterpreter demo completed");
} 