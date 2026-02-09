use std::error::Error;
use std::fs;
use std::path::Path;
use arkade_compiler::compile;

fn main() -> Result<(), Box<dyn Error>> {
    // Define the Arkade Script files to compile
    let files = vec![
        ("bare.ark", "bare.json"),
        ("htlc.ark", "htlc.json"),
        ("arkade_kitties", "arkade_kitties.json")
    ];
    
    // Compile each file
    for (input_file, output_file) in files {
        println!("Compiling {} to {}...", input_file, output_file);
        
        // Read the input file
        let input_path = Path::new("examples").join(input_file);
        let source_code = fs::read_to_string(&input_path)?;
        
        // Compile it
        let output = compile(&source_code)?;
        
        // Write the JSON output
        let json = serde_json::to_string_pretty(&output)?;
        let output_path = Path::new("examples").join(output_file);
        fs::write(&output_path, &json)?;
        
        println!("Successfully compiled {} to {}", input_file, output_file);
        // Remove JSON output to terminal since it's already written to file
        // println!("{}", json);
        println!("\n-----------------------------------\n");
    }
    
    println!("All files compiled successfully!");
    
    Ok(())
} 