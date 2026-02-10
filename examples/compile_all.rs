use std::error::Error;
use std::fs;
use std::path::Path;
use arkade_compiler::compile;

fn main() -> Result<(), Box<dyn Error>> {
    // Define the Arkade Script files to compile
    let files = vec![
        ("bare.ark", "bare.json", "bare.hack"),
        ("htlc.ark", "htlc.json", "htlc.hack"),
        ("arkade_kitties.ark", "arkade_kitties.json", "arkade_kitties.hack"),
        ("non_interactive_swap.ark", "non_interactive_swap.json", "non_interactive_swap.hack")
    ];

    // Compile each file
    for (input_file, output_file, hack_file) in files {
        println!("Compiling {} to {} and {}...", input_file, output_file, hack_file);

        // Read the input file
        let input_path = Path::new("examples").join(input_file);
        let source_code = fs::read_to_string(&input_path)?;

        // Compile it
        let output = compile(&source_code)?;

        // Write the JSON output
        let json = serde_json::to_string_pretty(&output)?;
        let output_path = Path::new("examples").join(output_file);
        fs::write(&output_path, &json)?;

        // Generate .hack file with opcodes for Bitcoin Script editors
        let mut hack_content = String::new();
        hack_content.push_str(&format!("# {}\n", output.name));
        hack_content.push_str("#\n");
        hack_content.push_str("#\n\n");

        for func in &output.functions {
            let variant = if func.server_variant { "cooperative" } else { "exit" };
            hack_content.push_str(&format!("# Function: {} ({})\n", func.name, variant));

            for opcode in &func.asm {
                hack_content.push_str(&format!("{}\n", opcode));
            }
            hack_content.push_str("\n");
        }

        let hack_path = Path::new("examples").join(hack_file);
        fs::write(&hack_path, &hack_content)?;

        println!("Successfully compiled {} to {} and {}", input_file, output_file, hack_file);
        println!("\n-----------------------------------\n");
    }

    println!("All files compiled successfully!");

    Ok(())
} 