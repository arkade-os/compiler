//! The workspace's layering: tools in `tools/` reach the compiler only through its public crate.

use serde_json::Value;

#[test]
fn tools_depend_on_the_compiler_and_the_compiler_on_no_tool() {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let tools = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools");
    let packages = metadata["packages"].as_array().unwrap();
    let is_tool = |package: &Value| {
        std::path::Path::new(package["manifest_path"].as_str().unwrap()).starts_with(&tools)
    };
    let local = |package: &Value| -> Vec<String> {
        package["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|dependency| dependency["path"].is_string())
            .map(|dependency| dependency["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(packages.iter().filter(|p| is_tool(p)).count() >= 2);
    for package in packages {
        let name = package["name"].as_str().unwrap();
        let expected: &[&str] = if is_tool(package) {
            &["arkade-compiler"]
        } else {
            &[]
        };
        assert_eq!(local(package), expected, "{name}");
    }
}
