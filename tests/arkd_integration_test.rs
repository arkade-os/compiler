/// Integration tests against a live arkd 2.7 instance.
///
/// These tests compile every example contract and submit the resulting
/// scripts to arkd for validation.  They are compiled only when the
/// `arkd-integration` feature flag is active and skipped at runtime when
/// the `ARKD_URL` environment variable is not set.
///
/// # Running
///
/// ```sh
/// ARKD_URL=http://localhost:7070 cargo test --features arkd-integration
/// ```
///
/// # What arkd validates
///
/// arkd 2.7 enforces script correctness when VTXOs are submitted.  By
/// asking it to validate our compiled scripts we get the ground-truth
/// answer about whether the generated tapscript leaf is well-formed —
/// without having to ship our own Elements Script interpreter.
///
/// The expected flow is:
/// 1. Compile `.ark` source → `ContractJson` (ASM + witnessSchema)
/// 2. Assemble the tapscript leaf from the `asm` token list
/// 3. POST to arkd's script-validation RPC and assert HTTP 200
///
/// Adapt the `submit_to_arkd` helper below once the exact arkd 2.7 RPC
/// endpoint and request schema are confirmed.
#[cfg(feature = "arkd-integration")]
mod arkd_integration {
    use arkade_compiler::compile;
    use std::fs;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Read `ARKD_URL` from the environment, or skip the test.
    fn arkd_url() -> Option<String> {
        std::env::var("ARKD_URL").ok()
    }

    /// Assemble a flat ASM token list into a hex-encoded script.
    ///
    /// This is a placeholder implementation that joins tokens with spaces.
    /// Replace with proper script assembly (opcode encoding, push-data, etc.)
    /// once the exact binary encoding required by arkd is known.
    fn asm_to_script_hex(asm: &[String]) -> String {
        // TODO: proper binary encoding of each token:
        //   - "OP_*" tokens → single-byte opcode
        //   - "<name>" tokens → OP_PUSHDATA + placeholder bytes
        //   - decimal literals → OP_PUSHDATA + scriptnum encoding
        // For now emit a human-readable form useful for debugging.
        asm.join(" ")
    }

    /// Submit a compiled script to arkd for validation.
    ///
    /// Returns `Ok(())` on acceptance, `Err(message)` on rejection.
    ///
    /// # Adapting to the real arkd 2.7 API
    ///
    /// arkd 2.7 exposes a gRPC interface (and optionally a REST gateway).
    /// The expected call when using the REST gateway is something like:
    ///
    /// ```
    /// POST {ARKD_URL}/v1/vtxo/validate
    /// Content-Type: application/json
    /// {
    ///   "contractName": "HTLC",
    ///   "functionName":  "claim",
    ///   "serverVariant": true,
    ///   "script":        "<hex-encoded tapscript leaf>"
    /// }
    /// ```
    ///
    /// Replace the body below with a real `reqwest` (or `ureq`) call once
    /// the endpoint schema is confirmed.  Add `reqwest` or `ureq` as an
    /// optional dev-dependency gated on `arkd-integration`.
    fn submit_to_arkd(
        url: &str,
        contract_name: &str,
        function_name: &str,
        server_variant: bool,
        script_hex: &str,
    ) -> Result<(), String> {
        // ── Stub ─────────────────────────────────────────────────────────────
        // HTTP client not yet implemented.  Emit a clear warning so callers
        // know no real validation is performed, then return an error so that
        // a misconfigured CI job doesn't silently pass.
        //
        // TODO: replace with an actual HTTP call once the arkd 2.7 RPC schema
        // is confirmed (see comment block above for the expected request shape).
        // Add `reqwest` or `ureq` as an optional dev-dependency gated on
        // `arkd-integration` at that point.
        println!(
            "[arkd-stub] ARKD_URL={url} — HTTP client not implemented; \
             skipping live validation for {contract_name}::{function_name} \
             (server={server_variant})\n  script: {script_hex}"
        );
        Err(format!(
            "submit_to_arkd: HTTP client not implemented \
             (url={url}, contract={contract_name}, fn={function_name})"
        ))
    }

    /// Compile `source` and validate every generated function script against arkd.
    fn validate_contract(source: &str) {
        let url = match arkd_url() {
            Some(u) => u,
            None => {
                println!("[arkd] ARKD_URL not set — skipping live validation");
                return;
            }
        };

        let result = compile(source).expect("compilation must succeed before arkd test");
        let contract_name = result.name.clone();

        for function in &result.functions {
            let script_hex = asm_to_script_hex(&function.asm);
            submit_to_arkd(
                &url,
                &contract_name,
                &function.name,
                function.server_variant,
                &script_hex,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "arkd rejected {}::{} (server={}): {}",
                    contract_name, function.name, function.server_variant, e
                )
            });
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn test_bare_vtxo_against_arkd() {
        let source = fs::read_to_string("examples/bare.ark").expect("examples/bare.ark must exist");
        validate_contract(&source);
    }

    #[test]
    fn test_htlc_against_arkd() {
        let source = fs::read_to_string("examples/htlc.ark").expect("examples/htlc.ark must exist");
        validate_contract(&source);
    }

    #[test]
    fn test_fuji_safe_against_arkd() {
        let source = fs::read_to_string("examples/fuji_safe.ark")
            .expect("examples/fuji_safe.ark must exist");
        validate_contract(&source);
    }
}
