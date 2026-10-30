// Run: node scripts/benchmark-compiler.mjs [fresh release nodejs WASM directory]
// Requires cargo and wasm-pack. Builds a temporary native harness; no npm dependencies.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir, arch, platform, cpus } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = mkdtempSync(path.join(tmpdir(), 'arkade-compiler-bench-'));
process.on('exit', () => rmSync(temporary, { recursive: true, force: true }));
const samples = 31, batch = 10, warmups = 100, wasmWarmups = 1000, coldSamples = 15;
function run(command, args, input, options = {}) {
    const result = spawnSync(command, args, { cwd: root, input, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, ...options });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, `${command}: ${result.stderr}`);
    return result.stdout;
}
function median(values) {
    return [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
}
function measure(fn, count = samples, repetitions = batch) {
    const times = [];
    for (let sample = 0; sample < count; sample++) {
        const start = performance.now();
        for (let i = 0; i < repetitions; i++) fn();
        times.push((performance.now() - start) / repetitions);
    }
    return median(times);
}
function decode(text) {
    const output = JSON.parse(text);
    output.artifact = JSON.parse(output.artifact);
    delete output.artifact.updatedAt;
    return output;
}

const wasmDirectory = process.argv[2] ? path.resolve(process.argv[2]) : path.join(temporary, 'wasm');
if (!process.argv[2]) {
    run('wasm-pack', ['build', '--release', '--target', 'nodejs', '--out-dir', wasmDirectory, '--', '--features', 'wasm'], undefined, { stdio: 'inherit' });
}
mkdirSync(path.join(temporary, 'src'));
writeFileSync(path.join(temporary, 'Cargo.toml'), `[package]
name = "arkade-compiler-bench"
version = "0.0.0"
edition = "2021"
[workspace]
[dependencies]
arkade-compiler = { path = ${JSON.stringify(root)}, features = ["wasm"] }
serde_json = "1"
`);
writeFileSync(path.join(temporary, 'Cargo.lock'), readFileSync(path.join(root, 'Cargo.lock')));
writeFileSync(path.join(temporary, 'src/main.rs'), `
use std::{collections::BTreeMap, hint::black_box, io::{self, Read}, time::Instant};
fn main() {
    let mode = std::env::args().nth(1).unwrap();
    if mode == "noop" { return; }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let request: serde_json::Value = serde_json::from_str(&input).unwrap();
    let entry = request["entry"].as_str().unwrap();
    let files = request["filesJson"].as_str().unwrap();
    if mode == "once" {
        print!("{}", arkade_compiler::wasm::compile_sources_with_diagnostics(entry, files, Some(true)).unwrap());
        return;
    }
    let parsed: BTreeMap<String, String> = serde_json::from_str(files).unwrap();
    let core = || { black_box(arkade_compiler::compile_sources(entry, &parsed).unwrap()); };
    let direct = || { black_box(arkade_compiler::wasm::compile_sources(entry, files, Some(true)).unwrap()); };
    let diagnostics = || { black_box(arkade_compiler::wasm::compile_sources_with_diagnostics(entry, files, Some(true)).unwrap()); };
    for _ in 0..${warmups} { core(); direct(); diagnostics(); }
    let mut times = [Vec::new(), Vec::new(), Vec::new()];
    for _ in 0..${samples} {
        for (index, call) in [&core as &dyn Fn(), &direct, &diagnostics].iter().enumerate() {
            let start = Instant::now();
            for _ in 0..${batch} { call(); }
            times[index].push(start.elapsed().as_secs_f64() * 1000.0 / ${batch}.0);
        }
    }
    println!("{}", serde_json::to_string(&times).unwrap());
}
`);
run('cargo', ['build', '--offline', '--release', '--manifest-path', path.join(temporary, 'Cargo.toml'), '--target-dir', path.join(root, 'target')], undefined, { stdio: 'inherit' });
const native = path.join(root, 'target/release/arkade-compiler-bench');
const wasmPath = path.join(wasmDirectory, 'arkade_compiler.js');
const initStart = performance.now();
const wasm = createRequire(import.meta.url)(wasmPath);
const initializationMs = performance.now() - initStart;
const cases = [
    ['SingleSig', 'examples/single_sig/single_sig.ark', []],
    ['StructVault', 'examples/struct_vault/struct_vault.ark', []],
    ['StabilityOffer', 'examples/stability/stability_offer.ark', ['examples/stability/stability_vault.ark', 'examples/single_sig/single_sig.ark']],
    ['Endpoint', 'examples/layerzero/endpoint.ark', ['examples/layerzero/receive_marker.ark']],
];
const coldScript = `
const fs = require('node:fs');
const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const start = performance.now();
const wasm = require(process.argv[1]);
const ready = performance.now();
const result = JSON.parse(wasm.compile_sources_with_diagnostics(request.entry, request.filesJson, true));
JSON.parse(result.artifact);
const end = performance.now();
console.log(JSON.stringify({ initializationMs: ready - start, firstCompileMs: end - ready }));
`;
const results = [];
for (const [name, entry, imports] of cases) {
    const files = Object.fromEntries([entry, ...imports].map(file => [file, readFileSync(path.join(root, file), 'utf8')]));
    const filesJson = JSON.stringify(files);
    const input = JSON.stringify({ entry, filesJson });
    const nativeOutput = decode(run(native, ['once'], input));
    const wasmOutput = decode(wasm.compile_sources_with_diagnostics(entry, filesJson, true));
    assert.deepEqual(wasmOutput, nativeOutput, `${name}: native/WASM artifact or warnings differ`);
    const directArtifact = JSON.parse(wasm.compile_sources(entry, filesJson, true));
    delete directArtifact.updatedAt;
    assert.deepEqual(directArtifact, nativeOutput.artifact, `${name}: diagnostics/direct artifact differs`);
    const nativeTimes = JSON.parse(run(native, ['bench'], input)).map(median);
    for (let i = 0; i < wasmWarmups; i++) {
        wasm.compile_sources(entry, filesJson, true);
        wasm.compile_sources_with_diagnostics(entry, filesJson, true);
    }
    const wasmDirectMs = measure(() => wasm.compile_sources(entry, filesJson, true));
    const wasmDiagnosticsMs = measure(() => wasm.compile_sources_with_diagnostics(entry, filesJson, true));
    const wasmWrapperMs = measure(() => {
        const result = JSON.parse(wasm.compile_sources_with_diagnostics(entry, JSON.stringify(files), true));
        JSON.parse(result.artifact);
    });
    const nativeProcessMs = measure(() => decode(run(native, ['once'], input)), coldSamples, 1);
    const initialization = [], firstCompile = [], nodeProcess = [];
    for (let i = 0; i < coldSamples; i++) {
        const start = performance.now();
        const cold = JSON.parse(run(process.execPath, ['-e', coldScript, wasmPath], input));
        nodeProcess.push(performance.now() - start);
        initialization.push(cold.initializationMs);
        firstCompile.push(cold.firstCompileMs);
    }
    results.push({
        name, sourceFiles: Object.keys(files).length, sourceBytes: Buffer.byteLength(Object.values(files).join('')),
        artifactBytes: Buffer.byteLength(JSON.stringify(nativeOutput.artifact)), warnings: nativeOutput.warnings.length,
        nativeCoreMs: nativeTimes[0], nativeDirectMs: nativeTimes[1], nativeDiagnosticsMs: nativeTimes[2],
        wasmDirectMs, wasmDiagnosticsMs, wasmWrapperMs, nativeProcessMs,
        wasmInitializationMs: median(initialization), wasmFirstCompileMs: median(firstCompile), wasmNodeProcessMs: median(nodeProcess),
    });
    console.error(`${name}: native core ${nativeTimes[0].toFixed(3)} ms; native/WASM diagnostics ${nativeTimes[2].toFixed(3)}/${wasmDiagnosticsMs.toFixed(3)} ms; native process ${nativeProcessMs.toFixed(3)} ms`);
}
console.log(JSON.stringify({
    environment: {
        platform: platform(), arch: arch(), cpu: cpus()[0]?.model, node: process.version,
        rust: run('rustc', ['--version']).trim(), wasmPack: run('wasm-pack', ['--version']).trim(), compiler: wasm.version(),
        wasmBytes: statSync(path.join(wasmDirectory, 'arkade_compiler_bg.wasm')).size,
    },
    methodology: {
        units: 'milliseconds; medians of batch-average times', samples, batch, nativeWarmups: warmups, wasmWarmups, coldSamples,
        optimization: 'cargo release; wasm-pack release with wasm-opt; optimize=true',
        nativeCore: 'public compile_sources on an already parsed virtual file map; no JSON serialization',
        bridge: 'same Rust WASM bridge implementation on each target; parses files JSON, compiles and serializes output',
        wasmWrapper: 'diagnostics bridge plus JS input JSON.stringify and both output JSON.parse calls',
        nativeProcess: 'fresh native harness per compile; stdin/out source JSON and diagnostics JSON; JS output decode included',
        wasmCold: 'fresh Node subprocess each sample; initialization and first diagnostic compile + JSON decode isolated inside process',
        parity: 'all artifact fields and warnings match after removing updatedAt; direct output matches diagnostics artifact',
    },
    nativeNoopProcessMs: measure(() => run(native, ['noop']), coldSamples, 1),
    nodeNoopProcessMs: measure(() => run(process.execPath, ['-e', '']), coldSamples, 1),
    initialWasmInitializationMs: initializationMs,
    results,
}, null, 2));
