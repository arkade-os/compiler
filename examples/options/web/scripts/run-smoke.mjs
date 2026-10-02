// Bundle the TS smoke test with esbuild's Node API and execute it. Keeps the
// test runnable via `pnpm smoke` without adding a test-runner dependency.
import { build } from "esbuild";

const result = await build({
  entryPoints: ["scripts/smoke.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  write: false,
  logLevel: "warning",
});

const code = result.outputFiles[0].text;
const url = "data:text/javascript;base64," + Buffer.from(code).toString("base64");
await import(url);
