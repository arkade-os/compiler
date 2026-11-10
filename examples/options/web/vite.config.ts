import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Standalone Arkade covered-call dApp. Base is "./" so the built bundle can be
// served from any sub-path (e.g. GitHub Pages under /examples/options/web).
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: { port: 5180, open: false },
  build: { target: "es2020", outDir: "dist", sourcemap: true },
});
