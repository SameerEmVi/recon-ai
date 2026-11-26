/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Dev server proxies API + WebSocket to the FastAPI backend (api.app) so the
// frontend talks same-origin paths in dev and prod alike. Production build goes
// to dist/, which FastAPI serves as static files. RECON_AI_API overrides the
// backend origin (e.g. a second backend on another port).
const api = process.env.RECON_AI_API ?? "http://127.0.0.1:8787";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: api, changeOrigin: true },
      "/ws": { target: api.replace(/^http/, "ws"), ws: true },
    },
  },
  build: { outDir: "dist", sourcemap: false },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
