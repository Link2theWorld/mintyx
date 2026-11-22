/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { mockApi } from "./dev/mockApi";

const backend = "http://127.0.0.1:8088";
// MINTYX_MOCK=1 serves /api from an in-memory fake instead of proxying to Go.
const useMock = process.env.MINTYX_MOCK === "1";

export default defineConfig({
  plugins: [react(), ...(useMock ? [mockApi()] : [])],
  server: {
    proxy: useMock
      ? {}
      : {
          "/api": { target: backend, changeOrigin: false },
          "/sub": { target: backend, changeOrigin: false },
        },
  },
  build: {
    outDir: "dist",
    // dist/unbuilt.html is committed; scripts/clean-dist.mjs clears everything else.
    emptyOutDir: false,
    chunkSizeWarningLimit: 1500,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
