import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
      "@shared": resolve(__dirname, "shared"),
      "@core": resolve(__dirname, "core")
    }
  },
  server: {
    port: 5173,
    strictPort: true
  }
});

