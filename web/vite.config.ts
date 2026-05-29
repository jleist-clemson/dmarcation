import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The PHP API runs separately (php -S localhost:8000 -t public).
// Proxy /api to it so the browser can use same-origin requests in dev.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
