import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/compliance-status": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/compliance-assessments": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
      "/reports": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
});
