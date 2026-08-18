var _a;
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// The dev server proxies /api to the FastAPI backend so the SPA can use
// same-origin relative URLs (no CORS juggling during development).
// Override QS_API_TARGET when port 8000 is taken by another service.
var apiTarget = (_a = process.env.QS_API_TARGET) !== null && _a !== void 0 ? _a : "http://127.0.0.1:8000";
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        proxy: {
            "/api": {
                target: apiTarget,
                changeOrigin: true,
            },
        },
    },
});
