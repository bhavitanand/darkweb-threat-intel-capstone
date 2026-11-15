import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// In dev, /api is proxied to the DarkLens backend (python -m darklens serve, port 8000), so no CORS is needed.
// For a production build set VITE_API_URL to the deployed API origin (no trailing slash).
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': 'http://127.0.0.1:8000' } },
  optimizeDeps: { exclude: ['lucide-react'] },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
});
