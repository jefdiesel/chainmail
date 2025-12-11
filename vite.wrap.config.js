import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: '.',
  plugins: [react()],
  server: {
    port: 3001,
  },
  build: {
    outDir: 'dist-app',
    sourcemap: true
  },
  define: {
    'global': 'globalThis',
  }
});
