import react from '@vitejs/plugin-react'
import path from 'node:path'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      // The dev server proxies the API so the browser only ever talks to one
      // origin. Keeps CORS out of the development loop and means the same
      // relative API paths work in dev, in preview and behind the production
      // reverse proxy.
      '/api': {
        target: process.env.VITE_API_TARGET ?? 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        // Split the two heaviest dependencies so the initial bundle is not
        // dominated by a graph library the dashboard never uses.
        manualChunks: {
          graph: ['reactflow'],
          charts: ['recharts'],
        },
      },
    },
  },
})
