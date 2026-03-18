import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '^/api/auth(?:/.*)?$': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '^/api/cart(?:/.*)?$': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '^/api/orders(?:/.*)?$': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '^/api/products/[^/]+/reviews(?:/.*)?$': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '^/api/upload(?:/.*)?$': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '^/api/products(?:/.*)?$': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/uploads': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
