import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const publicDir = process.env.PATCHLINE_E2E_PUBLIC_DIR;
if (!publicDir) {
  throw new Error('PATCHLINE_E2E_PUBLIC_DIR is required for isolated browser tests');
}
export default defineConfig({ plugins: [react()], base: '/', publicDir });
