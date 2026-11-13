import base from './playwright.config.mjs';
import { pagesBase } from './scripts/pages-base.mjs';

const siteBase = pagesBase();

// Test the production build at the exact repository subpath before deployment.
export default {
  ...base,
  testMatch: '**/pages-preview.spec.mjs',
  testIgnore: [],
  outputDir: 'test-results-pages',
  reporter: [['list']],
  use: {...base.use, baseURL: 'http://127.0.0.1:4175'},
  webServer: {
    command: `npx vite preview --base ${siteBase} --host 127.0.0.1 --port 4175 --strictPort`,
    url: `http://127.0.0.1:4175${siteBase}`,
    reuseExistingServer: false,
    timeout: 45_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
};
