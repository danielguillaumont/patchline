import base from './playwright.config.mjs';

// Test the production build at the exact repository subpath before deployment.
export default {
  ...base,
  testMatch: '**/pages-preview.spec.mjs',
  testIgnore: [],
  outputDir: 'test-results-pages',
  reporter: [['list']],
  use: {...base.use, baseURL: 'http://127.0.0.1:4175'},
  webServer: {
    command: 'npx vite preview --base /patchline/ --host 127.0.0.1 --port 4175 --strictPort',
    url: 'http://127.0.0.1:4175/patchline/',
    reuseExistingServer: false,
    timeout: 45_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
};
