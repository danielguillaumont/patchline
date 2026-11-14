import {defineConfig, devices} from '@playwright/test';
// Isolated Vite development preview; not a Pages deployment path.
export default defineConfig({
  testDir: './tests/review',
  testMatch: '**/*.spec.mjs',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  outputDir: 'test-results',
  use: {baseURL: 'http://127.0.0.1:5187', trace: 'retain-on-failure'},
  projects: [
    {name: 'research-desktop', use: {...devices['Desktop Chrome'], viewport: {width: 1440, height: 900}}},
    {name: 'research-mobile', use: {...devices['Desktop Chrome'], viewport: {width: 390, height: 844}}},
  ],
  webServer: {
    command: 'npx vite --host 127.0.0.1 --port 5187 --strictPort',
    url: 'http://127.0.0.1:5187/research-review.html',
    reuseExistingServer: false, timeout: 45_000, stdout: 'pipe', stderr: 'pipe',
  },
});
