import { devices } from '@playwright/test';
import base from './playwright.config.mjs';

// Manual screenshot curation. Uses verified v2 synthetic data in an isolated
// server; does not modify the developer's ordinary public/demo directory.
export default {
  ...base,
  testDir: './tests/portfolio',
  testIgnore: [],
  testMatch: '**/portfolio.spec.mjs',
  fullyParallel: false,
  retries: 0,
  workers: 1,
  projects: [
    {
      name: 'portfolio-chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 },
    },
  ],
  reporter: [['list']],
  outputDir: 'test-results-portfolio',
  webServer: {
    ...base.webServer,
    command: 'node scripts/serve-e2e.mjs --v2',
  },
};
