import { devices } from '@playwright/test';
import pages from './playwright.pages.config.mjs';

// Manual approved synthetic Pages screenshot curation, not part of ordinary CI.
export default {
  ...pages,
  testDir: './tests/portfolio',
  testMatch: '**/explorer-portfolio.spec.mjs',
  testIgnore: [],
  fullyParallel: false,
  retries: 0,
  workers: 1,
  projects: [{
    name: 'approved-explorer-chromium',
    use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 },
  }],
  outputDir: 'test-results-portfolio',
  reporter: [['list']],
};
