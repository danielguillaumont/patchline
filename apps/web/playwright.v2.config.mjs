import base from './playwright.config.mjs';

// Run the versioned v2 fixture separately so the existing v1 suite stays intact.
export default {
  ...base,
  testIgnore: [],
  testMatch: '**/v2-cohorts.spec.mjs',
  outputDir: 'test-results-v2',
  reporter: [['list'], ['html', {outputFolder:'playwright-report-v2',open:'never'}]],
  webServer: {
    ...base.webServer,
    command: 'node scripts/serve-e2e.mjs --v2',
  },
};
