import base from './playwright.config.mjs';

// Separate browser suite: explicitly opt in to the local-only Explorer UI.
// Existing v1/v2 suites and the Pages preview retain the approved placeholder.
export default {
  ...base,
  testIgnore: [],
  testMatch: '**/explorer-local.spec.mjs',
  outputDir: 'test-results-explorer',
  reporter: [['list'], ['html', {outputFolder:'playwright-report-explorer',open:'never'}]],
  webServer: {
    ...base.webServer,
    env: { ...process.env, VITE_CVE_EXPLORER_LOCAL: '1' },
  },
};
