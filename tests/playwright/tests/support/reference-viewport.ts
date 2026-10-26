import { test } from '@playwright/test';

// Skip reference-only cases before browser/page fixtures are constructed.
// Responsive journeys continue to use the ordinary test registration.
export const referenceTest = test.extend<{ _referenceViewport: void }>({
  _referenceViewport: [async ({}, use, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop-1440',
      'This contract runs at the reference viewport.');
    await use();
  }, { auto: true }],
});
