import { expect, Page } from '@playwright/test';

/** Wait for the requested route's committed, interactive surface. Network
 * silence adds a fixed delay and does not establish application readiness. */
export async function waitForRouteReady(page: Page, name: string) {
  const route = name.toLowerCase();
  const main = page.locator('main');
  await expect(page.getByRole('heading', { level: 1, name, exact: true })).toBeVisible();
  await expect(main).toHaveAttribute('data-requested-view', route);
  await expect(main).toHaveAttribute('data-rendered-view', route);
  await expect(main, `${name} route handoff is complete`).not.toHaveAttribute('aria-busy', 'true');
  const surface = main.locator(`:scope > section[data-route-surface="${route}"]`);
  await expect(surface, `${name} route surface`).toHaveCount(1);
  await expect(surface, `${name} route surface is not busy`).not.toHaveAttribute('aria-busy', 'true');
  await expect(surface, `${name} route surface is interactive`).not.toHaveAttribute('inert', '');
  await expect(surface, `${name} route surface is exposed`).not.toHaveAttribute('aria-hidden', 'true');
  if (name === 'Overview') {
    // Overview mounts before the initial dashboard reads settle. These loaded
    // counters witness the committed response batch, unlike route geometry.
    const summary = surface.locator('dl[aria-label="Overview summary"]');
    await expect(summary).toBeVisible();
    await expect(summary).not.toContainText('Not loaded');
  }
  return surface;
}
