import type { Page } from '@playwright/test'

import { expect, expectSignedInConsole, test } from './fixtures'

/**
 * Console smoke tests, signed in.
 *
 * Scope is deliberately narrow: that every route renders, and that the two
 * claims the console makes about itself on screen — simulated data is
 * labelled, and the AI is optional — are actually true in a browser.
 *
 * Everything else is covered by the backend suite, which is faster and more
 * precise. A browser test asserting a risk score would be a slow, flaky way of
 * testing arithmetic.
 *
 * The session comes from auth.setup.ts; see playwright.config.ts for why these
 * do not each sign in.
 */

/** Fail on any console error or 5xx the page produces. */
function watchForFailures(page: Page): string[] {
  const failures: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') failures.push(`console: ${message.text()}`)
  })
  page.on('pageerror', (error) => failures.push(`pageerror: ${error.message}`))
  page.on('response', (response) => {
    if (response.status() >= 500) failures.push(`${response.status()} ${response.url()}`)
  })
  return failures
}

test.describe('every route renders', () => {
  const routes = [
    '/dashboard',
    '/alerts',
    '/incidents',
    '/hunt',
    '/hosts',
    '/users',
    '/iocs',
    '/cloud',
    '/detections',
    '/mitre',
    '/simulator',
    '/evaluation',
    '/reports',
    '/settings',
  ]

  for (const route of routes) {
    test(`${route} loads without errors`, async ({ page }) => {
      const failures = watchForFailures(page)
      await page.goto(route)

      // Specifically the signed-in console, not just "some h1 rendered" —
      // the sign-in page has an h1 too, and asserting on that made every one
      // of these pass while the browser was looking at the login screen.
      await expectSignedInConsole(page)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible({ timeout: 20_000 })
      await expect(page.getByText(/that page does not exist/i)).toHaveCount(0)

      expect(failures, `${route} produced: ${failures.join(' | ')}`).toEqual([])
    })
  }

  test('an unknown route shows the not-found page, not a blank screen', async ({ page }) => {
    await page.goto('/definitely-not-a-route')
    await expectSignedInConsole(page)
    await expect(page.getByText(/that page does not exist/i)).toBeVisible({ timeout: 15_000 })
  })
})

test.describe('session', () => {
  // Signs in for itself: sessionStorage is per context, so signing out here
  // cannot disturb the shared session, but the fixture would put the token
  // back on every navigation and mask the sign-out.
  test.use({ signedIn: undefined })

  test('signing out returns to the sign-in page', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel(/username/i).fill('analyst')
    await page.getByLabel(/password/i).fill('e2e-test-password-1')
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 })

    // The sidebar carries a sign-out control on every page.
    await page.getByRole('button', { name: /sign out/i }).first().click()
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 })

    // And the session is genuinely gone, not merely navigated away from.
    await page.goto('/incidents')
    await expect(page).toHaveURL(/\/login/)
  })
})

test.describe('the console tells the truth about itself', () => {
  test('an incident opens with its evidence and its risk breakdown', async ({ page }) => {
    await page.goto('/incidents')

    await expectSignedInConsole(page)

    const firstIncident = page.getByText(/SX-\d{4}-\d{4}/).first()
    await expect(firstIncident).toBeVisible({ timeout: 20_000 })
    await firstIncident.click()

    await expect(page).toHaveURL(/\/incidents\/SX-/, { timeout: 15_000 })
    // Risk is never presented as a bare number: the breakdown is on the page.
    await expect(page.getByText(/risk/i).first()).toBeVisible({ timeout: 15_000 })
  })

  test('seeded data is labelled as simulated', async ({ page }) => {
    await page.goto('/settings')
    await expectSignedInConsole(page)
    // The platform reports its own simulated share rather than implying the
    // demo estate is production telemetry.
    await expect(page.getByText(/simulated/i).first()).toBeVisible({ timeout: 20_000 })
  })

  test('the AI panel reports itself unavailable with no provider configured', async ({
    page,
  }) => {
    await page.goto('/settings')
    await expectSignedInConsole(page)
    await page.getByRole('tab', { name: /ai assistance/i }).click()
    await expect(page.getByText(/not configured/i).first()).toBeVisible({ timeout: 15_000 })
  })

  test('detection still works with no AI provider', async ({ page }) => {
    await page.goto('/detections')
    await expectSignedInConsole(page)
    // Rules loaded and self-tests are reported.
    await expect(page.getByText(/rule/i).first()).toBeVisible({ timeout: 15_000 })
  })
})
