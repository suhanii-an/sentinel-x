import { test as base, expect } from '@playwright/test'
import fs from 'node:fs'

export const SESSION_FILE = 'test-results/.session.json'

interface SavedSession {
  token: string
  user: string
}

/**
 * A signed-in page.
 *
 * Playwright's own `storageState` cannot carry this session: the token lives in
 * `sessionStorage`, deliberately — it should die with the browser tab, which is
 * the right default for a console that shows security incidents on shared
 * analyst workstations — and `storageState` persists cookies and localStorage
 * only.
 *
 * So the setup project signs in once, saves what the app put in sessionStorage,
 * and this fixture replays it through an init script that runs before any page
 * script on every navigation. Signing in per test is not an option: the API
 * throttles sign-in attempts to ten a minute per address and that throttle is
 * deliberately not configurable, so the suite would trip its own defences.
 */
export const test = base.extend<{ signedIn: void }>({
  signedIn: [
    async ({ context }, use) => {
      const saved = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8')) as SavedSession
      await context.addInitScript(
        ([token, user]) => {
          try {
            sessionStorage.setItem('sentinelx.token', token)
            sessionStorage.setItem('sentinelx.user', user)
          } catch {
            /* blocked storage: the test will fail on its own assertions */
          }
        },
        [saved.token, saved.user],
      )
      await use()
    },
    { auto: true },
  ],
})

export { expect }

/**
 * Asserts the console is rendered and signed in.
 *
 * The check is deliberately specific. An earlier version asserted only that an
 * `h1` was visible — which the *sign-in* page also has, so every route test
 * passed while the session was silently not restoring and the browser was
 * looking at the login screen the whole time.
 */
export async function expectSignedInConsole(page: import('@playwright/test').Page) {
  await expect(page.getByRole('navigation', { name: /primary navigation/i })).toBeVisible({
    timeout: 20_000,
  })
  await expect(page.getByRole('button', { name: /^sign in$/i })).toHaveCount(0)
}
