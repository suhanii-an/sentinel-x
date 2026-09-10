import { expect, test as setup } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

import { SESSION_FILE } from './fixtures'

/**
 * Signs in once for the whole run and saves the resulting session.
 *
 * `storageState` is not used: the token is in sessionStorage by design, and
 * storageState does not capture it. See tests/fixtures.ts.
 */
setup('authenticate', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel(/username/i).fill('analyst')
  await page.getByLabel(/password/i).fill('e2e-test-password-1')
  await page.getByRole('button', { name: /sign in/i }).click()

  await expect(page).toHaveURL(/\/dashboard/, { timeout: 30_000 })
  await expect(page.getByRole('navigation', { name: /primary navigation/i })).toBeVisible()

  const session = await page.evaluate(() => ({
    token: sessionStorage.getItem('sentinelx.token') ?? '',
    user: sessionStorage.getItem('sentinelx.user') ?? '',
  }))
  expect(session.token, 'sign-in produced no token').not.toBe('')

  fs.mkdirSync(path.dirname(SESSION_FILE), { recursive: true })
  fs.writeFileSync(SESSION_FILE, JSON.stringify(session))
})
