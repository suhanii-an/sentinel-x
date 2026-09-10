import { expect, test } from '@playwright/test'

/**
 * Tests that must start signed out.
 *
 * Their own project, with no stored session — the rest of the suite reuses one
 * sign-in, and these would be meaningless inside it.
 */

test('an unauthenticated visitor is sent to the sign-in page', async ({ page }) => {
  await page.goto('/incidents')
  await expect(page).toHaveURL(/\/login/)
})

test('a wrong password is refused and says so', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel(/username/i).fill('analyst')
  await page.getByLabel(/password/i).fill('not-the-password')
  await page.getByRole('button', { name: /sign in/i }).click()

  await expect(page.getByRole('alert')).toBeVisible({ timeout: 20_000 })
  await expect(page).toHaveURL(/\/login/)
})

test('an unknown account is refused the same way as a wrong password', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel(/username/i).fill('nobody-at-all')
  await page.getByLabel(/password/i).fill('not-the-password')
  await page.getByRole('button', { name: /sign in/i }).click()

  // Same message, because a different one would make sign-in an account
  // enumeration oracle.
  await expect(page.getByRole('alert')).toContainText(/invalid username or password/i, {
    timeout: 20_000,
  })
})
