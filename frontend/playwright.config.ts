import { defineConfig, devices } from '@playwright/test'

/**
 * End-to-end tests against the built console and a real backend.
 *
 * These are deliberately few. The backend suite already covers behaviour; what
 * a browser adds is the answer to one question the API tests cannot ask: does
 * the thing an analyst actually opens render, navigate and sign in? A large
 * browser suite duplicating API assertions would be slow and would fail for
 * reasons that have nothing to do with the code under test.
 *
 * Both servers are started by Playwright, so `npm test` needs no setup beyond
 * a Python environment with the backend's dependencies installed.
 */
const BROWSER = {
  ...devices['Desktop Chrome'],
  // Honour a preinstalled browser when the environment provides one (CI images
  // and sandboxes often do) rather than downloading ~150 MB on every run.
  // Falls back to Playwright's own managed browser.
  launchOptions: process.env.CHROMIUM_PATH
    ? { executablePath: process.env.CHROMIUM_PATH }
    : {},
}

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',

  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    // Signs in once and saves the session.
    //
    // Not an optimisation: the API throttles sign-in attempts per address to
    // ten a minute, and that throttle is deliberately not configurable, so a
    // suite that signed in per test would trip its own defences and fail for
    // the right reason at the wrong time. Reusing one session is also how a
    // real analyst uses the console.
    { name: 'setup', testMatch: /auth\.setup\.ts/, use: BROWSER },
    {
      name: 'chromium',
      testMatch: /console\.spec\.ts/,
      dependencies: ['setup'],
      use: BROWSER,
    },
    // The handful of tests that must start signed out get their own project
    // with no stored session.
    {
      name: 'anonymous',
      testMatch: /anonymous\.spec\.ts/,
      use: BROWSER,
    },
  ],

  webServer: [
    {
      // A throwaway SQLite database seeded with the quick demo estate, so the
      // console has incidents to render. Never points at a developer's own
      // database: the seed script would write demo data into it.
      command:
        'python -c "import os,secrets,subprocess,sys,tempfile; ' +
        "d=tempfile.mkdtemp(); " +
        "env={**os.environ,'DATABASE_URL':f'sqlite+pysqlite:///{d}/e2e.db'," +
        "'SECRET_KEY':secrets.token_urlsafe(48),'ENVIRONMENT':'development'," +
        "'AI_PROVIDER':'none','BOOTSTRAP_ADMIN_PASSWORD':'e2e-test-password-1'," +
        "'PYTHONPATH':'.'}; " +
        "subprocess.run([sys.executable,'../scripts/seed_database.py','--quick'],env=env,check=True); " +
        'sys.exit(subprocess.run([sys.executable,\'-m\',\'uvicorn\',\'app.main:app\',\'--port\',\'8001\'],env=env).returncode)"',
      cwd: '../backend',
      url: 'http://127.0.0.1:8001/api/v1/system/health',
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      stdout: 'pipe',
      stderr: 'pipe',
    },
    {
      // `preview` serves the production build, so these tests exercise the
      // bundle that ships rather than the dev server's on-the-fly transform.
      command: 'npm run build && npm run preview -- --port 4173 --strictPort',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      env: { VITE_API_TARGET: 'http://127.0.0.1:8001' },
    },
  ],
})
