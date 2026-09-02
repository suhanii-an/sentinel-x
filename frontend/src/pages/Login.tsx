import { AlertCircle } from 'lucide-react'
import { useState } from 'react'

import { ApiError } from '@/api/client'
import { Spinner } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'

export function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await login(username.trim(), password)
    } catch (exception) {
      setError(
        exception instanceof ApiError
          ? exception.message
          : 'Could not reach the SENTINEL-X API. Check that the backend is running.',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center p-6 bg-base">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-3 mb-6">
          <svg viewBox="0 0 32 32" className="h-10 w-10" aria-hidden="true">
            <path
              d="M16 4 26 8v7.8c0 5.7-3.9 10.1-10 12.2-6.1-2.1-10-6.5-10-12.2V8l10-4z"
              fill="none"
              stroke="#22d3ee"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            <path
              d="M11 16h2.4l1.7-4.4 2.2 8.4 1.7-4h2.5"
              fill="none"
              stroke="#22d3ee"
              strokeWidth="1.9"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-ink leading-none">SENTINEL-X</h1>
            <p className="text-xs text-ink-faint mt-1">
              Threat Detection &amp; Investigation Platform
            </p>
          </div>
        </div>

        <form onSubmit={submit} className="panel p-5 space-y-4">
          <div>
            <label htmlFor="username" className="label block mb-1">
              Username
            </label>
            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              required
              autoFocus
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="input"
            />
          </div>

          <div>
            <label htmlFor="password" className="label block mb-1">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="input"
            />
          </div>

          {error && (
            <div
              className="flex items-start gap-2 text-xs text-critical bg-critical/10 border border-critical/30 rounded-md px-3 py-2"
              role="alert"
            >
              <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <button type="submit" className="btn-primary w-full" disabled={busy}>
            {busy && <Spinner />}
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="mt-4 text-2xs text-ink-faint leading-relaxed space-y-2">
          <p>
            Credentials are created by <code className="mono">scripts/seed_database.py</code>, which
            prints them once on first run. There is no default password.
          </p>
          <p>
            All telemetry in this deployment is synthetic and every containment action is simulated.
            No real system is monitored or modified.
          </p>
        </div>
      </div>
    </div>
  )
}
