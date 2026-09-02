/* eslint-disable react-refresh/only-export-components --
 * A provider and its consumer hook belong in one module; splitting them to
 * satisfy a hot-reload heuristic would make the context harder to follow for
 * no runtime benefit. The cost is that editing this file does a full reload
 * during development.
 */
import { useQueryClient } from '@tanstack/react-query'
import {
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'

import { api, tokenStore } from '@/api/client'
import type { CurrentUser, LoginResponse, Role } from '@/types'

interface AuthContextValue {
  user: CurrentUser | null
  isAuthenticated: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  /** Role check used to hide (and, on the server, refuse) privileged actions. */
  can: (minimum: Role) => boolean
}

const ROLE_LEVEL: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 }

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(() => tokenStore.getUser<CurrentUser>())
  const queryClient = useQueryClient()

  const logout = useCallback(() => {
    // Best effort: the audit trail should record the sign-out, but a failed
    // request must not prevent the client from clearing its own state.
    api.post('/auth/logout').catch(() => undefined)
    tokenStore.clear()
    setUser(null)
    queryClient.clear()
  }, [queryClient])

  useEffect(() => {
    // The API client broadcasts this when any request returns 401 with a token
    // present, so an expired session is handled once here rather than in every
    // component that happens to be fetching at the time.
    const handler = () => {
      tokenStore.clear()
      setUser(null)
      queryClient.clear()
    }
    window.addEventListener('sentinelx:session-expired', handler)
    return () => window.removeEventListener('sentinelx:session-expired', handler)
  }, [queryClient])

  const login = useCallback(
    async (username: string, password: string) => {
      const response = await api.post<LoginResponse>('/auth/login', { username, password })
      tokenStore.set(response.access_token)
      tokenStore.setUser(response.user)
      setUser(response.user)
      queryClient.clear()
    },
    [queryClient],
  )

  const can = useCallback(
    (minimum: Role) => (user ? ROLE_LEVEL[user.role] >= ROLE_LEVEL[minimum] : false),
    [user],
  )

  const value = useMemo(
    () => ({ user, isAuthenticated: Boolean(user && tokenStore.get()), login, logout, can }),
    [user, login, logout, can],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
