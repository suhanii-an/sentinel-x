import type { ApiErrorBody } from '@/types'

const BASE = '/api/v1'
const TOKEN_KEY = 'sentinelx.token'
const USER_KEY = 'sentinelx.user'

/**
 * Token storage.
 *
 * `sessionStorage`, not `localStorage`: the token dies with the browser tab,
 * which is the right default for a console that shows security incidents on
 * shared analyst workstations. It is still readable by any script running on
 * this origin — the real mitigation for that is the strict CSP and the fact
 * that this console loads no third-party script or font at all, not the choice
 * of storage API.
 *
 * Token lifetime is deliberately *not* listed as a mitigation. Tokens last
 * eight hours, there is no server-side deny list, and clearing this key on
 * sign-out does not invalidate the token itself. See docs/threat-model.md §5.
 */
export const tokenStore = {
  get(): string | null {
    try {
      return sessionStorage.getItem(TOKEN_KEY)
    } catch {
      return null
    }
  },
  set(token: string) {
    try {
      sessionStorage.setItem(TOKEN_KEY, token)
    } catch {
      /* private mode or blocked storage: the session simply will not persist */
    }
  },
  clear() {
    try {
      sessionStorage.removeItem(TOKEN_KEY)
      sessionStorage.removeItem(USER_KEY)
    } catch {
      /* nothing to do */
    }
  },
  getUser<T>(): T | null {
    try {
      const raw = sessionStorage.getItem(USER_KEY)
      return raw ? (JSON.parse(raw) as T) : null
    } catch {
      return null
    }
  },
  setUser(user: unknown) {
    try {
      sessionStorage.setItem(USER_KEY, JSON.stringify(user))
    } catch {
      /* nothing to do */
    }
  },
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
  }

  /** True when re-authenticating would plausibly fix this. */
  get isAuthError() {
    return this.status === 401
  }

  get isForbidden() {
    return this.status === 403
  }
}

/** Broadcast so the app shell can redirect to the login screen once, centrally. */
function signalSessionExpired() {
  window.dispatchEvent(new CustomEvent('sentinelx:session-expired'))
}

export interface RequestOptions {
  method?: string
  body?: unknown
  params?: Record<string, string | number | boolean | undefined | null | string[]>
  signal?: AbortSignal
  raw?: boolean
}

function buildUrl(path: string, params?: RequestOptions['params']): string {
  const url = new URL(BASE + path, window.location.origin)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === '') continue
      if (Array.isArray(value)) {
        value.forEach((v) => url.searchParams.append(key, String(v)))
      } else {
        url.searchParams.set(key, String(value))
      }
    }
  }
  return url.pathname + url.search
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, params, signal } = options
  const headers: Record<string, string> = { accept: 'application/json' }

  const token = tokenStore.get()
  if (token) headers.authorization = `Bearer ${token}`
  if (body !== undefined) headers['content-type'] = 'application/json'

  const response = await fetch(buildUrl(path, params), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  })

  if (!response.ok) {
    let code = 'HTTP_ERROR'
    let message = `Request failed with status ${response.status}.`
    let details: unknown
    try {
      const payload = (await response.json()) as ApiErrorBody
      if (payload?.error) {
        code = payload.error.code
        message = payload.error.message
        details = payload.error.details
      }
    } catch {
      /* the body was not the structured error envelope */
    }
    if (response.status === 401 && token) signalSessionExpired()
    throw new ApiError(response.status, code, message, details)
  }

  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

/** Fetch a binary payload (report exports) and hand back a blob. */
export async function requestBlob(path: string): Promise<Blob> {
  const headers: Record<string, string> = {}
  const token = tokenStore.get()
  if (token) headers.authorization = `Bearer ${token}`

  const response = await fetch(BASE + path, { headers })
  if (!response.ok) {
    if (response.status === 401 && token) signalSessionExpired()
    throw new ApiError(response.status, 'DOWNLOAD_FAILED', `Download failed (${response.status}).`)
  }
  return response.blob()
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export const api = {
  get: <T,>(path: string, params?: RequestOptions['params'], signal?: AbortSignal) =>
    request<T>(path, { params, signal }),
  post: <T,>(path: string, body?: unknown, params?: RequestOptions['params']) =>
    request<T>(path, { method: 'POST', body, params }),
  patch: <T,>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  delete: <T,>(path: string) => request<T>(path, { method: 'DELETE' }),
}
