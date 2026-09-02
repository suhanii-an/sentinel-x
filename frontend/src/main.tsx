import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import { App } from '@/App'
import { ApiError } from '@/api/client'
import { AuthProvider } from '@/hooks/useAuth'
import '@/styles/index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // Retrying an auth or authorization failure achieves nothing except
        // three more audit-log entries.
        if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
          return false
        }
        if (error instanceof ApiError && error.status === 404) return false
        return failureCount < 2
      },
    },
    mutations: { retry: false },
  },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
)
