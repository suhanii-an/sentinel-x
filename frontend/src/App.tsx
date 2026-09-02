import { Suspense, lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import { AppLayout } from '@/layouts/AppLayout'
import { Loading } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { Dashboard } from '@/pages/Dashboard'
import { Login } from '@/pages/Login'

// Route-level code splitting. The dashboard and alert queue are what an analyst
// opens first, so they ship eagerly; the graph- and chart-heavy pages load on
// demand rather than sitting in the initial bundle.
const Alerts = lazy(() => import('@/pages/Alerts').then((m) => ({ default: m.Alerts })))
const Incidents = lazy(() => import('@/pages/Incidents').then((m) => ({ default: m.Incidents })))
const IncidentDetail = lazy(() =>
  import('@/pages/IncidentDetail').then((m) => ({ default: m.IncidentDetail })),
)
const Hunt = lazy(() => import('@/pages/Hunt').then((m) => ({ default: m.Hunt })))
const Hosts = lazy(() => import('@/pages/Hosts').then((m) => ({ default: m.Hosts })))
const HostDetail = lazy(() => import('@/pages/Hosts').then((m) => ({ default: m.HostDetail })))
const Identities = lazy(() => import('@/pages/Identities').then((m) => ({ default: m.Identities })))
const IdentityDetail = lazy(() =>
  import('@/pages/Identities').then((m) => ({ default: m.IdentityDetail })),
)
const Indicators = lazy(() => import('@/pages/Indicators').then((m) => ({ default: m.Indicators })))
const CloudSecurity = lazy(() => import('@/pages/CloudSecurity').then((m) => ({ default: m.CloudSecurity })))
const Detections = lazy(() => import('@/pages/Detections').then((m) => ({ default: m.Detections })))
const Mitre = lazy(() => import('@/pages/Mitre').then((m) => ({ default: m.Mitre })))
const Simulator = lazy(() => import('@/pages/Simulator').then((m) => ({ default: m.Simulator })))
const Evaluation = lazy(() => import('@/pages/Evaluation').then((m) => ({ default: m.Evaluation })))
const Reports = lazy(() => import('@/pages/Reports').then((m) => ({ default: m.Reports })))
const AuditLog = lazy(() => import('@/pages/AuditLog').then((m) => ({ default: m.AuditLog })))
const SettingsPage = lazy(() => import('@/pages/Settings').then((m) => ({ default: m.SettingsPage })))

function RouteFallback() {
  return (
    <div className="p-6">
      <Loading rows={5} label="Loading page" />
    </div>
  )
}

export function App() {
  const { isAuthenticated } = useAuth()

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/login" element={<Navigate to="/dashboard" replace />} />
        <Route element={<AppLayout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
          <Route path="/hunt" element={<Hunt />} />
          <Route path="/hosts" element={<Hosts />} />
          <Route path="/hosts/:hostId" element={<HostDetail />} />
          <Route path="/users" element={<Identities />} />
          <Route path="/users/:userId" element={<IdentityDetail />} />
          <Route path="/iocs" element={<Indicators />} />
          <Route path="/iocs/:iocId" element={<Indicators />} />
          <Route path="/cloud" element={<CloudSecurity />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/mitre" element={<Mitre />} />
          <Route path="/simulator" element={<Simulator />} />
          <Route path="/evaluation" element={<Evaluation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  )
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-2 text-center px-6">
      <p className="text-3xl font-bold text-ink-faint">404</p>
      <p className="text-sm text-ink">That page does not exist.</p>
      <a href="/dashboard" className="link text-sm mt-2">
        Return to the dashboard
      </a>
    </div>
  )
}
