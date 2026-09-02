import clsx from 'clsx'
import {
  Activity,
  AlertTriangle,
  Blocks,
  Cloud,
  Crosshair,
  FileText,
  FlaskConical,
  Gauge,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  Users,
} from 'lucide-react'
import { type ReactNode, useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'

import { useKpis } from '@/api/queries'
import { GlobalSearch } from '@/components/GlobalSearch'
import { useAuth } from '@/hooks/useAuth'

interface NavItem {
  to: string
  label: string
  icon: typeof LayoutDashboard
  badge?: 'incidents' | 'alerts'
}

/** Ordered by the analyst's workflow, not alphabetically. */
const PRIMARY_NAV: { group: string; items: NavItem[] }[] = [
  {
    group: 'Operations',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/alerts', label: 'Alerts', icon: AlertTriangle, badge: 'alerts' },
      { to: '/incidents', label: 'Incidents', icon: ShieldAlert, badge: 'incidents' },
      { to: '/hunt', label: 'Threat Hunting', icon: Crosshair },
    ],
  },
  {
    group: 'Entities',
    items: [
      { to: '/hosts', label: 'Hosts', icon: Server },
      { to: '/users', label: 'Identities', icon: Users },
      { to: '/iocs', label: 'Indicators', icon: Radar },
      { to: '/cloud', label: 'Cloud', icon: Cloud },
    ],
  },
  {
    group: 'Engineering',
    items: [
      { to: '/detections', label: 'Detections', icon: Blocks },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Activity },
      { to: '/simulator', label: 'Simulator', icon: FlaskConical },
      { to: '/evaluation', label: 'Evaluation', icon: Gauge },
    ],
  },
  {
    group: 'Records',
    items: [
      { to: '/reports', label: 'Reports', icon: FileText },
      { to: '/audit', label: 'Audit Log', icon: ScrollText },
    ],
  },
]

const SIDEBAR_KEY = 'sentinelx.sidebar-collapsed'

export function AppLayout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const { data: kpis } = useKpis()
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return sessionStorage.getItem(SIDEBAR_KEY) === '1'
    } catch {
      return false
    }
  })
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    try {
      sessionStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0')
    } catch {
      /* storage blocked: the preference simply will not persist */
    }
  }, [collapsed])

  // Close the mobile drawer on navigation, or it covers the page just opened.
  useEffect(() => setMobileOpen(false), [location.pathname])

  const badgeFor = (badge?: NavItem['badge']) => {
    if (!kpis) return null
    if (badge === 'incidents') return kpis.active_incidents || null
    if (badge === 'alerts') return kpis.critical_alerts || null
    return null
  }

  return (
    <div className="flex h-full bg-base">
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      <aside
        className={clsx(
          'flex flex-col border-r border-line bg-surface shrink-0 transition-[width] duration-150 z-40',
          collapsed ? 'w-[60px]' : 'w-[216px]',
          'fixed inset-y-0 left-0 lg:static',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
          'transition-transform lg:transition-[width]',
        )}
      >
        <div className="h-14 flex items-center gap-2 px-3 border-b border-line shrink-0">
          <ShieldIcon />
          {!collapsed && (
            <div className="min-w-0">
              <p className="text-sm font-bold tracking-tight text-ink leading-none">SENTINEL-X</p>
              <p className="text-2xs text-ink-faint leading-none mt-1">Threat Detection</p>
            </div>
          )}
        </div>

        {/* The label belongs on the navigation landmark itself, not on the
            <aside> that wraps it: the aside is complementary content (logo,
            nav, footer), and a screen-reader user asking for the page's
            navigation landmarks would not have found this one. */}
        <nav className="flex-1 overflow-y-auto py-3" aria-label="Primary navigation">
          {PRIMARY_NAV.map((section) => (
            <div key={section.group} className="mb-4">
              {!collapsed && <p className="label px-3 mb-1">{section.group}</p>}
              <ul>
                {section.items.map((item) => {
                  const badge = badgeFor(item.badge)
                  return (
                    <li key={item.to}>
                      <NavLink
                        to={item.to}
                        title={collapsed ? item.label : undefined}
                        className={({ isActive }) =>
                          clsx(
                            'flex items-center gap-2.5 px-3 py-1.5 mx-1 rounded text-sm transition-colors relative',
                            isActive
                              ? 'bg-accent/10 text-accent font-medium'
                              : 'text-ink-muted hover:text-ink hover:bg-raised',
                          )
                        }
                      >
                        <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                        {!collapsed && <span className="truncate flex-1">{item.label}</span>}
                        {badge !== null && (
                          <span
                            className={clsx(
                              'tabular-nums text-2xs font-semibold rounded px-1',
                              collapsed
                                ? 'absolute top-0.5 right-0.5 bg-critical text-white'
                                : 'bg-critical/15 text-critical',
                            )}
                          >
                            {badge}
                          </span>
                        )}
                      </NavLink>
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </nav>

        <div className="border-t border-line p-1 shrink-0">
          <NavLink
            to="/settings"
            title={collapsed ? 'Settings' : undefined}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2.5 px-3 py-1.5 rounded text-sm transition-colors',
                isActive ? 'bg-accent/10 text-accent' : 'text-ink-muted hover:text-ink hover:bg-raised',
              )
            }
          >
            <Settings className="h-4 w-4 shrink-0" aria-hidden="true" />
            {!collapsed && <span>Settings</span>}
          </NavLink>
          <button
            type="button"
            onClick={() => setCollapsed((value) => !value)}
            className="hidden lg:flex w-full items-center gap-2.5 px-3 py-1.5 rounded text-sm text-ink-faint hover:text-ink hover:bg-raised transition-colors"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <Menu className="h-4 w-4 shrink-0" aria-hidden="true" />
            {!collapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 border-b border-line bg-surface/80 backdrop-blur flex items-center gap-3 px-3 sm:px-4 shrink-0">
          <button
            type="button"
            className="btn-ghost p-1.5 lg:hidden"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Menu className="h-5 w-5" />
          </button>

          <GlobalSearch />

          <div className="ml-auto flex items-center gap-3">
            <DemoModeIndicator />
            <div className="hidden sm:block text-right leading-tight">
              <p className="text-xs font-medium text-ink">{user?.username}</p>
              <p className="text-2xs text-ink-faint uppercase tracking-wide">{user?.role}</p>
            </div>
            <button
              type="button"
              className="btn-ghost p-1.5"
              onClick={logout}
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto" id="main-content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 32 32" className="h-7 w-7 shrink-0" aria-hidden="true">
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
  )
}

function DemoModeIndicator() {
  return (
    <span
      className="hidden md:inline-flex chip border-line-strong bg-raised text-ink-faint"
      title="All telemetry in this deployment is synthetic and all response actions are simulated."
    >
      DEMO DATA
    </span>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  children?: ReactNode
}) {
  return (
    <div className="border-b border-line bg-surface/40">
      <div className="px-4 sm:px-6 py-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold text-ink">{title}</h1>
          {description && (
            <div className="text-sm text-ink-muted mt-1 max-w-3xl">{description}</div>
          )}
        </div>
        {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
      </div>
      {children}
    </div>
  )
}

export function PageBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx('px-4 sm:px-6 py-5', className)}>{children}</div>
}
