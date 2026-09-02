import clsx from 'clsx'
import { ArrowLeft, KeyRound, UserX } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { useUser, useUserTimeline, useUsers } from '@/api/queries'
import { EventTimeline } from '@/components/EventTimeline'
import {
  Badge,
  Callout,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  Pagination,
  Panel,
  QueryBoundary,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { MiniStat } from '@/pages/Hosts'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, compactNumber, relativeTime } from '@/utils/format'
import { SEVERITY_ORDER } from '@/utils/severity'

const PAGE_SIZE = 50

export function Identities() {
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const query = useUsers({ limit: PAGE_SIZE, offset, q: search || undefined })

  return (
    <>
      <PageHeader
        title="Identities"
        description="Security principals observed in telemetry. These are the accounts under investigation, not the accounts that sign in to SENTINEL-X."
        actions={
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setOffset(0)
            }}
            placeholder="Filter accounts…"
            aria-label="Filter accounts"
            className="input max-w-[220px]"
          />
        }
      />
      <PageBody>
        <Panel dense>
          <QueryBoundary
            query={query}
            empty={{ title: 'No identities recorded' }}
            context="Could not load identities"
          >
            {(page) => (
              <>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Account</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Department</th>
                        <th>Privileged</th>
                        <th>State</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((user) => (
                        <tr key={user.user_id}>
                          <td>
                            <Link to={`/users/${user.user_id}`} className="link mono">
                              {user.user_id}
                            </Link>
                          </td>
                          <td className="text-ink-muted">{user.display_name ?? '—'}</td>
                          <td className="text-ink-muted">{user.user_type}</td>
                          <td className="text-ink-muted">{user.department ?? '—'}</td>
                          <td>
                            {user.is_privileged ? (
                              <Badge className="border-high/40 text-high">
                                <KeyRound className="h-3 w-3" /> privileged
                              </Badge>
                            ) : (
                              <span className="text-ink-faint text-xs">—</span>
                            )}
                          </td>
                          <td>
                            {user.is_disabled ? (
                              <Badge className="border-high/40 text-high">
                                <UserX className="h-3 w-3" /> disabled (sim)
                              </Badge>
                            ) : (
                              <span className="text-healthy text-xs">active</span>
                            )}
                          </td>
                          <td className="text-ink-muted" title={absoluteTime(user.last_seen)}>
                            {relativeTime(user.last_seen)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pagination total={page.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
              </>
            )}
          </QueryBoundary>
        </Panel>
      </PageBody>
    </>
  )
}

export function IdentityDetail() {
  const { userId } = useParams<{ userId: string }>()
  const query = useUser(userId)
  const timeline = useUserTimeline(userId)

  if (query.isLoading) {
    return (
      <PageBody>
        <Loading rows={5} label="Loading identity" />
      </PageBody>
    )
  }
  if (query.isError) {
    return (
      <PageBody>
        <ErrorState error={query.error} onRetry={query.refetch} context="Account not found" />
      </PageBody>
    )
  }
  if (!query.data) return null
  const user = query.data
  const auth = user.authentication_summary

  return (
    <>
      <PageHeader
        title={user.user_id}
        description={
          <span className="text-ink-muted">
            {user.display_name ?? 'No display name'} · {user.user_type}
            {user.department ? ` · ${user.department}` : ''}
          </span>
        }
      >
        <div className="px-4 sm:px-6 pb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          <Link to="/users" className="btn-ghost text-xs">
            <ArrowLeft className="h-3.5 w-3.5" /> All identities
          </Link>
          {user.is_privileged && (
            <Badge className="border-high/40 text-high">
              <KeyRound className="h-3 w-3" /> privileged account
            </Badge>
          )}
          {user.is_disabled && (
            <Badge className="border-high/40 text-high">
              <UserX className="h-3 w-3" /> Disabled (simulated) since{' '}
              {absoluteTime(user.disabled_at, false)}
            </Badge>
          )}
        </div>
      </PageHeader>

      <PageBody className="space-y-5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MiniStat label="Events" value={compactNumber(user.event_count)} />
          <MiniStat label="Successful auths" value={auth.success ?? 0} />
          <MiniStat label="Failed auths" value={auth.failure ?? 0} />
          <MiniStat label="Open incidents" value={user.open_incidents.length} />
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <Panel className="xl:col-span-2" title="Activity timeline" dense>
            <QueryBoundary query={timeline} context="Could not load account activity">
              {(entries) => <EventTimeline entries={entries} maxHeight={520} />}
            </QueryBoundary>
          </Panel>

          <div className="space-y-5">
            <Panel
              title="Behavioural baseline"
              subtitle="What the anomaly rules measure against"
            >
              <BaselineView baseline={user.baseline} />
            </Panel>

            <Panel title="Source addresses" dense>
              {user.source_ips.length === 0 ? (
                <p className="px-4 py-4 text-xs text-ink-faint">No addresses recorded.</p>
              ) : (
                <ul className="divide-y divide-line/60">
                  {user.source_ips.slice(0, 10).map((entry) => (
                    <li key={entry.source_ip} className="px-4 py-1.5 flex items-center gap-2">
                      <span className="mono text-ink flex-1 truncate">{entry.source_ip}</span>
                      <span className="text-2xs text-ink-faint tabular-nums">{entry.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Hosts accessed" dense>
              {user.hosts.length === 0 ? (
                <p className="px-4 py-4 text-xs text-ink-faint">No hosts recorded.</p>
              ) : (
                <ul className="divide-y divide-line/60">
                  {user.hosts.slice(0, 10).map((entry) => (
                    <li key={entry.host} className="px-4 py-1.5 flex items-center gap-2">
                      <Link to={`/hosts/${entry.host}`} className="link mono flex-1 truncate">
                        {entry.host}
                      </Link>
                      <span className="text-2xs text-ink-faint tabular-nums">{entry.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Alert breakdown">
              {Object.keys(user.alert_counts).length === 0 ? (
                <p className="text-xs text-ink-faint">No alerts for this account.</p>
              ) : (
                <ul className="space-y-1.5">
                  {SEVERITY_ORDER.filter((s) => user.alert_counts[s]).map((severity) => (
                    <li key={severity} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={severity} />
                      <span className="text-ink tabular-nums ml-auto">
                        {user.alert_counts[severity]}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </div>

        <Panel title="Recent alerts" dense>
          {user.recent_alerts.length === 0 ? (
            <EmptyState title="No alerts for this account" />
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Detected</th>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Title</th>
                    <th>Host</th>
                    <th>Conf.</th>
                    <th>Status</th>
                    <th>Incident</th>
                  </tr>
                </thead>
                <tbody>
                  {user.recent_alerts.map((alert) => (
                    <tr key={alert.alert_id}>
                      <td className="whitespace-nowrap" title={absoluteTime(alert.detected_at)}>
                        {relativeTime(alert.detected_at)}
                      </td>
                      <td>
                        <SeverityBadge severity={alert.severity} showLabel={false} />
                      </td>
                      <td className="mono text-ink-muted">{alert.rule_id}</td>
                      <td className="text-ink">{alert.title}</td>
                      <td className="mono">{alert.host_ref ?? '—'}</td>
                      <td>
                        <ConfidenceBadge value={alert.confidence} />
                      </td>
                      <td>
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="mono">
                        {alert.incident_id ? (
                          <Link to={`/incidents/${alert.incident_id}`} className="link">
                            {alert.incident_id}
                          </Link>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Identity record">
          <KeyValue
            columns={3}
            items={[
              { label: 'Account', value: user.user_id },
              { label: 'Display name', value: user.display_name ?? '—' },
              { label: 'Type', value: user.user_type },
              { label: 'Department', value: user.department ?? '—' },
              { label: 'Privileged', value: user.is_privileged ? 'Yes' : 'No' },
              { label: 'State', value: user.is_disabled ? 'Disabled (simulated)' : 'Active' },
              { label: 'First seen', value: absoluteTime(user.first_seen) },
              { label: 'Last seen', value: absoluteTime(user.last_seen) },
              {
                label: 'Authentication',
                value: `${auth.success ?? 0} succeeded / ${auth.failure ?? 0} failed`,
              },
            ]}
          />
        </Panel>
      </PageBody>
    </>
  )
}

function BaselineView({ baseline }: { baseline: Record<string, { value: Record<string, unknown>; observations: number }> }) {
  const entries = Object.entries(baseline)
  if (entries.length === 0) {
    return (
      <Callout tone="info">
        No behavioural baseline yet. Anomaly rules stay silent for accounts with too little history —
        with nothing to compare against, "unusual" is a guess rather than a finding.
      </Callout>
    )
  }

  return (
    <div className="space-y-3">
      {entries.map(([feature, data]) => {
        const inner = Object.values(data.value)[0] as Record<string, number> | undefined
        const items = inner ? Object.entries(inner).sort((a, b) => b[1] - a[1]) : []
        const max = Math.max(1, ...items.map(([, count]) => count))
        return (
          <div key={feature}>
            <div className="flex items-baseline justify-between">
              <span className="label">{feature.replace(/_/g, ' ')}</span>
              <span className="text-2xs text-ink-faint tabular-nums">
                {data.observations} observations
              </span>
            </div>
            {feature.includes('hours') ? (
              <HourHistogram hours={(inner ?? {}) as Record<string, number>} />
            ) : (
              <ul className="mt-1 space-y-0.5">
                {items.slice(0, 6).map(([key, count]) => (
                  <li key={key} className="flex items-center gap-2 text-2xs">
                    <span className="mono text-ink-muted truncate flex-1">{key}</span>
                    <span className="h-1 w-12 bg-raised rounded-full overflow-hidden shrink-0">
                      <span
                        className="block h-full bg-accent/60"
                        style={{ width: `${(count / max) * 100}%` }}
                      />
                    </span>
                    <span className="text-ink-faint tabular-nums w-6 text-right">{count}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )
      })}
      <p className="text-2xs text-ink-faint leading-relaxed">
        These are frequency tables, not a machine-learning model. They are inspectable on purpose:
        an analyst can check exactly what "normal" means for this account.
      </p>
    </div>
  )
}

function HourHistogram({ hours }: { hours: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(hours))
  return (
    <div className="flex items-end gap-px h-8 mt-1" role="img" aria-label="Observed activity by hour of day, UTC">
      {Array.from({ length: 24 }).map((_, hour) => {
        const count = hours[String(hour)] ?? 0
        return (
          <span
            key={hour}
            className={clsx('flex-1 rounded-sm', count ? 'bg-accent/60' : 'bg-raised')}
            style={{ height: count ? `${Math.max(12, (count / max) * 100)}%` : '3px' }}
            title={`${String(hour).padStart(2, '0')}:00 UTC — ${count} observation(s)`}
          />
        )
      })}
    </div>
  )
}
