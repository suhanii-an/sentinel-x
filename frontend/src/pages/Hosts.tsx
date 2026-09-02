import clsx from 'clsx'
import { ArrowLeft, ShieldOff } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { useHost, useHostTimeline, useHosts } from '@/api/queries'
import { EventTimeline } from '@/components/EventTimeline'
import {
  Badge,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  Pagination,
  Panel,
  QueryBoundary,
  RiskScore,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, compactNumber, relativeTime } from '@/utils/format'
import { SEVERITY_ORDER } from '@/utils/severity'

const PAGE_SIZE = 50

export function Hosts() {
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const query = useHosts({ limit: PAGE_SIZE, offset, q: search || undefined })

  return (
    <>
      <PageHeader
        title="Hosts"
        description="Asset inventory. Criticality is a real input to the risk model — the same detection on a domain controller and a staging box should not score the same."
        actions={
          <input
            type="search"
            value={search}
            onChange={(event) => {
              setSearch(event.target.value)
              setOffset(0)
            }}
            placeholder="Filter hosts…"
            aria-label="Filter hosts"
            className="input max-w-[220px]"
          />
        }
      />
      <PageBody>
        <Panel dense>
          <QueryBoundary
            query={query}
            empty={{ title: 'No hosts in the inventory', description: 'Run the seed script to populate the demo estate.' }}
            context="Could not load hosts"
          >
            {(page) => (
              <>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Address</th>
                        <th>Environment</th>
                        <th>Criticality</th>
                        <th>State</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((host) => (
                        <tr key={host.host_id}>
                          <td>
                            <Link to={`/hosts/${host.host_id}`} className="link mono">
                              {host.host_id}
                            </Link>
                          </td>
                          <td className="text-ink-muted">{host.hostname}</td>
                          <td className="text-ink-muted">
                            {host.os_family} {host.os_version ?? ''}
                          </td>
                          <td className="mono text-ink-muted">{host.ip_address ?? '—'}</td>
                          <td className="text-ink-muted">{host.environment}</td>
                          <td>
                            <CriticalityBar value={host.criticality} />
                          </td>
                          <td>
                            {host.is_isolated ? (
                              <Badge className="border-high/40 text-high">
                                <ShieldOff className="h-3 w-3" /> isolated (sim)
                              </Badge>
                            ) : (
                              <span className="text-healthy text-xs">active</span>
                            )}
                          </td>
                          <td className="text-ink-muted" title={absoluteTime(host.last_seen)}>
                            {relativeTime(host.last_seen)}
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

function CriticalityBar({ value }: { value: number }) {
  return (
    <span className="flex items-center gap-1" title={`Criticality ${value} of 5`}>
      {Array.from({ length: 5 }).map((_, index) => (
        <span
          key={index}
          className={clsx(
            'h-3 w-1 rounded-sm',
            index < value ? (value >= 4 ? 'bg-high' : 'bg-accent/70') : 'bg-raised',
          )}
          aria-hidden="true"
        />
      ))}
      <span className="sr-only">Criticality {value} of 5</span>
      <span className="text-2xs text-ink-faint tabular-nums ml-1">{value}</span>
    </span>
  )
}

export function HostDetail() {
  const { hostId } = useParams<{ hostId: string }>()
  const query = useHost(hostId)
  const timeline = useHostTimeline(hostId)

  if (query.isLoading) {
    return (
      <PageBody>
        <Loading rows={5} label="Loading host" />
      </PageBody>
    )
  }
  if (query.isError) {
    return (
      <PageBody>
        <ErrorState error={query.error} onRetry={query.refetch} context="Host not found" />
      </PageBody>
    )
  }
  if (!query.data) return null
  const host = query.data

  return (
    <>
      <PageHeader
        title={host.host_id}
        description={
          <span className="text-ink-muted">
            {host.hostname} · {host.os_family} {host.os_version ?? ''}
          </span>
        }
      >
        <div className="px-4 sm:px-6 pb-4 flex flex-wrap items-center gap-x-5 gap-y-2">
          <Link to="/hosts" className="btn-ghost text-xs">
            <ArrowLeft className="h-3.5 w-3.5" /> All hosts
          </Link>
          <CriticalityBar value={host.criticality} />
          <Badge>{host.environment}</Badge>
          {host.is_isolated && (
            <Badge className="border-high/40 text-high">
              <ShieldOff className="h-3 w-3" /> Isolated (simulated) since{' '}
              {absoluteTime(host.isolated_at, false)}
            </Badge>
          )}
          {host.tags.map((tag) => (
            <Badge key={tag} className="border-line text-ink-faint">
              {tag}
            </Badge>
          ))}
        </div>
      </PageHeader>

      <PageBody className="space-y-5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MiniStat label="Events observed" value={compactNumber(host.event_count)} />
          <MiniStat
            label="Alerts"
            value={Object.values(host.alert_counts).reduce((a, b) => a + b, 0)}
          />
          <MiniStat label="Open incidents" value={host.open_incidents.length} />
          <MiniStat label="Accounts seen" value={host.users.length} />
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <Panel className="xl:col-span-2" title="Activity timeline" dense>
            <QueryBoundary query={timeline} context="Could not load host activity">
              {(entries) => <EventTimeline entries={entries} maxHeight={520} />}
            </QueryBoundary>
          </Panel>

          <div className="space-y-5">
            <Panel title="Alert breakdown">
              {Object.keys(host.alert_counts).length === 0 ? (
                <p className="text-xs text-ink-faint">No alerts for this host.</p>
              ) : (
                <ul className="space-y-1.5">
                  {SEVERITY_ORDER.filter((s) => host.alert_counts[s]).map((severity) => (
                    <li key={severity} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={severity} />
                      <span className="text-ink tabular-nums ml-auto">
                        {host.alert_counts[severity]}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Open incidents" dense>
              {host.open_incidents.length === 0 ? (
                <p className="px-4 py-4 text-xs text-ink-faint">No active incidents.</p>
              ) : (
                <ul className="divide-y divide-line/60">
                  {host.open_incidents.map((incident) => (
                    <li key={incident.incident_id} className="px-4 py-2.5">
                      <Link to={`/incidents/${incident.incident_id}`} className="block">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={incident.severity} showLabel={false} />
                          <span className="mono text-accent">{incident.incident_id}</span>
                          <RiskScore score={incident.risk_score} showBar={false} />
                        </div>
                        <p className="text-xs text-ink-muted mt-1 line-clamp-2">{incident.title}</p>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Top processes" dense>
              {host.top_processes.length === 0 ? (
                <p className="px-4 py-4 text-xs text-ink-faint">No process telemetry.</p>
              ) : (
                <ul className="divide-y divide-line/60">
                  {host.top_processes.slice(0, 10).map((process) => (
                    <li key={process.process} className="px-4 py-1.5 flex items-center gap-2">
                      <span className="mono text-ink truncate flex-1">{process.process}</span>
                      <span className="text-2xs text-ink-faint tabular-nums">{process.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Network peers" dense>
              {host.network_peers.length === 0 ? (
                <p className="px-4 py-4 text-xs text-ink-faint">No network telemetry.</p>
              ) : (
                <ul className="divide-y divide-line/60">
                  {host.network_peers.slice(0, 10).map((peer, index) => (
                    <li key={index} className="px-4 py-1.5 flex items-center gap-2">
                      <span className="mono text-ink truncate flex-1">
                        {peer.destination_ip}
                        {peer.port ? `:${peer.port}` : ''}
                      </span>
                      <span className="text-2xs text-ink-faint tabular-nums">
                        {peer.connections}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Accounts observed" dense>
              <div className="p-4 flex flex-wrap gap-1">
                {host.users.length === 0 ? (
                  <p className="text-xs text-ink-faint">None.</p>
                ) : (
                  host.users.map((user) => (
                    <Link key={user} to={`/users/${user}`} className="chip border-line text-ink-muted hover:text-ink">
                      {user}
                    </Link>
                  ))
                )}
              </div>
            </Panel>
          </div>
        </div>

        <Panel title="Recent alerts" dense>
          {host.recent_alerts.length === 0 ? (
            <EmptyState title="No alerts for this host" />
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Detected</th>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Title</th>
                    <th>Conf.</th>
                    <th>Status</th>
                    <th>Incident</th>
                  </tr>
                </thead>
                <tbody>
                  {host.recent_alerts.map((alert) => (
                    <tr key={alert.alert_id}>
                      <td className="whitespace-nowrap" title={absoluteTime(alert.detected_at)}>
                        {relativeTime(alert.detected_at)}
                      </td>
                      <td>
                        <SeverityBadge severity={alert.severity} showLabel={false} />
                      </td>
                      <td className="mono text-ink-muted">{alert.rule_id}</td>
                      <td className="text-ink">{alert.title}</td>
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

        <Panel title="Inventory record">
          <KeyValue
            columns={3}
            items={[
              { label: 'Host ID', value: host.host_id },
              { label: 'Hostname', value: host.hostname },
              { label: 'Operating system', value: `${host.os_family} ${host.os_version ?? ''}` },
              { label: 'Address', value: host.ip_address ?? '—' },
              { label: 'Environment', value: host.environment },
              { label: 'Criticality', value: `${host.criticality} / 5` },
              { label: 'First seen', value: absoluteTime(host.first_seen) },
              { label: 'Last seen', value: absoluteTime(host.last_seen) },
              { label: 'Containment', value: host.is_isolated ? 'Isolated (simulated)' : 'Active' },
            ]}
          />
        </Panel>
      </PageBody>
    </>
  )
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="panel p-3">
      <p className="label">{label}</p>
      <p className="text-xl font-bold text-ink tabular-nums mt-1">{value}</p>
    </div>
  )
}

export { MiniStat }
