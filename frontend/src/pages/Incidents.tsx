import clsx from 'clsx'
import { X } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { useIncidents } from '@/api/queries'
import {
  Badge,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  Loading,
  Pagination,
  Panel,
  RiskScore,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, duration, relativeTime } from '@/utils/format'
import { SEVERITY_ORDER, severityMeta } from '@/utils/severity'

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive'] as const
const PAGE_SIZE = 25

export function Incidents() {
  const [params, setParams] = useSearchParams()
  const [offset, setOffset] = useState(0)

  const severity = params.getAll('severity')
  const status = params.getAll('status')

  const query = useIncidents({
    limit: PAGE_SIZE,
    offset,
    severity: severity.length ? severity : undefined,
    status: status.length ? status : undefined,
    sort: 'last_seen',
    order: 'desc',
  })

  const toggle = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    const current = next.getAll(key)
    next.delete(key)
    const updated = current.includes(value)
      ? current.filter((entry) => entry !== value)
      : [...current, value]
    updated.forEach((entry) => next.append(key, entry))
    setParams(next, { replace: true })
    setOffset(0)
  }

  const activeFilters = severity.length + status.length

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Alerts that share an entity and fall within the correlation window are assembled into one incident. Each carries the reasoning behind that decision."
        actions={
          activeFilters > 0 && (
            <button
              type="button"
              className="btn-ghost text-xs"
              onClick={() => {
                setParams(new URLSearchParams(), { replace: true })
                setOffset(0)
              }}
            >
              <X className="h-3.5 w-3.5" /> Clear filters
            </button>
          )
        }
      >
        <div className="px-4 sm:px-6 pb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-1.5">
            <span className="label">Severity</span>
            {SEVERITY_ORDER.slice(0, 4).map((value) => {
              const active = severity.includes(value)
              const meta = severityMeta(value)
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => toggle('severity', value)}
                  aria-pressed={active}
                  className={clsx(
                    'chip transition-colors',
                    active ? `${meta.bg} ${meta.border} ${meta.text}` : 'border-line text-ink-muted hover:text-ink',
                  )}
                >
                  {meta.label}
                </button>
              )
            })}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="label">Status</span>
            {STATUSES.map((value) => {
              const active = status.includes(value)
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => toggle('status', value)}
                  aria-pressed={active}
                  className={clsx(
                    'chip transition-colors',
                    active ? 'border-accent/50 bg-accent/10 text-accent' : 'border-line text-ink-muted hover:text-ink',
                  )}
                >
                  {value.replace('_', ' ')}
                </button>
              )
            })}
          </div>
        </div>
      </PageHeader>

      <PageBody className="space-y-3">
        {query.isLoading && <Loading rows={4} label="Loading incidents" />}
        {query.isError && <ErrorState error={query.error} onRetry={query.refetch} />}
        {query.data && query.data.items.length === 0 && (
          <Panel dense>
            <EmptyState
              title="No incidents"
              description={
                activeFilters
                  ? 'No incidents match the selected filters.'
                  : 'Nothing has correlated into an incident yet. Run the full attack chain from the Simulator page.'
              }
              action={
                <Link to="/simulator" className="btn-primary">
                  Run attack scenario
                </Link>
              }
            />
          </Panel>
        )}

        {query.data?.items.map((incident) => (
          <Link
            key={incident.incident_id}
            to={`/incidents/${incident.incident_id}`}
            className="block panel p-4 hover:border-line-strong transition-colors focus-visible:rounded-lg"
          >
            <div className="flex flex-wrap items-start gap-3">
              <div className="flex items-center gap-2 shrink-0">
                <SeverityBadge severity={incident.severity} />
                <span className="mono text-ink-faint">{incident.incident_id}</span>
              </div>
              <h2 className="text-sm font-medium text-ink flex-1 min-w-[240px]">{incident.title}</h2>
              <div className="flex items-center gap-3 shrink-0">
                <StatusBadge status={incident.status} />
                <RiskScore score={incident.risk_score} />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 mt-3 text-xs text-ink-muted">
              <span>
                <span className="text-ink font-medium tabular-nums">{incident.alert_count}</span>{' '}
                detections
              </span>
              <span>
                <span className="text-ink font-medium tabular-nums">{incident.event_count}</span>{' '}
                events
              </span>
              <span>
                <span className="text-ink font-medium tabular-nums">
                  {incident.technique_ids.length}
                </span>{' '}
                techniques
              </span>
              <span>
                Confidence <ConfidenceBadge value={incident.confidence} />
              </span>
              <span title={absoluteTime(incident.first_seen)}>
                Duration{' '}
                <span className="text-ink">
                  {duration(
                    (new Date(incident.last_seen).getTime() -
                      new Date(incident.first_seen).getTime()) /
                      1000,
                  )}
                </span>
              </span>
              <span className="ml-auto" title={absoluteTime(incident.last_seen)}>
                last activity {relativeTime(incident.last_seen)}
              </span>
            </div>

            <div className="flex flex-wrap gap-1.5 mt-2.5">
              {incident.affected_hosts.slice(0, 4).map((host) => (
                <Badge key={host} className="border-accent/25 text-accent/90">
                  {host}
                </Badge>
              ))}
              {incident.affected_users.slice(0, 4).map((user) => (
                <Badge key={user}>{user}</Badge>
              ))}
              {incident.is_demo && (
                <Badge className="border-line-strong text-ink-faint ml-auto">SIMULATED</Badge>
              )}
            </div>
          </Link>
        ))}

        {query.data && query.data.total > PAGE_SIZE && (
          <Panel dense>
            <Pagination
              total={query.data.total}
              limit={PAGE_SIZE}
              offset={offset}
              onChange={setOffset}
            />
          </Panel>
        )}
      </PageBody>
    </>
  )
}
