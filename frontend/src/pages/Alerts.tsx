import clsx from 'clsx'
import { Filter, X } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import { useAlert, useAlertStats, useAlerts, useUpdateAlertStatus } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  Modal,
  Pagination,
  Panel,
  RiskScore,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { Alert } from '@/types'
import { absoluteTime, durationMs, relativeTime } from '@/utils/format'
import { SEVERITY_ORDER, severityMeta } from '@/utils/severity'

const STATUSES = ['new', 'investigating', 'escalated', 'resolved', 'false_positive'] as const
const PAGE_SIZE = 50

export function Alerts() {
  const [params, setParams] = useSearchParams()
  const [offset, setOffset] = useState(0)

  const severity = params.getAll('severity')
  const status = params.getAll('status')
  const search = params.get('q') ?? ''
  const selectedId = params.get('alert')

  const query = useAlerts({
    limit: PAGE_SIZE,
    offset,
    severity: severity.length ? severity : undefined,
    status: status.length ? status : undefined,
    q: search || undefined,
    sort: 'detected_at',
    order: 'desc',
  })
  const stats = useAlertStats()

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

  const setSearch = (value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set('q', value)
    else next.delete('q')
    setParams(next, { replace: true })
    setOffset(0)
  }

  const activeFilters = severity.length + status.length + (search ? 1 : 0)

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Every detection the engine produced, newest first. An alert is a rule's verdict on specific events — open one to see exactly which."
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
              <X className="h-3.5 w-3.5" />
              Clear {activeFilters} filter{activeFilters === 1 ? '' : 's'}
            </button>
          )
        }
      >
        <div className="px-4 sm:px-6 pb-3 flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex items-center gap-1.5">
            <Filter className="h-3.5 w-3.5 text-ink-faint" aria-hidden="true" />
            <span className="label">Severity</span>
            {SEVERITY_ORDER.map((value) => {
              const active = severity.includes(value)
              const meta = severityMeta(value)
              const count = stats.data?.by_severity[value] ?? 0
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
                  <span className="tabular-nums opacity-70">{count}</span>
                </button>
              )
            })}
          </div>

          <div className="flex items-center gap-1.5">
            <span className="label">Status</span>
            {STATUSES.map((value) => {
              const active = status.includes(value)
              const count = stats.data?.by_status[value] ?? 0
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
                  <span className="tabular-nums opacity-70">{count}</span>
                </button>
              )
            })}
          </div>

          <input
            type="search"
            defaultValue={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter by title or rule…"
            aria-label="Filter alerts"
            className="input max-w-xs ml-auto"
          />
        </div>
      </PageHeader>

      <PageBody>
        <Panel dense>
          {query.isLoading && <Loading rows={8} label="Loading alerts" />}
          {query.isError && <ErrorState error={query.error} onRetry={query.refetch} />}
          {query.data && query.data.items.length === 0 && (
            <EmptyState
              title="No alerts match these filters"
              description={
                activeFilters
                  ? 'Try removing a filter, or widen the severity selection.'
                  : 'Run a scenario from the Simulator page to generate detections.'
              }
              action={
                <Link to="/simulator" className="btn-primary">
                  Open the simulator
                </Link>
              }
            />
          )}
          {query.data && query.data.items.length > 0 && (
            <>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Detected</th>
                      <th>Severity</th>
                      <th>Risk</th>
                      <th>Detection</th>
                      <th>Host</th>
                      <th>Account</th>
                      <th>Source</th>
                      <th>ATT&CK</th>
                      <th>Conf.</th>
                      <th>Status</th>
                      <th>Incident</th>
                    </tr>
                  </thead>
                  <tbody>
                    {query.data.items.map((alert) => (
                      <AlertRow
                        key={alert.alert_id}
                        alert={alert}
                        onSelect={() => {
                          const next = new URLSearchParams(params)
                          next.set('alert', alert.alert_id)
                          setParams(next, { replace: true })
                        }}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination
                total={query.data.total}
                limit={PAGE_SIZE}
                offset={offset}
                onChange={setOffset}
              />
            </>
          )}
        </Panel>
      </PageBody>

      <AlertDetailModal
        alertId={selectedId}
        onClose={() => {
          const next = new URLSearchParams(params)
          next.delete('alert')
          setParams(next, { replace: true })
        }}
      />
    </>
  )
}

function AlertRow({ alert, onSelect }: { alert: Alert; onSelect: () => void }) {
  return (
    <tr
      className="cursor-pointer"
      onClick={onSelect}
      tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onSelect()
        }
      }}
    >
      <td className="whitespace-nowrap">
        <span className="text-ink" title={absoluteTime(alert.detected_at)}>
          {relativeTime(alert.detected_at)}
        </span>
      </td>
      <td>
        <SeverityBadge severity={alert.severity} />
      </td>
      <td>
        <RiskScore score={alert.risk_score} showBar={false} />
      </td>
      <td className="max-w-[320px]">
        <p className="text-ink truncate">{alert.title}</p>
        <Code className="mt-0.5 inline-block">{alert.rule_id}</Code>
      </td>
      <td className="mono">
        {alert.host_ref ? (
          <Link to={`/hosts/${alert.host_ref}`} className="link" onClick={(e) => e.stopPropagation()}>
            {alert.host_ref}
          </Link>
        ) : (
          <span className="text-ink-faint">—</span>
        )}
      </td>
      <td className="mono">
        {alert.user_ref ? (
          <Link to={`/users/${alert.user_ref}`} className="link" onClick={(e) => e.stopPropagation()}>
            {alert.user_ref}
          </Link>
        ) : (
          <span className="text-ink-faint">—</span>
        )}
      </td>
      <td className="mono text-ink-muted">{alert.source_ip ?? '—'}</td>
      <td>
        <div className="flex flex-wrap gap-1 max-w-[150px]">
          {alert.technique_ids.slice(0, 3).map((technique) => (
            <Badge key={technique} className="border-accent/30 text-accent/90">
              {technique}
            </Badge>
          ))}
          {alert.technique_ids.length > 3 && (
            <span className="text-2xs text-ink-faint">+{alert.technique_ids.length - 3}</span>
          )}
        </div>
      </td>
      <td>
        <ConfidenceBadge value={alert.confidence} />
      </td>
      <td>
        <StatusBadge status={alert.status} />
      </td>
      <td className="mono">
        {alert.incident_id ? (
          <Link
            to={`/incidents/${alert.incident_id}`}
            className="link"
            onClick={(e) => e.stopPropagation()}
          >
            {alert.incident_id}
          </Link>
        ) : (
          <span className="text-ink-faint">—</span>
        )}
      </td>
    </tr>
  )
}

function AlertDetailModal({ alertId, onClose }: { alertId: string | null; onClose: () => void }) {
  const query = useAlert(alertId ?? undefined)
  const update = useUpdateAlertStatus()
  const { can } = useAuth()
  const [status, setStatus] = useState('')
  const [reason, setReason] = useState('')

  const alert = query.data
  const needsReason = status === 'false_positive'

  const submit = async () => {
    if (!alert || !status) return
    await update.mutateAsync({ alertId: alert.alert_id, status, reason: reason || undefined })
    setStatus('')
    setReason('')
  }

  return (
    <Modal open={Boolean(alertId)} onClose={onClose} title={alertId ?? 'Alert'} wide>
      {query.isLoading && <Loading rows={4} />}
      {query.isError && <ErrorState error={query.error} onRetry={query.refetch} />}
      {alert && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <RiskScore score={alert.risk_score} />
            {alert.is_demo && <Badge className="border-line-strong">SIMULATED</Badge>}
          </div>

          <h3 className="text-base font-semibold text-ink">{alert.title}</h3>

          <KeyValue
            columns={3}
            items={[
              { label: 'Rule', value: <Code>{alert.rule_id}</Code> },
              { label: 'Rule type', value: alert.rule_type },
              { label: 'Confidence', value: <ConfidenceBadge value={alert.confidence} /> },
              { label: 'Detected at', value: absoluteTime(alert.detected_at) },
              {
                label: 'Detection latency',
                value: durationMs(alert.detection_latency_ms),
                title: 'Time from the first event of the activity to the event that triggered this rule.',
              },
              {
                label: 'Incident',
                value: alert.incident_id ? (
                  <Link to={`/incidents/${alert.incident_id}`} className="link">
                    {alert.incident_id}
                  </Link>
                ) : (
                  'Not correlated'
                ),
              },
            ]}
          />

          <section>
            <h4 className="label mb-2">Why this fired</h4>
            <ul className="space-y-1.5">
              {alert.explanation.map((line, index) => (
                <li key={index} className="text-sm text-ink-muted flex gap-2">
                  <span className="text-accent shrink-0" aria-hidden="true">
                    ›
                  </span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </section>

          <section>
            <h4 className="label mb-2">Risk score breakdown</h4>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Weight</th>
                  <th>Value</th>
                  <th>Contribution</th>
                  <th>Basis</th>
                </tr>
              </thead>
              <tbody>
                {alert.risk_breakdown.map((component) => (
                  <tr key={component.factor}>
                    <td className="capitalize text-ink">{component.factor}</td>
                    <td className="tabular-nums text-ink-muted">{component.weight.toFixed(2)}</td>
                    <td className="tabular-nums text-ink-muted">{component.value.toFixed(2)}</td>
                    <td className="tabular-nums text-ink">{component.contribution.toFixed(1)}</td>
                    <td className="text-ink-muted text-xs">{component.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section>
            <h4 className="label mb-2">Evidence ({alert.evidence.length} events)</h4>
            <div className="table-wrap max-h-64 overflow-y-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Type</th>
                    <th>Host</th>
                    <th>Account</th>
                    <th>Action</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {alert.evidence.map((event) => (
                    <tr key={event.event_id}>
                      <td className="mono whitespace-nowrap">{absoluteTime(event.timestamp)}</td>
                      <td className="mono text-ink-faint">{event.event_id}</td>
                      <td>{event.event_type}</td>
                      <td className="mono">{event.host_ref ?? '—'}</td>
                      <td className="mono">{event.user_ref ?? '—'}</td>
                      <td>{event.action ?? '—'}</td>
                      <td className={event.status === 'failure' ? 'text-high' : 'text-ink-muted'}>
                        {event.status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {alert.false_positive_reason && (
            <Callout tone="info" title="Marked as a false positive">
              <p>{alert.false_positive_reason}</p>
              <p className="mt-1 text-ink-faint">
                by {alert.triaged_by} at {absoluteTime(alert.triaged_at)}
              </p>
            </Callout>
          )}

          {can('analyst') && (
            <section className="border-t border-line pt-4">
              <h4 className="label mb-2">Triage</h4>
              <div className="flex flex-wrap items-start gap-2">
                <select
                  value={status}
                  onChange={(event) => setStatus(event.target.value)}
                  aria-label="New alert status"
                  className="input max-w-[200px]"
                >
                  <option value="">Change status…</option>
                  {STATUSES.filter((value) => value !== alert.status).map((value) => (
                    <option key={value} value={value}>
                      {value.replace('_', ' ')}
                    </option>
                  ))}
                </select>
                {needsReason && (
                  <input
                    type="text"
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder="Why is this benign? (required)"
                    aria-label="False positive reason"
                    className="input flex-1 min-w-[240px]"
                  />
                )}
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!status || (needsReason && !reason.trim()) || update.isPending}
                  onClick={submit}
                >
                  Apply
                </button>
              </div>
              {needsReason && (
                <p className="text-2xs text-ink-faint mt-2">
                  A reason is required. It becomes the record of why this detection was wrong, which
                  is what makes the rule improvable.
                </p>
              )}
              {update.isError && (
                <p className="text-xs text-critical mt-2">{(update.error as Error).message}</p>
              )}
            </section>
          )}
        </div>
      )}
    </Modal>
  )
}
