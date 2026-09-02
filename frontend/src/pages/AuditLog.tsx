/**
 * Audit trail.
 *
 * Append-only by construction: there is no endpoint anywhere in this API that
 * updates or deletes an audit record, so this page is a reader and nothing
 * else. It is admin-only on the server; the role check here only avoids
 * showing a viewer a screen that would 403 on every request.
 *
 * Both successes and failures are recorded, and the failures are the
 * interesting half — a run of `login` / `failure` rows from one address is
 * exactly the signal this platform detects in its own telemetry.
 */
import clsx from 'clsx'
import { ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { useAuditLog } from '@/api/queries'
import {
  Badge,
  Callout,
  EmptyState,
  Modal,
  Pagination,
  Panel,
  QueryBoundary,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { AuditEntry } from '@/types'
import { absoluteTime, relativeTime } from '@/utils/format'

const PAGE_SIZE = 50

/** Actions the platform records. Kept as a hint list, not a filter whitelist —
 *  the server filters on exact strings and new actions appear without a
 *  frontend change. */
const COMMON_ACTIONS = [
  'login',
  'logout',
  'alert_status_changed',
  'incident_status_changed',
  'incident_note_added',
  'response_action_executed',
  'report_generated',
  'report_exported',
  'rule_toggled',
  'simulation_run',
  'evaluation_run',
  'ai_investigation',
  'hunt_executed',
]

const SINCE_OPTIONS = [
  { label: 'Any time', hours: 0 },
  { label: 'Last hour', hours: 1 },
  { label: 'Last 24 hours', hours: 24 },
  { label: 'Last 7 days', hours: 168 },
]

export function AuditLog() {
  const { can, user } = useAuth()
  const [offset, setOffset] = useState(0)
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const [result, setResult] = useState('')
  const [sinceHours, setSinceHours] = useState(0)
  const [selected, setSelected] = useState<AuditEntry | null>(null)

  const since =
    sinceHours > 0 ? new Date(Date.now() - sinceHours * 3600_000).toISOString() : undefined

  const query = useAuditLog({
    limit: PAGE_SIZE,
    offset,
    actor: actor.trim() || undefined,
    action: action || undefined,
    result: result || undefined,
    since,
  })

  const reset = (apply: () => void) => {
    apply()
    setOffset(0)
  }

  if (!can('admin')) {
    return (
      <>
        <PageHeader title="Audit Log" />
        <PageBody>
          <Panel>
            <EmptyState
              icon={<ShieldCheck className="h-7 w-7" />}
              title="Administrator access required"
              description={`The audit trail is restricted to administrators. You are signed in as ${
                user?.username ?? 'an analyst'
              } with the ${user?.role ?? 'viewer'} role. The server enforces this independently of the interface.`}
            />
          </Panel>
        </PageBody>
      </>
    )
  }

  return (
    <>
      <PageHeader
        title="Audit Log"
        description="Every privileged action, who took it, from which address, and whether it succeeded."
      />

      <PageBody className="space-y-5">
        <Callout tone="info" title="Append-only">
          <p>
            No endpoint in this API updates or deletes an audit record — the trail can be read and
            exported, never edited. Failed actions are recorded alongside successful ones, because
            a denied action is often the more interesting event.
          </p>
        </Callout>

        <Panel dense>
          <div className="flex flex-wrap items-end gap-3 px-4 py-3 border-b border-line">
            <div>
              <label htmlFor="audit-actor" className="label block mb-1">
                Actor
              </label>
              <input
                id="audit-actor"
                type="search"
                value={actor}
                onChange={(event) => reset(() => setActor(event.target.value))}
                placeholder="username"
                className="input max-w-[160px]"
              />
            </div>
            <div>
              <label htmlFor="audit-action" className="label block mb-1">
                Action
              </label>
              <select
                id="audit-action"
                value={action}
                onChange={(event) => reset(() => setAction(event.target.value))}
                className="input max-w-[200px]"
              >
                <option value="">All actions</option>
                {COMMON_ACTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value.replace(/_/g, ' ')}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="audit-result" className="label block mb-1">
                Result
              </label>
              <select
                id="audit-result"
                value={result}
                onChange={(event) => reset(() => setResult(event.target.value))}
                className="input max-w-[130px]"
              >
                <option value="">Any result</option>
                <option value="success">success</option>
                <option value="failure">failure</option>
                <option value="denied">denied</option>
              </select>
            </div>
            <div>
              <label htmlFor="audit-since" className="label block mb-1">
                Time
              </label>
              <select
                id="audit-since"
                value={sinceHours}
                onChange={(event) => reset(() => setSinceHours(Number(event.target.value)))}
                className="input max-w-[150px]"
              >
                {SINCE_OPTIONS.map((option) => (
                  <option key={option.hours} value={option.hours}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            {(actor || action || result || sinceHours > 0) && (
              <button
                type="button"
                className="btn-ghost text-xs"
                onClick={() =>
                  reset(() => {
                    setActor('')
                    setAction('')
                    setResult('')
                    setSinceHours(0)
                  })
                }
              >
                Clear filters
              </button>
            )}
          </div>

          <QueryBoundary
            query={query}
            context="Could not load the audit trail"
            empty={{
              title: 'No audit entries match',
              description: 'Clear the filters, or take an action elsewhere in the console to create one.',
            }}
          >
            {(page) => (
              <>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Actor</th>
                        <th>Role</th>
                        <th>Action</th>
                        <th>Target</th>
                        <th>Result</th>
                        <th>Source IP</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((entry) => (
                        <tr key={entry.id}>
                          <td className="whitespace-nowrap" title={absoluteTime(entry.created_at)}>
                            {relativeTime(entry.created_at)}
                          </td>
                          <td className="mono text-ink">{entry.actor}</td>
                          <td>
                            <Badge className="border-line text-ink-faint">
                              {entry.actor_role ?? 'unknown'}
                            </Badge>
                          </td>
                          <td className="text-ink">{entry.action.replace(/_/g, ' ')}</td>
                          <td className="mono text-ink-muted">
                            <TargetCell entry={entry} />
                          </td>
                          <td>
                            <ResultBadge result={entry.result} />
                          </td>
                          <td className="mono text-ink-faint">{entry.ip_address ?? '—'}</td>
                          <td>
                            {Object.keys(entry.details ?? {}).length === 0 ? (
                              <span className="text-ink-faint text-2xs">—</span>
                            ) : (
                              <button
                                type="button"
                                className="btn-ghost text-2xs px-1.5 py-0.5"
                                onClick={() => setSelected(entry)}
                              >
                                view
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pagination
                  total={page.total}
                  limit={PAGE_SIZE}
                  offset={offset}
                  onChange={setOffset}
                />
              </>
            )}
          </QueryBoundary>
        </Panel>
      </PageBody>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected ? `${selected.action.replace(/_/g, ' ')} — entry ${selected.id}` : 'Entry'}
      >
        {selected && (
          <div className="space-y-3">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
              <Field label="Actor" value={selected.actor} />
              <Field label="Role" value={selected.actor_role ?? 'unknown'} />
              <Field label="Result" value={selected.result} />
              <Field label="Source IP" value={selected.ip_address ?? '—'} />
              <Field label="Target type" value={selected.target_type ?? '—'} />
              <Field label="Target" value={selected.target_id ?? '—'} />
              <Field label="Recorded" value={absoluteTime(selected.created_at)} />
            </dl>
            <div>
              <p className="label mb-1">Details</p>
              <pre className="mono bg-base border border-line rounded-md p-3 overflow-auto max-h-72 text-ink-muted whitespace-pre-wrap break-words">
                {JSON.stringify(selected.details, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="label mb-0.5">{label}</dt>
      <dd className="mono text-ink break-words">{value}</dd>
    </div>
  )
}

function ResultBadge({ result }: { result: string }) {
  return (
    <span
      className={clsx(
        'chip',
        result === 'success'
          ? 'border-healthy/40 text-healthy'
          : result === 'denied'
            ? 'border-high/40 text-high'
            : 'border-critical/40 text-critical',
      )}
    >
      {result}
    </span>
  )
}

/** Links a target to the page that shows it, when the type is one with a page. */
function TargetCell({ entry }: { entry: AuditEntry }) {
  if (!entry.target_id) return <span className="text-ink-faint">—</span>

  const routes: Record<string, string> = {
    incident: '/incidents',
    host: '/hosts',
    user: '/users',
    ioc: '/iocs',
  }
  const base = entry.target_type ? routes[entry.target_type] : undefined

  if (!base) {
    return (
      <span title={entry.target_type ?? undefined}>
        {entry.target_type && <span className="text-ink-faint">{entry.target_type}/</span>}
        {entry.target_id}
      </span>
    )
  }

  return (
    <Link to={`${base}/${entry.target_id}`} className="link">
      {entry.target_id}
    </Link>
  )
}
