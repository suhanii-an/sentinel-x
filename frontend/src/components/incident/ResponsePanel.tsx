import clsx from 'clsx'
import { CheckCircle2, ShieldOff, TriangleAlert } from 'lucide-react'
import { useState } from 'react'

import { useExecuteAction, useIncidentResponse, useResponseActions } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  EmptyState,
  ErrorState,
  Loading,
  Modal,
  Panel,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import type { IncidentDetail, RecommendedAction } from '@/types'
import { absoluteTime, duration } from '@/utils/format'

const PHASE_TONE: Record<string, string> = {
  investigate: 'text-low',
  contain: 'text-high',
  eradicate: 'text-critical',
  recover: 'text-healthy',
  report: 'text-ink-muted',
}

export function ResponsePanel({ incident }: { incident: IncidentDetail }) {
  const state = useIncidentResponse(incident.incident_id)
  const catalogue = useResponseActions()
  const execute = useExecuteAction()
  const { can } = useAuth()

  const [pending, setPending] = useState<RecommendedAction | null>(null)
  const [justification, setJustification] = useState('')

  if (state.isLoading) return <Loading rows={4} label="Loading response state" />
  if (state.isError) return <ErrorState error={state.error} onRetry={state.refetch} />
  if (!state.data) return null

  const data = state.data
  const specs = new Map(catalogue.data?.actions.map((action) => [action.action_type, action]) ?? [])

  const confirm = async () => {
    if (!pending) return
    await execute.mutateAsync({
      action_type: pending.action_type,
      target: pending.target,
      incident_id: incident.incident_id,
      justification: justification || undefined,
      playbook_id: pending.playbook_id ?? undefined,
    })
    setPending(null)
    setJustification('')
    state.refetch()
  }

  return (
    <div className="space-y-5">
      <Callout tone="warning" title="Every containment action here is simulated">
        {data.simulation_notice}
      </Callout>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-2 space-y-5">
          <Panel
            title="Recommended actions"
            subtitle="Derived deterministically from this incident's own entities — no AI involved"
          >
            {data.recommended_actions.length === 0 ? (
              <EmptyState
                title="Nothing further proposed"
                description="Every containment action the platform would suggest has already been taken."
                icon={<CheckCircle2 className="h-7 w-7 text-healthy" />}
              />
            ) : (
              <ul className="space-y-2">
                {data.recommended_actions.map((action) => {
                  const spec = specs.get(action.action_type)
                  return (
                    <li
                      key={`${action.action_type}-${action.target}`}
                      className="border border-line rounded-md p-3 bg-base"
                    >
                      <div className="flex flex-wrap items-start gap-2">
                        <Badge
                          className={clsx(
                            action.priority === 'high'
                              ? 'border-critical/40 text-critical'
                              : 'border-medium/40 text-medium',
                          )}
                        >
                          {action.priority}
                        </Badge>
                        <div className="min-w-0 flex-1">
                          <p className="text-sm text-ink">
                            {spec?.name ?? action.action_type}{' '}
                            <Code className="ml-1">{action.target}</Code>
                          </p>
                          <p className="text-xs text-ink-muted mt-1">{action.rationale}</p>
                          {spec && (
                            <p className="text-2xs text-ink-faint mt-1.5">
                              <span className="text-ink-muted">In production this would:</span>{' '}
                              {spec.production_behaviour}
                            </p>
                          )}
                        </div>
                        {can('analyst') && (
                          <button
                            type="button"
                            className={spec?.destructive ? 'btn-danger text-xs' : 'btn-secondary text-xs'}
                            onClick={() => setPending(action)}
                          >
                            Simulate
                          </button>
                        )}
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
          </Panel>

          <Panel
            title="Actions taken"
            subtitle={
              data.mttr_seconds !== null
                ? `First containment ${duration(data.mttr_seconds)} after the first alert`
                : 'No containment action recorded yet'
            }
            dense
          >
            {data.actions_taken.length === 0 ? (
              <EmptyState title="No response actions recorded" />
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Action</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Simulated</th>
                      <th>By</th>
                      <th>Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.actions_taken.map((action) => (
                      <tr key={action.action_id}>
                        <td className="mono whitespace-nowrap">{absoluteTime(action.created_at)}</td>
                        <td className="text-ink">{action.action_type.replace(/_/g, ' ')}</td>
                        <td className="mono">{action.target}</td>
                        <td>
                          <Badge
                            className={
                              action.status === 'failed'
                                ? 'border-critical/40 text-critical'
                                : 'border-healthy/40 text-healthy'
                            }
                          >
                            {action.status}
                          </Badge>
                        </td>
                        <td className={action.is_simulated ? 'text-medium' : 'text-healthy'}>
                          {action.is_simulated ? 'Yes' : 'No — performed'}
                        </td>
                        <td className="text-ink-muted">{action.requested_by}</td>
                        <td className="text-xs text-ink-muted max-w-[280px]">
                          {String(
                            action.result?.note ?? action.result?.error ?? action.result?.state ?? '—',
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel title="Containment state">
            <dl className="space-y-3 text-xs">
              <div>
                <dt className="label mb-1">Isolated hosts (simulated)</dt>
                <dd>
                  {data.containment_state.isolated_hosts.length ? (
                    <div className="flex flex-wrap gap-1">
                      {data.containment_state.isolated_hosts.map((host) => (
                        <Badge key={host} className="border-high/40 text-high">
                          <ShieldOff className="h-3 w-3" /> {host}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-ink-faint">None</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="label mb-1">Disabled accounts (simulated)</dt>
                <dd>
                  {data.containment_state.disabled_accounts.length ? (
                    <div className="flex flex-wrap gap-1">
                      {data.containment_state.disabled_accounts.map((user) => (
                        <Badge key={user} className="border-high/40 text-high">
                          {user}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <span className="text-ink-faint">None</span>
                  )}
                </dd>
              </div>
            </dl>
          </Panel>

          {data.playbooks.length > 0 && (
            <Panel
              title="Playbook"
              subtitle={`${data.playbooks[0].name} — matched from the rules that fired`}
            >
              <p className="text-xs text-ink-muted mb-3">{data.playbooks[0].description}</p>
              <ol className="space-y-2.5">
                {data.playbooks[0].steps.map((step) => (
                  <li key={step.order} className="flex gap-2.5">
                    <span className="text-2xs text-ink-faint tabular-nums shrink-0 pt-0.5 w-4">
                      {step.order}
                    </span>
                    <div className="min-w-0">
                      <p className="text-xs text-ink flex items-center gap-1.5">
                        {step.title}
                        <span className={clsx('text-2xs', PHASE_TONE[step.phase])}>
                          {step.phase}
                        </span>
                      </p>
                      <p className="text-2xs text-ink-muted leading-relaxed mt-0.5">{step.detail}</p>
                      {step.reference && (
                        <p className="text-2xs text-ink-faint mt-0.5">→ {step.reference}</p>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
              {data.playbooks.length > 1 && (
                <p className="text-2xs text-ink-faint mt-3">
                  {data.playbooks.length - 1} other playbook(s) also match:{' '}
                  {data.playbooks.slice(1).map((p) => p.name).join(', ')}.
                </p>
              )}
            </Panel>
          )}
        </div>
      </div>

      <Modal
        open={Boolean(pending)}
        onClose={() => setPending(null)}
        title="Confirm simulated action"
        footer={
          <>
            <button type="button" className="btn-secondary" onClick={() => setPending(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn-danger"
              onClick={confirm}
              disabled={execute.isPending}
            >
              Simulate action
            </button>
          </>
        }
      >
        {pending && (
          <div className="space-y-3">
            <div className="flex items-start gap-2">
              <TriangleAlert className="h-5 w-5 text-medium shrink-0 mt-0.5" aria-hidden="true" />
              <div>
                <p className="text-sm text-ink">
                  {specs.get(pending.action_type)?.name ?? pending.action_type} on{' '}
                  <Code>{pending.target}</Code>
                </p>
                <p className="text-xs text-ink-muted mt-1">{pending.rationale}</p>
              </div>
            </div>

            <Callout tone="warning">
              This records a rehearsed action in SENTINEL-X and updates its own state. It does not
              contact any EDR platform, directory service, firewall or cloud provider, and no real
              system is affected.
            </Callout>

            <div>
              <label htmlFor="justification" className="label block mb-1">
                Justification (optional, recorded in the audit log)
              </label>
              <textarea
                id="justification"
                rows={2}
                value={justification}
                onChange={(event) => setJustification(event.target.value)}
                className="input resize-y"
                placeholder="Why this action, now?"
              />
            </div>

            {execute.isError && (
              <p className="text-xs text-critical">{(execute.error as Error).message}</p>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}
