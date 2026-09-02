/**
 * Cloud control-plane security.
 *
 * The audit trail of a cloud provider is just another log source to the
 * detection engine — the same rules, the same alerts. What is genuinely
 * different is the *shape* of the risk: there is no host to isolate, the
 * blast radius is an identity's permissions, and the interesting signal is
 * almost always a permission change rather than a process execution. This page
 * is organised around that: accounts, then identities ranked by an explained
 * risk score, then the IAM change feed.
 */
import clsx from 'clsx'
import { Cloud, KeyRound, ShieldAlert, ShieldOff } from 'lucide-react'
import { useState } from 'react'

import { useCloudIdentities, useCloudIdentityGraph, useCloudOverview } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  EmptyState,
  KeyValue,
  Loading,
  Modal,
  Panel,
  QueryBoundary,
  RiskScore,
  SeverityBadge,
} from '@/components/ui'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { CloudIamChange, CloudIdentity } from '@/types'
import { absoluteTime, compactNumber, relativeTime } from '@/utils/format'

const WINDOWS = [
  { label: '24 hours', value: 24 },
  { label: '7 days', value: 168 },
  { label: '30 days', value: 720 },
]

export function CloudSecurity() {
  const [windowHours, setWindowHours] = useState(168)
  const [identity, setIdentity] = useState<string | null>(null)

  const overview = useCloudOverview(windowHours)
  const identities = useCloudIdentities(windowHours)

  return (
    <>
      <PageHeader
        title="Cloud Security"
        description="Control-plane activity from the simulated cloud audit log. Identities are scored on observed behaviour — the factors behind every score are listed, never a single opaque number."
        actions={
          <select
            value={windowHours}
            onChange={(event) => setWindowHours(Number(event.target.value))}
            aria-label="Time window"
            className="input max-w-[140px]"
          >
            {WINDOWS.map((option) => (
              <option key={option.value} value={option.value}>
                Last {option.label}
              </option>
            ))}
          </select>
        }
      />

      <PageBody className="space-y-5">
        <QueryBoundary query={overview} context="Could not load cloud activity">
          {(data) => (
            <>
              <Callout tone="warning" title="Scope">
                <p>{data.notice}</p>
              </Callout>

              <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                <Stat icon={<Cloud className="h-4 w-4" />} label="Accounts" value={data.account_count} />
                <Stat
                  icon={<KeyRound className="h-4 w-4" />}
                  label="Identities seen"
                  value={data.identity_count}
                />
                <Stat label="API calls" value={compactNumber(data.event_count)} />
                <Stat
                  icon={<ShieldAlert className="h-4 w-4" />}
                  label="Privilege operations"
                  value={data.privilege_operations}
                  tone={data.privilege_operations > 0 ? 'high' : undefined}
                />
                <Stat
                  icon={<ShieldOff className="h-4 w-4" />}
                  label="Defense evasion"
                  value={data.defense_evasion_operations}
                  tone={data.defense_evasion_operations > 0 ? 'critical' : undefined}
                />
              </div>

              <Panel title="Accounts" subtitle="Every cloud account that produced control-plane telemetry in this window" dense>
                {data.accounts.length === 0 ? (
                  <EmptyState
                    title="No cloud telemetry in this window"
                    description="Run the cloud_compromise or full_chain scenario from the Simulator."
                  />
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Account</th>
                          <th>Provider</th>
                          <th>Regions</th>
                          <th>Identities</th>
                          <th>API calls</th>
                          <th>Failed</th>
                          <th>Privilege ops</th>
                          <th>Evasion ops</th>
                          <th>Last activity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.accounts.map((account) => (
                          <tr key={account.cloud_account}>
                            <td className="mono text-accent">{account.cloud_account}</td>
                            <td className="text-ink-muted uppercase text-2xs">{account.provider}</td>
                            <td className="text-ink-muted">{account.regions.join(', ') || '—'}</td>
                            <td className="tabular-nums">{account.identity_count}</td>
                            <td className="tabular-nums">{account.event_count}</td>
                            <td className="tabular-nums">
                              {account.failed_count > 0 ? (
                                <span className="text-medium">{account.failed_count}</span>
                              ) : (
                                <span className="text-ink-faint">0</span>
                              )}
                            </td>
                            <td className="tabular-nums">
                              {account.privilege_operations > 0 ? (
                                <span className="text-high font-medium">{account.privilege_operations}</span>
                              ) : (
                                <span className="text-ink-faint">0</span>
                              )}
                            </td>
                            <td className="tabular-nums">
                              {account.defense_evasion_operations > 0 ? (
                                <span className="text-critical font-medium">
                                  {account.defense_evasion_operations}
                                </span>
                              ) : (
                                <span className="text-ink-faint">0</span>
                              )}
                            </td>
                            <td
                              className="whitespace-nowrap text-ink-muted"
                              title={absoluteTime(account.last_seen)}
                            >
                              {relativeTime(account.last_seen)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>

              <IamChangeFeed changes={data.recent_iam_changes} />
            </>
          )}
        </QueryBoundary>

        <Panel
          title="Identity risk"
          subtitle={identities.data?.risk_model}
          dense
        >
          {identities.isLoading && <Loading rows={4} />}
          {identities.data && identities.data.identities.length === 0 && (
            <EmptyState title="No cloud identities in this window" />
          )}
          {identities.data && identities.data.identities.length > 0 && (
            <div className="divide-y divide-line">
              {identities.data.identities.map((entry) => (
                <IdentityRow
                  key={`${entry.cloud_account}:${entry.identity}`}
                  identity={entry}
                  onInspect={() => setIdentity(entry.identity)}
                />
              ))}
            </div>
          )}
        </Panel>

        {identities.data?.notice && (
          <p className="text-2xs text-ink-faint leading-relaxed">{identities.data.notice}</p>
        )}
      </PageBody>

      <IdentityGraphModal identity={identity} onClose={() => setIdentity(null)} />
    </>
  )
}

function Stat({
  label,
  value,
  icon,
  tone,
}: {
  label: string
  value: number | string
  icon?: React.ReactNode
  tone?: 'high' | 'critical'
}) {
  return (
    <div className="panel p-3">
      <div className="flex items-center gap-1.5 text-ink-faint">
        {icon}
        <p className="label">{label}</p>
      </div>
      <p
        className={clsx(
          'text-xl font-bold tabular-nums mt-1',
          tone === 'critical' ? 'text-critical' : tone === 'high' ? 'text-high' : 'text-ink',
        )}
      >
        {value}
      </p>
    </div>
  )
}

function IdentityRow({ identity, onInspect }: { identity: CloudIdentity; onInspect: () => void }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={identity.risk_band} showLabel={false} />
        <button
          type="button"
          className="mono text-accent hover:underline text-sm text-left"
          onClick={onInspect}
        >
          {identity.identity}
        </button>
        <Badge className="border-line text-ink-faint">{identity.identity_type ?? 'unknown type'}</Badge>
        <span className="text-xs text-ink-faint mono">{identity.cloud_account}</span>
        <div className="flex-1 min-w-[120px]">
          <RiskScore score={identity.risk_score} />
        </div>
        <button
          type="button"
          className="btn-ghost text-2xs"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
        >
          {open ? 'Hide' : 'Why this score'}
        </button>
      </div>

      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-2xs text-ink-muted">
        <span>
          <span className="text-ink-faint">API calls</span>{' '}
          <span className="tabular-nums text-ink">{identity.api_calls}</span> across{' '}
          <span className="tabular-nums text-ink">{identity.distinct_apis}</span> operations
        </span>
        {identity.privilege_operations > 0 && (
          <span className="text-high">{identity.privilege_operations} privilege ops</span>
        )}
        {identity.defense_evasion_operations > 0 && (
          <span className="text-critical">
            {identity.defense_evasion_operations} defense-evasion ops
          </span>
        )}
        {identity.denied_attempts > 0 && (
          <span className="text-medium">{identity.denied_attempts} denied</span>
        )}
        {identity.no_mfa_calls > 0 && <span className="text-medium">{identity.no_mfa_calls} without MFA</span>}
        {identity.external_source_ips.length > 0 && (
          <span>
            <span className="text-ink-faint">external source IPs</span>{' '}
            <span className="mono text-ink">{identity.external_source_ips.join(', ')}</span>
          </span>
        )}
      </div>

      {open && (
        <div className="mt-3 bg-base border border-line rounded-md p-3">
          <p className="label mb-2">Risk factors</p>
          {identity.factors.length === 0 ? (
            <p className="text-xs text-ink-faint">
              No risk factors fired. The score is the baseline for an identity with observed activity.
            </p>
          ) : (
            <ul className="space-y-1.5">
              {identity.factors.map((factor) => (
                <li key={factor.factor} className="text-xs flex flex-wrap items-baseline gap-x-2">
                  <span className="text-ink font-medium">{factor.factor.replace(/_/g, ' ')}</span>
                  <span className="mono text-2xs text-ink-faint">
                    weight {factor.weight} × value {factor.value.toFixed(2)} ={' '}
                    <span className="text-accent">+{factor.contribution.toFixed(1)}</span>
                  </span>
                  <span className="text-ink-muted basis-full">{factor.explanation}</span>
                </li>
              ))}
            </ul>
          )}
          {identity.high_risk_policies.length > 0 && (
            <div className="mt-3">
              <p className="label mb-1">High-risk policies touched</p>
              <div className="flex flex-wrap gap-1">
                {identity.high_risk_policies.map((policy) => (
                  <Code key={policy}>{policy}</Code>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function IamChangeFeed({ changes }: { changes: CloudIamChange[] }) {
  return (
    <Panel
      title="IAM changes"
      subtitle="Permission and policy operations, newest first — the control-plane equivalent of privilege escalation on a host"
      dense
    >
      {changes.length === 0 ? (
        <EmptyState title="No IAM changes in this window" />
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Identity</th>
                <th>Operation</th>
                <th>Target</th>
                <th>Policy</th>
                <th>Source IP</th>
                <th>MFA</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {changes.map((change) => (
                <tr key={change.event_id}>
                  <td className="whitespace-nowrap mono" title={absoluteTime(change.timestamp)}>
                    {relativeTime(change.timestamp)}
                  </td>
                  <td className="mono text-accent">{change.identity ?? '—'}</td>
                  <td>
                    <span className="mono text-ink">{change.api_call ?? '—'}</span>
                    {change.risk && (
                      <Badge
                        className={clsx(
                          'ml-1.5',
                          change.risk === 'high' || change.risk === 'critical'
                            ? 'border-high/40 text-high'
                            : 'border-line text-ink-faint',
                        )}
                      >
                        {change.risk}
                      </Badge>
                    )}
                  </td>
                  <td className="mono text-ink-muted">
                    {change.target_principal ?? change.resource ?? '—'}
                  </td>
                  <td className="mono">
                    {change.policy ? (
                      <span className={change.high_risk_policy ? 'text-critical' : 'text-ink-muted'}>
                        {change.policy}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="mono text-ink-muted">{change.source_ip ?? '—'}</td>
                  <td>
                    {change.mfa_authenticated === null ? (
                      <span className="text-ink-faint text-2xs">unknown</span>
                    ) : change.mfa_authenticated ? (
                      <span className="text-healthy text-2xs">yes</span>
                    ) : (
                      <span className="text-medium text-2xs">no</span>
                    )}
                  </td>
                  <td>
                    {change.status === 'success' ? (
                      <span className="text-xs text-ink-muted">success</span>
                    ) : (
                      <span className="text-xs text-medium" title={change.error_code ?? undefined}>
                        {change.error_code ?? change.status}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

/**
 * Identity graph.
 *
 * Deliberately a grouped list rather than a force-directed picture: for a
 * single identity the useful question is "what did it touch, and how often",
 * and a list answers that faster and more accurately than a hairball. The
 * multi-entity attack graph on the incident page is where node layout earns
 * its keep.
 */
function IdentityGraphModal({ identity, onClose }: { identity: string | null; onClose: () => void }) {
  const query = useCloudIdentityGraph(identity ?? undefined)

  return (
    <Modal open={Boolean(identity)} onClose={onClose} title={identity ?? 'Identity'} wide>
      {query.isLoading && <Loading rows={4} />}
      {query.data && (
        <div className="space-y-4">
          <KeyValue
            columns={3}
            items={[
              { label: 'Identity', value: <span className="mono">{query.data.identity}</span> },
              { label: 'Window', value: `${query.data.window_hours} hours` },
              { label: 'Control-plane events', value: query.data.event_count },
            ]}
          />

          {query.data.nodes.length === 0 ? (
            <EmptyState title="No control-plane activity for this identity" />
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {Object.entries(
                query.data.nodes.reduce<Record<string, typeof query.data.nodes>>((groups, node) => {
                  const bucket = groups[node.kind] ?? []
                  bucket.push(node)
                  groups[node.kind] = bucket
                  return groups
                }, {}),
              ).map(([kind, nodes]) => (
                <section key={kind}>
                  <h3 className="label mb-2">
                    {kind.replace(/_/g, ' ')} ({nodes.length})
                  </h3>
                  <ul className="space-y-1">
                    {[...nodes]
                      .sort((a, b) => b.count - a.count)
                      .map((node) => (
                        <li
                          key={node.id}
                          className="flex items-center gap-2 bg-base border border-line rounded-md px-2.5 py-1.5"
                        >
                          <span className="mono text-xs text-ink truncate flex-1">{node.label}</span>
                          <span className="tabular-nums text-2xs text-ink-faint">{node.count}</span>
                        </li>
                      ))}
                  </ul>
                </section>
              ))}
            </div>
          )}

          {query.data.edges.length > 0 && (
            <section>
              <h3 className="label mb-2">Relationships ({query.data.edges.length})</h3>
              <div className="table-wrap max-h-56 overflow-y-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>From</th>
                      <th>Relation</th>
                      <th>To</th>
                      <th>Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {query.data.edges.map((edge) => (
                      <tr key={edge.id}>
                        <td className="mono text-ink-muted">{edge.source}</td>
                        <td className="text-2xs text-accent">{edge.relation.replace(/_/g, ' ')}</td>
                        <td className="mono text-ink-muted">{edge.target}</td>
                        <td className="tabular-nums">{edge.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>
      )}
    </Modal>
  )
}
