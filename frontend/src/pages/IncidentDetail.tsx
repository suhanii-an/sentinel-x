import clsx from 'clsx'
import { ArrowLeft, ExternalLink, Shield } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'

import {
  useAddIncidentNote,
  useIncident,
  useIncidentEvidence,
  useIncidentGraph,
  useIncidentTimeline,
  useSimilarIncidents,
  useUpdateIncidentStatus,
} from '@/api/queries'
import { AiInvestigationPanel } from '@/components/incident/AiInvestigationPanel'
import { MitrePanel } from '@/components/incident/MitrePanel'
import { ReportPanel } from '@/components/incident/ReportPanel'
import { ResponsePanel } from '@/components/incident/ResponsePanel'
import { EventTimeline } from '@/components/EventTimeline'
import {
  Badge,
  Callout,
  Code,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  Panel,
  QueryBoundary,
  RiskScore,
  SectionHeading,
  SeverityBadge,
  StatusBadge,
  TabPanel,
  Tabs,
} from '@/components/ui'
import { AttackGraph } from '@/graphs/AttackGraph'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { IncidentDetail as IncidentDetailType } from '@/types'
import { absoluteTime, duration, relativeTime, timeOnly } from '@/utils/format'

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive'] as const

export function IncidentDetail() {
  const { incidentId } = useParams<{ incidentId: string }>()
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') ?? 'overview'
  const query = useIncident(incidentId)

  const setTab = (next: string) => {
    const updated = new URLSearchParams(params)
    updated.set('tab', next)
    setParams(updated, { replace: true })
  }

  if (query.isLoading) {
    return (
      <PageBody>
        <Loading rows={6} label="Loading incident" />
      </PageBody>
    )
  }
  if (query.isError) {
    return (
      <PageBody>
        <ErrorState error={query.error} onRetry={query.refetch} context="Incident not available" />
      </PageBody>
    )
  }
  if (!query.data) return null

  const incident = query.data

  return (
    <>
      <PageHeader
        title={incident.incident_id}
        description={<p className="text-ink">{incident.title}</p>}
        actions={<StatusControls incident={incident} />}
      >
        <div className="px-4 sm:px-6 pb-4 flex flex-wrap items-center gap-x-5 gap-y-2">
          <Link to="/incidents" className="btn-ghost text-xs">
            <ArrowLeft className="h-3.5 w-3.5" /> All incidents
          </Link>
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          <div className="flex items-center gap-2">
            <span className="label">Risk</span>
            <RiskScore score={incident.risk_score} />
          </div>
          <div className="flex items-center gap-2">
            <span className="label">Attack-chain confidence</span>
            <ConfidenceBadge value={incident.confidence} />
          </div>
          <span className="text-xs text-ink-muted">
            {incident.alert_count} detections · {incident.event_count} events ·{' '}
            {duration(incident.duration_seconds)}
          </span>
          {incident.is_demo && (
            <Badge className="border-line-strong text-ink-faint">SIMULATED DATA</Badge>
          )}
        </div>
      </PageHeader>

      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'timeline', label: 'Timeline', badge: incident.event_count },
          { id: 'graph', label: 'Attack graph' },
          { id: 'evidence', label: 'Evidence', badge: incident.event_count },
          { id: 'mitre', label: 'ATT&CK', badge: incident.techniques.length },
          { id: 'ai', label: 'AI investigation' },
          { id: 'response', label: 'Response' },
          { id: 'report', label: 'Report' },
          { id: 'similar', label: 'Similar' },
        ]}
        className="bg-surface/40"
      >
        <PageBody>
          <TabPanel id="overview">
            <OverviewTab incident={incident} onRefresh={query.refetch} />
          </TabPanel>
          <TabPanel id="timeline">
            <TimelineTab incidentId={incident.incident_id} />
          </TabPanel>
          <TabPanel id="graph">
            <GraphTab incidentId={incident.incident_id} />
          </TabPanel>
          <TabPanel id="evidence">
            <EvidenceTab incidentId={incident.incident_id} />
          </TabPanel>
          <TabPanel id="mitre">
            <MitrePanel incident={incident} />
          </TabPanel>
          <TabPanel id="ai">
            <AiInvestigationPanel incident={incident} />
          </TabPanel>
          <TabPanel id="response">
            <ResponsePanel incident={incident} />
          </TabPanel>
          <TabPanel id="report">
            <ReportPanel incident={incident} />
          </TabPanel>
          <TabPanel id="similar">
            <SimilarTab incidentId={incident.incident_id} />
          </TabPanel>
        </PageBody>
      </Tabs>
    </>
  )
}

function StatusControls({ incident }: { incident: IncidentDetailType }) {
  const { can, user } = useAuth()
  const update = useUpdateIncidentStatus()
  const [status, setStatus] = useState('')
  const [reason, setReason] = useState('')

  if (!can('analyst')) return null
  const needsReason = status === 'false_positive'

  return (
    <div className="flex flex-wrap items-center gap-2">
      {!incident.assigned_to && (
        <button
          type="button"
          className="btn-secondary text-xs"
          onClick={() =>
            update.mutate({
              incidentId: incident.incident_id,
              status: incident.status,
              assigned_to: user?.username,
            })
          }
        >
          Assign to me
        </button>
      )}
      {incident.assigned_to && (
        <Badge className="border-accent/30 text-accent">Assigned: {incident.assigned_to}</Badge>
      )}
      <select
        value={status}
        onChange={(event) => setStatus(event.target.value)}
        aria-label="Change incident status"
        className="input max-w-[170px] text-xs py-1"
      >
        <option value="">Change status…</option>
        {STATUSES.filter((value) => value !== incident.status).map((value) => (
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
          placeholder="Reason (required)"
          aria-label="False positive reason"
          className="input max-w-[240px] text-xs py-1"
        />
      )}
      <button
        type="button"
        className="btn-primary text-xs"
        disabled={!status || (needsReason && !reason.trim()) || update.isPending}
        onClick={() => {
          update.mutate(
            { incidentId: incident.incident_id, status, reason: reason || undefined },
            { onSuccess: () => { setStatus(''); setReason('') } },
          )
        }}
      >
        Apply
      </button>
    </div>
  )
}

function OverviewTab({
  incident,
  onRefresh,
}: {
  incident: IncidentDetailType
  onRefresh: () => void
}) {
  const { can } = useAuth()
  const addNote = useAddIncidentNote()
  const [note, setNote] = useState('')

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
      <div className="xl:col-span-2 space-y-5">
        <Panel title="Summary" subtitle="Generated deterministically from stored records">
          <p className="text-sm text-ink-muted leading-relaxed">{incident.summary}</p>
        </Panel>

        <Panel
          title="Why was this incident created?"
          subtitle="The correlation decision, with the numbers behind it"
        >
          <WhyPanel incident={incident} />
        </Panel>

        <Panel title="Attack chain" subtitle="Ordered by when each tactic became detectable">
          <AttackChain incident={incident} />
        </Panel>

        <Panel title="Contributing detections" dense>
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
                </tr>
              </thead>
              <tbody>
                {incident.alerts.map((alert) => (
                  <tr key={alert.alert_id}>
                    <td className="mono whitespace-nowrap" title={absoluteTime(alert.detected_at)}>
                      {timeOnly(alert.detected_at)}
                    </td>
                    <td>
                      <SeverityBadge severity={alert.severity} showLabel={false} />
                    </td>
                    <td>
                      <Link to={`/detections?rule=${alert.rule_id}`} className="link mono">
                        {alert.rule_id}
                      </Link>
                    </td>
                    <td className="text-ink">{alert.title}</td>
                    <td>
                      <ConfidenceBadge value={alert.confidence} />
                    </td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <div className="space-y-5">
        <Panel title="Scope">
          <KeyValue
            columns={1}
            items={[
              { label: 'First observed', value: absoluteTime(incident.first_seen) },
              { label: 'Last observed', value: absoluteTime(incident.last_seen) },
              { label: 'Duration', value: duration(incident.duration_seconds) },
              {
                label: 'Time to first containment',
                value:
                  incident.mttr_seconds === null
                    ? 'No containment action taken'
                    : duration(incident.mttr_seconds),
              },
              {
                label: 'Affected hosts',
                value: incident.affected_hosts.length ? (
                  <div className="flex flex-wrap gap-1">
                    {incident.affected_hosts.map((host) => (
                      <Link key={host} to={`/hosts/${host}`} className="chip border-accent/30 text-accent">
                        {host}
                      </Link>
                    ))}
                  </div>
                ) : (
                  'None'
                ),
              },
              {
                label: 'Accounts with successful activity',
                value: incident.affected_users.length ? (
                  <div className="flex flex-wrap gap-1">
                    {incident.affected_users.map((user) => (
                      <Link key={user} to={`/users/${user}`} className="chip border-line-strong text-ink-muted">
                        {user}
                      </Link>
                    ))}
                  </div>
                ) : (
                  'None'
                ),
              },
              {
                label: 'Accounts targeted without success',
                value: incident.targeted_users.length ? (
                  <div className="flex flex-wrap gap-1">
                    {incident.targeted_users.map((user) => (
                      <span key={user} className="chip border-line text-ink-faint">
                        {user}
                      </span>
                    ))}
                  </div>
                ) : (
                  'None'
                ),
                title:
                  'These accounts appear only on failed attempts. They were attacked but show no evidence of compromise.',
              },
              {
                label: 'Source addresses',
                value: incident.source_ips.length
                  ? incident.source_ips.map((ip) => (
                      <span key={ip} className="mono block">
                        {ip}
                      </span>
                    ))
                  : 'None recorded',
              },
            ]}
          />
        </Panel>

        <Panel title="Risk score" subtitle={`${incident.risk_score.toFixed(1)} / 100`}>
          <ScoreBreakdown components={incident.risk_breakdown} suffix="/100" />
        </Panel>

        <Panel
          title="Correlation confidence"
          subtitle={`${(incident.confidence * 100).toFixed(0)}% — how sure the platform is that these detections are one attack`}
        >
          <ScoreBreakdown components={incident.confidence_breakdown} normalized />
        </Panel>

        {incident.ioc_matches.length > 0 && (
          <Panel title="Indicator matches" dense>
            <ul className="divide-y divide-line/60">
              {incident.ioc_matches.map((match, index) => (
                <li key={`${match.ioc_id}-${index}`} className="px-4 py-2 text-xs">
                  <Link to={`/iocs/${match.ioc_id}`} className="link mono">
                    {match.indicator}
                  </Link>
                  <p className="text-ink-faint mt-0.5">
                    {match.ioc_type} · matched on {match.matched_field} · feed confidence{' '}
                    {(match.confidence * 100).toFixed(0)}%
                  </p>
                </li>
              ))}
            </ul>
          </Panel>
        )}

        <Panel title="Analyst notes" dense>
          {incident.notes.length === 0 ? (
            <p className="px-4 py-4 text-xs text-ink-faint">No notes recorded.</p>
          ) : (
            <ul className="divide-y divide-line/60 max-h-64 overflow-y-auto">
              {incident.notes.map((entry, index) => (
                <li key={index} className="px-4 py-2.5">
                  <p className="text-sm text-ink-muted whitespace-pre-wrap">{entry.body}</p>
                  <p className="text-2xs text-ink-faint mt-1">
                    {entry.author} · {relativeTime(entry.created_at)}
                  </p>
                </li>
              ))}
            </ul>
          )}
          {can('analyst') && (
            <div className="p-3 border-t border-line space-y-2">
              <label htmlFor="note" className="sr-only">
                Add a note
              </label>
              <textarea
                id="note"
                rows={3}
                value={note}
                onChange={(event) => setNote(event.target.value)}
                placeholder="Record what you checked and what you concluded…"
                className="input resize-y"
              />
              <button
                type="button"
                className="btn-secondary w-full text-xs"
                disabled={!note.trim() || addNote.isPending}
                onClick={() =>
                  addNote.mutate(
                    { incidentId: incident.incident_id, body: note.trim() },
                    { onSuccess: () => { setNote(''); onRefresh() } },
                  )
                }
              >
                Add note
              </button>
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}

function WhyPanel({ incident }: { incident: IncidentDetailType }) {
  const reason = incident.correlation_reason
  if (!reason?.method) {
    return <p className="text-xs text-ink-faint">No correlation record available.</p>
  }

  const byType = Object.entries(reason.events_by_type ?? {})

  return (
    <div className="space-y-4">
      <p className="text-sm text-ink-muted">
        This incident was assembled by <span className="text-ink">{reason.method}</span> using a{' '}
        <span className="text-ink tabular-nums">{reason.window_seconds}s</span> window. Two alerts
        join the same incident when they share at least one entity <em>and</em> their activity
        windows fall within that window of one another.
      </p>

      <div>
        <SectionHeading>Evidence composition</SectionHeading>
        <p className="text-sm text-ink-muted">
          Correlated from{' '}
          {byType.map(([type, count], index) => (
            <span key={type}>
              <span className="text-ink font-medium tabular-nums">{count}</span>{' '}
              {type.replace(/_/g, ' ')} event{count === 1 ? '' : 's'}
              {index < byType.length - 2 ? ', ' : index === byType.length - 2 ? ' and ' : ''}
            </span>
          ))}
          , producing {reason.alert_count} detections from {reason.contributing_rules?.length ?? 0}{' '}
          distinct rules.
        </p>
      </div>

      {reason.linking_entities?.length > 0 && (
        <div>
          <SectionHeading hint="entities appearing in more than one detection">
            What links these detections
          </SectionHeading>
          <ul className="space-y-1">
            {reason.linking_entities.map((entity) => (
              <li key={entity.entity} className="flex items-center gap-2 text-xs">
                <Code>{entity.entity}</Code>
                <span className="text-ink-faint">appears in</span>
                <span className="text-ink tabular-nums font-medium">{entity.alert_count}</span>
                <span className="text-ink-faint">detections</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {reason.contributing_rules?.length > 0 && (
        <div>
          <SectionHeading>Contributing rules</SectionHeading>
          <div className="flex flex-wrap gap-1">
            {reason.contributing_rules.map((rule) => (
              <Link key={rule} to={`/detections?rule=${rule}`} className="chip border-line text-ink-muted hover:text-ink">
                {rule}
              </Link>
            ))}
          </div>
        </div>
      )}

      {reason.merged_from && reason.merged_from.length > 0 && (
        <Callout tone="info" title="Merged incidents">
          <ul>
            {reason.merged_from.map((merged) => (
              <li key={merged.incident_id}>
                {merged.incident_id} ({merged.alert_count} alerts) was absorbed into this incident at{' '}
                {absoluteTime(merged.merged_at)}.
              </li>
            ))}
          </ul>
        </Callout>
      )}

      <Callout tone="info">
        Correlation is a heuristic. It can merge concurrent unrelated activity on a busy host, and
        it will not merge one campaign whose stages share no entity. The confidence breakdown in the
        sidebar shows how strongly the evidence supports this grouping.
      </Callout>
    </div>
  )
}

function AttackChain({ incident }: { incident: IncidentDetailType }) {
  if (!incident.attack_chain.length) {
    return <p className="text-xs text-ink-faint">No tactic-level reconstruction available.</p>
  }

  return (
    <ol className="space-y-0">
      {incident.attack_chain.map((stage, index) => {
        const last = index === incident.attack_chain.length - 1
        return (
          <li key={stage.tactic_id} className="flex gap-3">
            <div className="flex flex-col items-center shrink-0">
              <span className="h-2.5 w-2.5 rounded-full bg-accent mt-1.5" aria-hidden="true" />
              {!last && <span className="w-px flex-1 bg-line my-1" aria-hidden="true" />}
            </div>
            <div className={clsx('min-w-0 flex-1', last ? 'pb-0' : 'pb-4')}>
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="text-sm font-medium text-ink">{stage.tactic}</span>
                <Code>{stage.tactic_id}</Code>
                <span className="mono text-ink-faint" title={absoluteTime(stage.detected_at)}>
                  detected {timeOnly(stage.detected_at)}
                </span>
                <span className="text-2xs text-ink-faint ml-auto">
                  kill-chain position {stage.order}
                </span>
              </div>
              <div className="flex flex-wrap gap-1 mt-1.5">
                {stage.techniques.map((technique) => (
                  <Link
                    key={technique.technique_id}
                    to={`/mitre?technique=${technique.technique_id}`}
                    className="chip border-accent/25 text-accent/90 hover:border-accent/50"
                    title={technique.name}
                  >
                    {technique.technique_id}
                    <span className="text-ink-faint">{technique.name}</span>
                  </Link>
                ))}
              </div>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

function ScoreBreakdown({
  components,
  suffix,
  normalized,
}: {
  components: IncidentDetailType['risk_breakdown']
  suffix?: string
  normalized?: boolean
}) {
  if (!components?.length) {
    return <p className="text-xs text-ink-faint">No breakdown recorded.</p>
  }
  const max = Math.max(...components.map((c) => c.contribution))

  return (
    <ul className="space-y-2.5">
      {components.map((component) => (
        <li key={component.factor}>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-xs text-ink capitalize">
              {component.factor.replace(/_/g, ' ')}
            </span>
            <span className="text-xs text-ink-muted tabular-nums">
              {normalized
                ? `${(component.contribution * 100).toFixed(1)}%`
                : `${component.contribution.toFixed(1)}${suffix ?? ''}`}
            </span>
          </div>
          <div className="h-1.5 bg-raised rounded-full overflow-hidden my-1">
            <div
              className="h-full bg-accent/70 rounded-full"
              style={{ width: `${max > 0 ? (component.contribution / max) * 100 : 0}%` }}
            />
          </div>
          <p className="text-2xs text-ink-faint leading-snug">{component.explanation}</p>
        </li>
      ))}
    </ul>
  )
}

function TimelineTab({ incidentId }: { incidentId: string }) {
  const query = useIncidentTimeline(incidentId)
  return (
    <Panel
      title="Evidence timeline"
      subtitle="Every event in this incident, in strict chronological order"
      dense
    >
      <QueryBoundary query={query} context="Could not load the timeline">
        {(data) => <EventTimeline entries={data.events} maxHeight={720} />}
      </QueryBoundary>
    </Panel>
  )
}

function GraphTab({ incidentId }: { incidentId: string }) {
  const query = useIncidentGraph(incidentId)
  return (
    <Panel
      title="Attack graph"
      subtitle="Derived from stored relationships between real events — every edge is backed by evidence"
    >
      <QueryBoundary query={query} context="Could not build the attack graph">
        {(graph) => <AttackGraph graph={graph} />}
      </QueryBoundary>
    </Panel>
  )
}

function EvidenceTab({ incidentId }: { incidentId: string }) {
  const query = useIncidentEvidence(incidentId, { limit: 500 })
  return (
    <Panel title="Evidence" subtitle="Every event correlated into this incident" dense>
      <QueryBoundary query={query} context="Could not load evidence">
        {(data) =>
          data.events.length === 0 ? (
            <EmptyState title="No evidence events" />
          ) : (
            <div className="table-wrap max-h-[720px] overflow-y-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Event ID</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Host</th>
                    <th>Account</th>
                    <th>Address</th>
                    <th>Action</th>
                    <th>Status</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {data.events.map((event) => (
                    <tr key={event.event_id}>
                      <td className="mono whitespace-nowrap">{absoluteTime(event.timestamp)}</td>
                      <td className="mono text-ink-faint">{event.event_id}</td>
                      <td>{event.event_type}</td>
                      <td className="text-ink-faint">{event.source}</td>
                      <td className="mono">{event.host_ref ?? '—'}</td>
                      <td className="mono">{event.user_ref ?? '—'}</td>
                      <td className="mono text-ink-muted">{event.source_ip ?? '—'}</td>
                      <td>{event.action ?? '—'}</td>
                      <td className={event.status === 'failure' ? 'text-high' : 'text-ink-muted'}>
                        {event.status}
                      </td>
                      <td
                        className="mono text-ink-faint max-w-[280px] truncate"
                        title={event.command_line ?? event.file_path ?? event.message ?? ''}
                      >
                        {event.command_line ?? event.file_path ?? event.message ?? '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </QueryBoundary>
    </Panel>
  )
}

function SimilarTab({ incidentId }: { incidentId: string }) {
  const query = useSimilarIncidents(incidentId)
  return (
    <Panel
      title="Structurally similar incidents"
      subtitle="Weighted Jaccard overlap across techniques, rules, entities and severity — not embeddings"
    >
      <QueryBoundary query={query} context="Could not compute similarity">
        {(data) =>
          data.similar.length === 0 ? (
            <EmptyState
              title="No similar incidents"
              description={`Compared against ${data.candidates_considered} other incident(s); none shared enough structure to score.`}
            />
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-ink-muted">
                Weights: {Object.entries(data.weights).map(([k, v]) => `${k} ${v}`).join(', ')}.
                Similarity is decomposable on purpose — an analyst can see exactly which features
                matched rather than trusting an opaque score.
              </p>
              {data.similar.map((item) => (
                <Link
                  key={item.incident_id}
                  to={`/incidents/${item.incident_id}`}
                  className="block panel p-3 hover:border-line-strong transition-colors"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={item.severity} />
                    <span className="mono text-ink-faint">{item.incident_id}</span>
                    <span className="text-sm text-ink flex-1 min-w-[200px]">{item.title}</span>
                    <span className="text-lg font-bold text-accent tabular-nums">
                      {(item.similarity * 100).toFixed(0)}%
                    </span>
                  </div>
                  <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2.5 text-2xs">
                    {Object.entries(item.matched_on).map(([feature, detail]) => (
                      <div key={feature}>
                        <dt className="text-ink-faint capitalize">{feature}</dt>
                        <dd className="text-ink tabular-nums">
                          {(detail.score * 100).toFixed(0)}%
                          {detail.shared && detail.shared.length > 0 && (
                            <span className="block text-ink-faint truncate" title={detail.shared.join(', ')}>
                              {detail.shared.slice(0, 3).join(', ')}
                            </span>
                          )}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </Link>
              ))}
            </div>
          )
        }
      </QueryBoundary>
    </Panel>
  )
}

export { Shield, ExternalLink }
