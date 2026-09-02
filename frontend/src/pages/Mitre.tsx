/**
 * ATT&CK coverage matrix.
 *
 * Two honesty constraints shape this page:
 *
 *  1. Coverage is reported against the *bundled* catalogue, which is a curated
 *     subset of ATT&CK Enterprise. A percentage against the full matrix would
 *     be a flattering lie, so the catalogue note is rendered prominently rather
 *     than tucked into a tooltip.
 *  2. Uncovered techniques are shown with the same weight as covered ones. A
 *     coverage view that only lights up what you detect tells an analyst
 *     nothing about where they are blind.
 *
 * Technique names always come from the API, which reads them from the local
 * catalogue. Nothing on this page hard-codes a technique name or identifier.
 */
import clsx from 'clsx'
import { ExternalLink } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'

import { useMitreCoverage, useMitreTechnique } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  Modal,
  Panel,
  ProgressBar,
  QueryBoundary,
  SeverityBadge,
} from '@/components/ui'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, percent, relativeTime } from '@/utils/format'

type Filter = 'all' | 'covered' | 'uncovered' | 'observed'

export function Mitre() {
  const coverage = useMitreCoverage()
  const [filter, setFilter] = useState<Filter>('all')
  const [search, setSearch] = useState('')
  const [technique, setTechnique] = useState<string | null>(null)

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK"
        description="Which adversary techniques this rule set detects, which it does not, and which have actually been observed in incidents here."
        actions={
          <div className="flex items-center gap-2">
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Technique or ID"
              aria-label="Search techniques"
              className="input max-w-[180px]"
            />
            <select
              value={filter}
              onChange={(event) => setFilter(event.target.value as Filter)}
              aria-label="Filter techniques"
              className="input max-w-[170px]"
            >
              <option value="all">All techniques</option>
              <option value="covered">Covered by a rule</option>
              <option value="uncovered">Not covered</option>
              <option value="observed">Observed in incidents</option>
            </select>
          </div>
        }
      />

      <PageBody className="space-y-5">
        <QueryBoundary query={coverage} context="Could not load ATT&CK coverage">
          {(data) => {
            const filtered = data.by_tactic
              .map((tactic) => ({
                ...tactic,
                techniques: tactic.techniques.filter((entry) => {
                  if (filter === 'covered' && !entry.covered) return false
                  if (filter === 'uncovered' && entry.covered) return false
                  if (filter === 'observed' && entry.observed_in_incidents === 0) return false
                  if (search.trim()) {
                    const needle = search.trim().toLowerCase()
                    if (
                      !entry.name.toLowerCase().includes(needle) &&
                      !entry.technique_id.toLowerCase().includes(needle)
                    ) {
                      return false
                    }
                  }
                  return true
                }),
              }))
              .filter((tactic) => tactic.techniques.length > 0)

            return (
              <>
                <Callout tone="warning" title="What this percentage means">
                  <p>{data.catalogue.note}</p>
                </Callout>

                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                  <SummaryCard
                    label="Techniques covered"
                    value={`${data.covered_techniques} / ${data.catalogue.technique_count}`}
                    detail={percent(data.coverage_ratio, 1)}
                    ratio={data.coverage_ratio}
                  />
                  <SummaryCard
                    label="Tactics in catalogue"
                    value={data.catalogue.tactic_count}
                    detail="kill-chain phases"
                  />
                  <SummaryCard
                    label="Uncovered techniques"
                    value={data.uncovered_techniques.length}
                    detail="known detection gaps"
                    tone="high"
                  />
                  <SummaryCard
                    label="Observed in incidents"
                    value={data.by_tactic.reduce(
                      (sum, tactic) =>
                        sum + tactic.techniques.filter((t) => t.observed_in_incidents > 0).length,
                      0,
                    )}
                    detail="seen in real detections"
                    tone="accent"
                  />
                </div>

                {filtered.length === 0 ? (
                  <Panel>
                    <EmptyState
                      title="No techniques match this filter"
                      description="Clear the search box or switch the filter back to all techniques."
                    />
                  </Panel>
                ) : (
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    {filtered.map((tactic) => (
                      <Panel
                        key={tactic.tactic_id}
                        title={tactic.tactic}
                        subtitle={`${tactic.covered_count} of ${tactic.total_count} techniques covered`}
                        actions={
                          <span className="mono text-2xs text-ink-faint">{tactic.tactic_id}</span>
                        }
                      >
                        <ProgressBar
                          value={tactic.covered_count}
                          max={tactic.total_count}
                          color={tactic.covered_count === 0 ? '#f43f5e' : '#22d3ee'}
                          label={`${tactic.tactic} coverage`}
                        />
                        <div className="flex flex-wrap gap-1.5 mt-3">
                          {tactic.techniques.map((entry) => (
                            <button
                              key={`${tactic.tactic_id}:${entry.technique_id}`}
                              type="button"
                              onClick={() => setTechnique(entry.technique_id)}
                              title={`${entry.technique_id} — ${entry.name}${
                                entry.covered
                                  ? `\nDetected by: ${entry.detection_rules.join(', ')}`
                                  : '\nNo rule covers this technique'
                              }${
                                entry.observed_in_incidents > 0
                                  ? `\nObserved in ${entry.observed_in_incidents} incident(s)`
                                  : ''
                              }`}
                              className={clsx(
                                'text-left rounded border px-2 py-1.5 transition-colors max-w-[190px]',
                                entry.observed_in_incidents > 0
                                  ? 'border-critical/50 bg-critical/10 hover:bg-critical/20'
                                  : entry.covered
                                    ? 'border-healthy/40 bg-healthy/[0.07] hover:bg-healthy/15'
                                    : 'border-line bg-base hover:border-line-strong',
                              )}
                            >
                              <span
                                className={clsx(
                                  'mono text-2xs block',
                                  entry.observed_in_incidents > 0
                                    ? 'text-critical'
                                    : entry.covered
                                      ? 'text-healthy'
                                      : 'text-ink-faint',
                                )}
                              >
                                {entry.technique_id}
                                {entry.observed_in_incidents > 0 && ` · ${entry.observed_in_incidents}`}
                              </span>
                              <span
                                className={clsx(
                                  'text-2xs block truncate',
                                  entry.covered ? 'text-ink' : 'text-ink-faint',
                                )}
                              >
                                {entry.name}
                              </span>
                            </button>
                          ))}
                        </div>
                      </Panel>
                    ))}
                  </div>
                )}

                <Panel title="Legend" dense>
                  <div className="flex flex-wrap gap-4 p-3 text-2xs text-ink-muted">
                    <LegendItem className="border-critical/50 bg-critical/10" label="Observed in a real incident here" />
                    <LegendItem className="border-healthy/40 bg-healthy/[0.07]" label="Covered by an enabled rule" />
                    <LegendItem className="border-line bg-base" label="No rule covers it — a known gap" />
                  </div>
                </Panel>
              </>
            )
          }}
        </QueryBoundary>
      </PageBody>

      <TechniqueModal techniqueId={technique} onClose={() => setTechnique(null)} />
    </>
  )
}

function LegendItem({ className, label }: { className: string; label: string }) {
  return (
    <span className="flex items-center gap-2">
      <span className={clsx('h-3 w-6 rounded border', className)} aria-hidden="true" />
      {label}
    </span>
  )
}

function SummaryCard({
  label,
  value,
  detail,
  ratio,
  tone,
}: {
  label: string
  value: number | string
  detail?: string
  ratio?: number
  tone?: 'high' | 'accent'
}) {
  return (
    <div className="panel p-3">
      <p className="label">{label}</p>
      <p
        className={clsx(
          'text-xl font-bold tabular-nums mt-1',
          tone === 'high' ? 'text-high' : tone === 'accent' ? 'text-accent' : 'text-ink',
        )}
      >
        {value}
      </p>
      {detail && <p className="text-2xs text-ink-faint mt-0.5">{detail}</p>}
      {ratio !== undefined && (
        <div className="mt-2">
          <ProgressBar value={ratio * 100} label={label} />
        </div>
      )}
    </div>
  )
}

interface TechniqueDetail {
  technique_id: string
  name: string
  description?: string
  is_subtechnique?: boolean
  url?: string | null
  tactics: { tactic_id: string; name: string }[]
  detection_rules: {
    rule_id: string
    name: string
    enabled: boolean
    severity: string
    rule_type: string
  }[]
  recent_alerts: {
    alert_id: string
    title: string
    severity: string
    detected_at: string
    rule_id: string
  }[]
  incidents: {
    incident_id: string
    title: string
    severity: string
    status: string
    last_seen: string
  }[]
  alert_count: number
  incident_count: number
}

function TechniqueModal({
  techniqueId,
  onClose,
}: {
  techniqueId: string | null
  onClose: () => void
}) {
  const query = useMitreTechnique(techniqueId ?? undefined)
  const detail = query.data as unknown as TechniqueDetail | undefined

  const title = useMemo(
    () => (detail ? `${detail.technique_id} — ${detail.name}` : (techniqueId ?? 'Technique')),
    [detail, techniqueId],
  )

  return (
    <Modal open={Boolean(techniqueId)} onClose={onClose} title={title} wide>
      {query.isLoading && <Loading rows={3} />}
      {query.isError && (
        <ErrorState
          error={query.error}
          context="This technique is not in the bundled catalogue"
          onRetry={query.refetch}
        />
      )}
      {detail && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            {detail.tactics.map((tactic) => (
              <Badge key={tactic.tactic_id} className="border-accent/30 text-accent">
                {tactic.name}
              </Badge>
            ))}
            {detail.is_subtechnique && (
              <Badge className="border-line text-ink-faint">sub-technique</Badge>
            )}
            {detail.url && (
              <a
                href={detail.url}
                target="_blank"
                rel="noreferrer noopener"
                className="link text-xs inline-flex items-center gap-1"
              >
                attack.mitre.org
                <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </a>
            )}
          </div>

          {detail.description && (
            <p className="text-sm text-ink-muted leading-relaxed">{detail.description}</p>
          )}

          <KeyValue
            columns={3}
            items={[
              { label: 'Rules covering it', value: detail.detection_rules.length },
              { label: 'Alerts referencing it', value: detail.alert_count },
              { label: 'Incidents containing it', value: detail.incident_count },
            ]}
          />

          <section>
            <h3 className="label mb-2">Detection rules</h3>
            {detail.detection_rules.length === 0 ? (
              <Callout tone="warning">
                No rule in this deployment maps to this technique. It is a coverage gap, and it is
                listed here rather than hidden so it can be closed.
              </Callout>
            ) : (
              <ul className="space-y-1.5">
                {detail.detection_rules.map((rule) => (
                  <li
                    key={rule.rule_id}
                    className="flex flex-wrap items-center gap-2 bg-base border border-line rounded-md px-2.5 py-1.5"
                  >
                    <SeverityBadge severity={rule.severity} showLabel={false} />
                    <Code>{rule.rule_id}</Code>
                    <span className="text-xs text-ink flex-1 min-w-[140px]">{rule.name}</span>
                    <Badge className="border-line text-ink-faint">{rule.rule_type}</Badge>
                    {rule.enabled ? (
                      <span className="text-2xs text-healthy">enabled</span>
                    ) : (
                      <span className="text-2xs text-medium">disabled</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>

          {detail.incidents.length > 0 && (
            <section>
              <h3 className="label mb-2">Incidents</h3>
              <ul className="space-y-1.5">
                {detail.incidents.map((incident) => (
                  <li key={incident.incident_id}>
                    <Link
                      to={`/incidents/${incident.incident_id}`}
                      onClick={onClose}
                      className="flex flex-wrap items-center gap-2 bg-base border border-line rounded-md px-2.5 py-1.5 hover:border-line-strong"
                    >
                      <SeverityBadge severity={incident.severity} showLabel={false} />
                      <span className="mono text-accent">{incident.incident_id}</span>
                      <span className="text-xs text-ink-muted flex-1 truncate min-w-[140px]">
                        {incident.title}
                      </span>
                      <span
                        className="text-2xs text-ink-faint"
                        title={absoluteTime(incident.last_seen)}
                      >
                        {relativeTime(incident.last_seen)}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {detail.recent_alerts.length > 0 && (
            <section>
              <h3 className="label mb-2">Recent alerts ({detail.recent_alerts.length})</h3>
              <div className="table-wrap max-h-56 overflow-y-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Detected</th>
                      <th>Alert</th>
                      <th>Severity</th>
                      <th>Rule</th>
                      <th>Title</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.recent_alerts.map((alert) => (
                      <tr key={alert.alert_id}>
                        <td className="whitespace-nowrap" title={absoluteTime(alert.detected_at)}>
                          {relativeTime(alert.detected_at)}
                        </td>
                        <td className="mono text-ink-faint">{alert.alert_id}</td>
                        <td>
                          <SeverityBadge severity={alert.severity} showLabel={false} />
                        </td>
                        <td className="mono text-ink-muted">{alert.rule_id}</td>
                        <td className="text-ink">{alert.title}</td>
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
