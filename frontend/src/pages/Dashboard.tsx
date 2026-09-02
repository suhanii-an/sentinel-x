import clsx from 'clsx'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Gauge,
  Server,
  ShieldAlert,
  Timer,
  Zap,
} from 'lucide-react'
import { type ReactNode } from 'react'
import { Link } from 'react-router-dom'

import { useDashboard, useLiveTimeline } from '@/api/queries'
import {
  AlertTrendChart,
  RiskDistributionChart,
  SeverityDonut,
  TechniqueChart,
} from '@/charts'
import { EventTimeline } from '@/components/EventTimeline'
import {
  Callout,
  ErrorState,
  Loading,
  Panel,
  QueryBoundary,
  RiskScore,
  SeverityBadge,
  StatusBadge,
} from '@/components/ui'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { DashboardKpis } from '@/types'
import { duration, relativeTime } from '@/utils/format'

export function Dashboard() {
  const dashboard = useDashboard(24)
  const timeline = useLiveTimeline({ limit: 40 })

  return (
    <>
      <PageHeader
        title="Security Operations Overview"
        description="Current posture across the monitored estate. Every figure is computed from stored records."
        actions={
          <Link to="/simulator" className="btn-primary">
            <Zap className="h-4 w-4" />
            Run attack scenario
          </Link>
        }
      />

      <PageBody className="space-y-5">
        {dashboard.isLoading && <Loading rows={4} label="Loading dashboard" />}
        {dashboard.isError && (
          <ErrorState error={dashboard.error} onRetry={dashboard.refetch} context="Dashboard unavailable" />
        )}

        {dashboard.data && (
          <>
            <KpiRow kpis={dashboard.data.kpis} />

            {/* Highest priority first: what is happening right now, then the
                analytics that explain it. */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
              <Panel
                className="xl:col-span-2"
                title="Live security event timeline"
                subtitle="Newest first. Click an event to inspect its raw record and the detections it triggered."
                actions={
                  <Link to="/alerts" className="btn-ghost text-xs">
                    All alerts <ArrowRight className="h-3 w-3" />
                  </Link>
                }
                dense
              >
                <QueryBoundary
                  query={timeline}
                  empty={{
                    title: 'No telemetry yet',
                    description:
                      'Seed the database or run a scenario from the Simulator page to generate activity.',
                  }}
                  context="Could not load the event timeline"
                >
                  {(events) => <EventTimeline entries={events} maxHeight={520} />}
                </QueryBoundary>
              </Panel>

              <div className="space-y-5">
                <Panel title="Alert severity" subtitle="Last 7 days">
                  <SeverityDonut data={dashboard.data.severity_distribution} />
                </Panel>

                <Panel
                  title="Detection performance"
                  subtitle="Measured against the labelled evaluation dataset"
                >
                  <DetectionPerformancePanel
                    performance={dashboard.data.detection_performance}
                    detectionRate={dashboard.data.kpis.detection_rate}
                  />
                </Panel>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
              <Panel title="Alert volume" subtitle="Stacked by severity, last 24 hours">
                <AlertTrendChart data={dashboard.data.alert_trend} />
              </Panel>

              <Panel title="ATT&CK techniques" subtitle="Most frequently detected">
                <TechniqueChart data={dashboard.data.technique_distribution} />
              </Panel>

              <Panel title="Incident risk distribution" subtitle="All incidents by scored band">
                <RiskDistributionChart data={dashboard.data.risk_distribution} />
              </Panel>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              <TopEntities
                title="Most-alerted hosts"
                items={dashboard.data.top_entities.hosts}
                hrefFor={(value) => `/hosts/${value}`}
              />
              <TopEntities
                title="Most-alerted accounts"
                items={dashboard.data.top_entities.users}
                hrefFor={(value) => `/users/${value}`}
              />
              <TopEntities
                title="Most-alerted source addresses"
                items={dashboard.data.top_entities.source_ips}
              />
            </div>
          </>
        )}
      </PageBody>
    </>
  )
}

function KpiRow({ kpis }: { kpis: DashboardKpis }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
      <StatTile
        label="Active incidents"
        value={kpis.active_incidents}
        icon={ShieldAlert}
        tone={kpis.critical_incidents > 0 ? 'critical' : kpis.active_incidents > 0 ? 'warning' : 'healthy'}
        hint={kpis.critical_incidents ? `${kpis.critical_incidents} critical` : 'None critical'}
        to="/incidents"
      />
      <StatTile
        label="High & critical alerts"
        value={kpis.critical_alerts}
        icon={AlertTriangle}
        tone={kpis.critical_alerts > 0 ? 'warning' : 'healthy'}
        hint={`${kpis.open_alerts} open in total`}
        to="/alerts"
      />
      <StatTile
        label="Hosts at risk"
        value={kpis.hosts_at_risk}
        icon={Server}
        tone={kpis.hosts_at_risk > 0 ? 'warning' : 'healthy'}
        hint={
          kpis.isolated_hosts
            ? `${kpis.isolated_hosts} isolated (simulated)`
            : 'In an active incident or carrying an open high alert'
        }
        to="/hosts"
      />
      <StatTile
        label="Detection rate"
        value={kpis.detection_rate.measured ? `${kpis.detection_rate.value?.toFixed(1)}%` : 'Not measured'}
        icon={Gauge}
        tone={kpis.detection_rate.measured ? 'accent' : 'muted'}
        hint={kpis.detection_rate.measured ? 'Recall, last evaluation run' : 'Run an evaluation'}
        to="/evaluation"
      />
      <StatTile
        label="MTTD"
        value={kpis.mttd.seconds === null ? '—' : duration(kpis.mttd.seconds)}
        icon={Timer}
        tone="accent"
        hint={`Median over ${kpis.mttd.sample_size} incident(s)`}
        title={kpis.mttd.definition}
      />
      <StatTile
        label="MTTR"
        value={kpis.mttr.seconds === null ? 'No response yet' : duration(kpis.mttr.seconds)}
        icon={Activity}
        tone={kpis.mttr.seconds === null ? 'muted' : 'accent'}
        hint={
          kpis.mttr.sample_size
            ? `Median over ${kpis.mttr.sample_size} incident(s)`
            : 'No containment action recorded'
        }
        title={kpis.mttr.definition}
      />
    </div>
  )
}

const TONES = {
  critical: 'text-critical',
  warning: 'text-high',
  healthy: 'text-healthy',
  accent: 'text-accent',
  muted: 'text-ink-faint',
} as const

function StatTile({
  label,
  value,
  icon: Icon,
  tone,
  hint,
  to,
  title,
}: {
  label: string
  value: ReactNode
  icon: typeof ShieldAlert
  tone: keyof typeof TONES
  hint?: string
  to?: string
  title?: string
}) {
  const content = (
    <div className="panel p-3 h-full hover:border-line-strong transition-colors" title={title}>
      <div className="flex items-start justify-between gap-2">
        <p className="label">{label}</p>
        <Icon className={clsx('h-4 w-4 shrink-0', TONES[tone])} aria-hidden="true" />
      </div>
      <p className={clsx('text-2xl font-bold tabular-nums mt-1.5 leading-none', TONES[tone])}>
        {value}
      </p>
      {hint && <p className="text-2xs text-ink-faint mt-1.5 leading-snug">{hint}</p>}
    </div>
  )
  return to ? (
    <Link to={to} className="block focus-visible:rounded-lg">
      {content}
    </Link>
  ) : (
    content
  )
}

function DetectionPerformancePanel({
  performance,
  detectionRate,
}: {
  performance: NonNullable<unknown> | null | undefined
  detectionRate: DashboardKpis['detection_rate']
}) {
  if (!detectionRate.measured || !performance) {
    return (
      <Callout tone="info" title="Not measured yet">
        <p>{detectionRate.explanation}</p>
        <Link to="/evaluation" className="link inline-flex items-center gap-1 mt-2">
          Open the Evaluation page <ArrowRight className="h-3 w-3" />
        </Link>
      </Callout>
    )
  }

  const perf = performance as {
    precision: number
    recall: number
    f1: number
    median_latency_ms: number
    dataset_size: number
    eval_id: string
    measured_at: string
    true_positives: number
    false_positives: number
    false_negatives: number
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2 text-center">
        {[
          { label: 'Precision', value: perf.precision },
          { label: 'Recall', value: perf.recall },
          { label: 'F1', value: perf.f1 },
        ].map((metric) => (
          <div key={metric.label} className="bg-base border border-line rounded-md py-2">
            <p className="text-lg font-bold text-accent tabular-nums leading-none">
              {(metric.value * 100).toFixed(1)}%
            </p>
            <p className="label mt-1">{metric.label}</p>
          </div>
        ))}
      </div>
      <dl className="text-2xs text-ink-muted space-y-1">
        <div className="flex justify-between">
          <dt>Median detection latency</dt>
          <dd className="text-ink tabular-nums">{duration(perf.median_latency_ms / 1000)}</dd>
        </div>
        <div className="flex justify-between">
          <dt>Confusion (TP / FP / FN)</dt>
          <dd className="text-ink tabular-nums">
            {perf.true_positives} / {perf.false_positives} / {perf.false_negatives}
          </dd>
        </div>
        <div className="flex justify-between">
          <dt>Dataset</dt>
          <dd className="text-ink tabular-nums">{perf.dataset_size} labelled events</dd>
        </div>
        <div className="flex justify-between">
          <dt>Measured</dt>
          <dd className="text-ink">{relativeTime(perf.measured_at)}</dd>
        </div>
      </dl>
      <Link to="/evaluation" className="link text-xs inline-flex items-center gap-1">
        Methodology and per-rule results <ArrowRight className="h-3 w-3" />
      </Link>
    </div>
  )
}

function TopEntities({
  title,
  items,
  hrefFor,
}: {
  title: string
  items: { value: string; alert_count: number }[]
  hrefFor?: (value: string) => string
}) {
  const max = Math.max(1, ...items.map((item) => item.alert_count))
  return (
    <Panel title={title} dense>
      {items.length === 0 ? (
        <p className="px-4 py-6 text-xs text-ink-faint text-center">No activity recorded.</p>
      ) : (
        <ul className="divide-y divide-line/60">
          {items.map((item) => (
            <li key={item.value} className="px-4 py-2 flex items-center gap-3">
              <span className="mono text-ink truncate flex-1 min-w-0">
                {hrefFor ? (
                  <Link to={hrefFor(item.value)} className="link">
                    {item.value}
                  </Link>
                ) : (
                  item.value
                )}
              </span>
              <div className="w-20 h-1.5 bg-raised rounded-full overflow-hidden shrink-0">
                <div
                  className="h-full bg-accent/70 rounded-full"
                  style={{ width: `${(item.alert_count / max) * 100}%` }}
                />
              </div>
              <span className="text-xs text-ink-muted tabular-nums w-6 text-right shrink-0">
                {item.alert_count}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

export { SeverityBadge, StatusBadge, RiskScore }
