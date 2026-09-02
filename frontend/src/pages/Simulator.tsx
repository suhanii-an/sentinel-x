import clsx from 'clsx'
import { CheckCircle2, Play, ShieldCheck, XCircle, Zap } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { useRunSimulation, useScenarios, useSimulationRuns } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  EmptyState,
  ErrorState,
  Loading,
  Panel,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { ScenarioSpec, SimulationRun } from '@/types'
import { absoluteTime, durationMs, relativeTime } from '@/utils/format'

export function Simulator() {
  const scenarios = useScenarios()
  const runs = useSimulationRuns({ limit: 15 })
  const execute = useRunSimulation()
  const { can } = useAuth()

  const [selected, setSelected] = useState<ScenarioSpec | null>(null)
  const [lastRun, setLastRun] = useState<Awaited<ReturnType<typeof execute.mutateAsync>> | null>(null)

  const start = (scenario: ScenarioSpec) => {
    setSelected(scenario)
    execute.mutate({ scenario: scenario.key }, { onSuccess: (data) => setLastRun(data) })
  }

  const fullChain = scenarios.data?.scenarios.find((s) => s.key === 'full_chain')

  return (
    <>
      <PageHeader
        title="Attack Simulator"
        description="Generate realistic security telemetry and watch the detection pipeline process it end to end."
        actions={
          fullChain &&
          can('analyst') && (
            <button
              type="button"
              className="btn-primary"
              disabled={execute.isPending}
              onClick={() => start(fullChain)}
            >
              {execute.isPending ? <Spinner /> : <Zap className="h-4 w-4" />}
              Run full attack scenario
            </button>
          )
        }
      />

      <PageBody className="space-y-5">
        {scenarios.data && (
          <Callout tone="warning" title="Safety">
            {scenarios.data.safety_notice}
          </Callout>
        )}

        {execute.isPending && (
          <Panel>
            <div className="flex items-center gap-3 py-2">
              <Spinner className="text-accent h-5 w-5" />
              <div>
                <p className="text-sm text-ink">Running {selected?.name}…</p>
                <p className="text-xs text-ink-muted">
                  Generating telemetry → normalizing → detection → alerting → correlation.
                </p>
              </div>
            </div>
          </Panel>
        )}

        {execute.isError && (
          <ErrorState error={execute.error} context="The simulation could not be run" />
        )}

        {lastRun && !execute.isPending && <RunResult result={lastRun} />}

        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {scenarios.isLoading && <Loading rows={4} />}
          {scenarios.data?.scenarios.map((scenario) => (
            <ScenarioCard
              key={scenario.key}
              scenario={scenario}
              onRun={() => start(scenario)}
              disabled={!can('analyst') || execute.isPending}
              featured={scenario.key === 'full_chain'}
            />
          ))}
        </div>

        <Panel title="Recent simulation runs" dense>
          {runs.isLoading && <Loading rows={3} />}
          {runs.data && runs.data.items.length === 0 && (
            <EmptyState title="No simulations run yet" />
          )}
          {runs.data && runs.data.items.length > 0 && (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Started</th>
                    <th>Scenario</th>
                    <th>Status</th>
                    <th>Events</th>
                    <th>Alerts</th>
                    <th>Incidents</th>
                    <th>Coverage</th>
                    <th>Seed</th>
                    <th>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.data.items.map((run) => (
                    <tr key={run.run_id}>
                      <td className="whitespace-nowrap" title={absoluteTime(run.started_at)}>
                        {relativeTime(run.started_at)}
                      </td>
                      <td className="text-ink">{run.scenario_name || run.scenario}</td>
                      <td>
                        <Badge
                          className={
                            run.status === 'completed'
                              ? 'border-healthy/40 text-healthy'
                              : 'border-critical/40 text-critical'
                          }
                        >
                          {run.status}
                        </Badge>
                      </td>
                      <td className="tabular-nums">{run.event_count}</td>
                      <td className="tabular-nums">{run.alert_count}</td>
                      <td className="mono">
                        {run.incident_ids.length === 0
                          ? '—'
                          : run.incident_ids.map((id) => (
                              <Link key={id} to={`/incidents/${id}`} className="link block">
                                {id}
                              </Link>
                            ))}
                      </td>
                      <td>
                        <CoverageBadge ratio={run.coverage.coverage_ratio} />
                      </td>
                      <td className="mono text-ink-faint">{run.seed}</td>
                      <td className="text-ink-muted tabular-nums">{durationMs(run.duration_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </PageBody>
    </>
  )
}

function ScenarioCard({
  scenario,
  onRun,
  disabled,
  featured,
}: {
  scenario: ScenarioSpec
  onRun: () => void
  disabled: boolean
  featured?: boolean
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <article
      className={clsx(
        'panel p-4 flex flex-col',
        featured && 'border-accent/40 bg-accent/[0.03]',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-ink">{scenario.name}</h3>
        {featured && <Badge className="border-accent/40 text-accent shrink-0">full chain</Badge>}
      </div>

      <p className="text-xs text-ink-muted mt-1.5 leading-relaxed flex-1">{scenario.description}</p>

      <div className="flex flex-wrap gap-1 mt-3">
        {scenario.techniques.slice(0, expanded ? undefined : 6).map((technique) => (
          <Badge key={technique} className="border-accent/25 text-accent/90">
            {technique}
          </Badge>
        ))}
        {!expanded && scenario.techniques.length > 6 && (
          <button
            type="button"
            className="text-2xs text-ink-faint hover:text-ink"
            onClick={() => setExpanded(true)}
          >
            +{scenario.techniques.length - 6} more
          </button>
        )}
      </div>

      <details className="mt-3">
        <summary className="text-2xs text-ink-faint cursor-pointer hover:text-ink-muted">
          Expected telemetry and detections
        </summary>
        <div className="mt-2 space-y-2">
          <div>
            <p className="label mb-1">Telemetry it will produce</p>
            <ul className="space-y-0.5">
              {scenario.expected_telemetry.map((item, index) => (
                <li key={index} className="text-2xs text-ink-muted flex gap-1.5">
                  <span className="text-ink-faint shrink-0" aria-hidden="true">
                    ·
                  </span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="label mb-1">Rules it should trigger</p>
            <div className="flex flex-wrap gap-1">
              {scenario.expected_detections.map((rule) => (
                <Code key={rule}>{rule}</Code>
              ))}
            </div>
          </div>
        </div>
      </details>

      <div className="flex items-start gap-2 mt-3 pt-3 border-t border-line">
        <ShieldCheck className="h-3.5 w-3.5 text-healthy shrink-0 mt-0.5" aria-hidden="true" />
        <p className="text-2xs text-ink-faint leading-relaxed flex-1">{scenario.safety_notice}</p>
      </div>

      <button type="button" className="btn-secondary mt-3 w-full" onClick={onRun} disabled={disabled}>
        <Play className="h-3.5 w-3.5" />
        Run scenario
      </button>
    </article>
  )
}

function CoverageBadge({ ratio }: { ratio: number }) {
  const tone =
    ratio >= 0.9 ? 'border-healthy/40 text-healthy' : ratio >= 0.6 ? 'border-medium/40 text-medium' : 'border-high/40 text-high'
  return <Badge className={tone}>{(ratio * 100).toFixed(0)}%</Badge>
}

function RunResult({
  result,
}: {
  result: {
    run: SimulationRun
    pipeline: Record<string, number>
    incidents: string[]
    expected_detections: string[]
    actual_detections: string[]
    detections_missing: string[]
  }
}) {
  const { run, pipeline } = result

  return (
    <Panel
      title={`${run.scenario_name} complete`}
      subtitle={`Seed ${run.seed} — re-running with this seed reproduces identical telemetry`}
      className="border-accent/40"
    >
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-4">
        {[
          { label: 'Events ingested', value: pipeline.events_ingested },
          { label: 'Alerts created', value: pipeline.alerts_created },
          { label: 'Alerts suppressed', value: pipeline.alerts_suppressed },
          { label: 'Indicator matches', value: pipeline.ioc_matches },
          { label: 'Detection', value: `${pipeline.detection_ms}ms` },
          { label: 'Correlation', value: `${pipeline.correlation_ms}ms` },
        ].map((stat) => (
          <div key={stat.label} className="bg-base border border-line rounded-md p-2.5">
            <p className="label">{stat.label}</p>
            <p className="text-lg font-bold text-ink tabular-nums mt-0.5">{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div>
          <p className="label mb-2">Pipeline stages executed</p>
          <ol className="space-y-1.5">
            {run.stage_log.map((stage) => (
              <li key={stage.stage} className="flex items-center gap-2 text-xs">
                <span className="mono text-ink-faint tabular-nums w-10 shrink-0">
                  +{stage.offset_seconds}s
                </span>
                <span className="text-ink flex-1">{stage.stage.replace(/_/g, ' ')}</span>
                <span className="text-ink-faint">{stage.record_count} records</span>
                <span className="text-2xs text-ink-faint">{stage.sources.join(', ')}</span>
              </li>
            ))}
          </ol>
        </div>

        <div>
          <p className="label mb-2">Detection coverage</p>
          <ul className="space-y-1">
            {result.expected_detections.map((rule) => {
              const fired = result.actual_detections.includes(rule)
              return (
                <li key={rule} className="flex items-center gap-2 text-xs">
                  {fired ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-healthy shrink-0" aria-hidden="true" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-high shrink-0" aria-hidden="true" />
                  )}
                  <Code>{rule}</Code>
                  {!fired && <span className="text-2xs text-high">did not fire</span>}
                </li>
              )
            })}
          </ul>
          {result.detections_missing.length > 0 && (
            <Callout tone="warning" title="Expected detections that did not fire">
              <p>
                This is reported rather than hidden — a rule that was expected and stayed silent is a
                coverage gap. The most common cause is a rule that needs behavioural history the
                database does not have yet (run the seed script to build baselines).
              </p>
            </Callout>
          )}
        </div>
      </div>

      {result.incidents.length > 0 && (
        <div className="mt-4 pt-4 border-t border-line">
          <p className="label mb-2">Incidents created</p>
          <div className="flex flex-wrap gap-2">
            {result.incidents.map((id) => (
              <Link key={id} to={`/incidents/${id}`} className="btn-primary text-xs">
                Investigate {id}
              </Link>
            ))}
          </div>
        </div>
      )}
    </Panel>
  )
}
