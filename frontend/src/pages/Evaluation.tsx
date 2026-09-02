import clsx from 'clsx'
import { CheckCircle2, Gauge, Play, XCircle } from 'lucide-react'
import { useState } from 'react'

import { useEvaluationRuns, useLatestEvaluation, useRunEvaluation } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  EmptyState,
  ErrorState,
  Loading,
  Panel,
  SectionHeading,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { EvaluationRun } from '@/types'
import { absoluteTime, duration, relativeTime } from '@/utils/format'

export function Evaluation() {
  const latest = useLatestEvaluation()
  const history = useEvaluationRuns()
  const run = useRunEvaluation()
  const { can } = useAuth()

  const [seed, setSeed] = useState(1337)
  const [days, setDays] = useState(14)
  const [ambiguous, setAmbiguous] = useState(true)

  const current = run.data ?? latest.data

  return (
    <>
      <PageHeader
        title="Detection Evaluation"
        description="Measured detection performance against a labelled dataset. Every figure here is computed at run time — there is no configuration, default or seed value for any metric anywhere in the codebase."
        actions={
          can('admin') && (
            <button
              type="button"
              className="btn-primary"
              disabled={run.isPending}
              onClick={() =>
                run.mutate({ seed, benign_days: days, include_ambiguous: ambiguous })
              }
            >
              {run.isPending ? <Spinner /> : <Play className="h-4 w-4" />}
              Run evaluation
            </button>
          )
        }
      >
        {can('admin') && (
          <div className="px-4 sm:px-6 pb-3 flex flex-wrap items-center gap-4">
            <label className="flex items-center gap-2 text-xs">
              <span className="label">Seed</span>
              <input
                type="number"
                value={seed}
                onChange={(event) => setSeed(Number(event.target.value))}
                className="input max-w-[110px] py-1"
              />
            </label>
            <label className="flex items-center gap-2 text-xs">
              <span className="label">Benign days</span>
              <input
                type="number"
                min={1}
                max={60}
                value={days}
                onChange={(event) => setDays(Number(event.target.value))}
                className="input max-w-[80px] py-1"
              />
            </label>
            <label className="flex items-center gap-2 text-xs text-ink-muted">
              <input
                type="checkbox"
                checked={ambiguous}
                onChange={(event) => setAmbiguous(event.target.checked)}
                className="accent-cyan-400"
              />
              Include ambiguous cases
            </label>
            <span className="text-2xs text-ink-faint">
              Deterministic: the same seed produces byte-identical telemetry, so any number here is
              reproducible from the repository.
            </span>
          </div>
        )}
      </PageHeader>

      <PageBody className="space-y-5">
        {run.isPending && (
          <Panel>
            <div className="flex items-center gap-3 py-2">
              <Spinner className="text-accent h-5 w-5" />
              <div>
                <p className="text-sm text-ink">Running evaluation…</p>
                <p className="text-xs text-ink-muted">
                  Generating the labelled dataset, replaying it through the real pipeline in hourly
                  batches, and scoring the result.
                </p>
              </div>
            </div>
          </Panel>
        )}
        {run.isError && <ErrorState error={run.error} context="Evaluation failed" />}
        {latest.isLoading && <Loading rows={4} />}

        {current && current.available === false && (
          <Panel>
            <EmptyState
              icon={<Gauge className="h-7 w-7" />}
              title="No evaluation has been run yet"
              description={current.message}
            />
          </Panel>
        )}

        {current && current.available !== false && <EvaluationReport run={current} />}

        {history.data && history.data.items.length > 1 && (
          <Panel title="Evaluation history" dense>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Run</th>
                    <th>When</th>
                    <th>Dataset</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>F1</th>
                    <th>Median latency</th>
                    <th>By</th>
                  </tr>
                </thead>
                <tbody>
                  {history.data.items.map((entry) => (
                    <tr key={entry.eval_id}>
                      <td className="mono text-ink-faint">{entry.eval_id}</td>
                      <td title={absoluteTime(entry.started_at)}>{relativeTime(entry.started_at)}</td>
                      <td className="tabular-nums">{entry.dataset.size} events</td>
                      <td className="tabular-nums text-ink">
                        {((entry.metrics.precision as number) * 100).toFixed(1)}%
                      </td>
                      <td className="tabular-nums text-ink">
                        {((entry.metrics.recall as number) * 100).toFixed(1)}%
                      </td>
                      <td className="tabular-nums text-accent font-medium">
                        {((entry.metrics.f1 as number) * 100).toFixed(1)}%
                      </td>
                      <td className="tabular-nums text-ink-muted">
                        {duration((entry.metrics.median_detection_latency_ms as number) / 1000)}
                      </td>
                      <td className="text-ink-muted">{entry.requested_by}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        )}
      </PageBody>
    </>
  )
}

function EvaluationReport({ run }: { run: EvaluationRun }) {
  const metrics = run.metrics as Record<string, number>
  const methodology = run.methodology ?? {}

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <BigMetric label="Precision" value={metrics.precision} hint="Of what fired, how much was real" />
        <BigMetric label="Recall" value={metrics.recall} hint="Of what was real, how much fired" />
        <BigMetric label="F1" value={metrics.f1} hint="Harmonic mean" accent />
        <BigMetric
          label="Scenario detection"
          value={metrics.scenario_detection_rate}
          hint={`${metrics.scenarios_detected}/${metrics.scenarios_total} attacks caught`}
        />
        <div className="panel p-3">
          <p className="label">Median latency</p>
          <p className="text-2xl font-bold text-ink tabular-nums mt-1 leading-none">
            {duration(metrics.median_detection_latency_ms / 1000)}
          </p>
          <p className="text-2xs text-ink-faint mt-1.5">
            p95 {duration(metrics.p95_detection_latency_ms / 1000)}
          </p>
        </div>
        <div className="panel p-3">
          <p className="label">False positive rate</p>
          <p className="text-2xl font-bold text-healthy tabular-nums mt-1 leading-none">
            {(metrics.false_positive_rate * 100).toFixed(2)}%
          </p>
          <p className="text-2xs text-ink-faint mt-1.5">of benign events</p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <Panel title="Confusion matrix" subtitle="Unit of analysis: one security event">
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'True positives', value: metrics.true_positives, tone: 'text-healthy' },
              { label: 'False positives', value: metrics.false_positives, tone: 'text-critical' },
              { label: 'False negatives', value: metrics.false_negatives, tone: 'text-high' },
              { label: 'True negatives', value: metrics.true_negatives, tone: 'text-ink-muted' },
            ].map((cell) => (
              <div key={cell.label} className="bg-base border border-line rounded-md p-3">
                <p className="label">{cell.label}</p>
                <p className={clsx('text-xl font-bold tabular-nums mt-1', cell.tone)}>{cell.value}</p>
              </div>
            ))}
          </div>

          <div className="mt-4 pt-3 border-t border-line">
            <SectionHeading hint="excluded from precision and recall">
              False-positive pressure
            </SectionHeading>
            <p className="text-sm text-ink">
              <span className="text-medium font-semibold tabular-nums">
                {metrics.ambiguous_alerted}
              </span>{' '}
              of{' '}
              <span className="tabular-nums">{metrics.ambiguous_total}</span> ambiguous events
              triggered an alert ({(metrics.ambiguous_alert_rate * 100).toFixed(0)}%).
            </p>
            <p className="text-2xs text-ink-faint mt-1.5 leading-relaxed">
              {methodology.ambiguous_handling}
            </p>
          </div>
        </Panel>

        <Panel
          className="xl:col-span-2"
          title="Per-scenario results"
          subtitle="Whether each attack was caught, how much of it was flagged, and how quickly"
          dense
        >
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Detected</th>
                  <th>Event recall</th>
                  <th>Latency</th>
                  <th>Alerts</th>
                  <th>Rules that did not fire</th>
                </tr>
              </thead>
              <tbody>
                {run.per_scenario
                  .filter((scenario) => scenario.label === 'malicious')
                  .map((scenario) => (
                    <tr key={scenario.scenario}>
                      <td className="text-ink">{scenario.scenario.replace(/_/g, ' ')}</td>
                      <td>
                        {scenario.detected ? (
                          <CheckCircle2 className="h-4 w-4 text-healthy" aria-label="Detected" />
                        ) : (
                          <XCircle className="h-4 w-4 text-critical" aria-label="Not detected" />
                        )}
                      </td>
                      <td className="tabular-nums">
                        {(scenario.event_recall * 100).toFixed(0)}%
                        <span className="text-ink-faint ml-1">
                          ({scenario.detected_events}/{scenario.events})
                        </span>
                      </td>
                      <td className="tabular-nums text-ink-muted">
                        {scenario.detection_latency_ms != null
                          ? duration(scenario.detection_latency_ms / 1000)
                          : '—'}
                      </td>
                      <td className="tabular-nums">{scenario.alert_count}</td>
                      <td>
                        {scenario.expected_rules_missed?.length ? (
                          <div className="flex flex-wrap gap-1">
                            {scenario.expected_rules_missed.map((rule) => (
                              <Badge key={rule} className="border-high/40 text-high">
                                {rule}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-healthy text-xs">all fired</span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <Panel title="Per-rule precision" subtitle="Which rules produce noise" dense>
          <div className="table-wrap max-h-[420px] overflow-y-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Alerts</th>
                  <th>TP events</th>
                  <th>FP events</th>
                  <th>Ambiguous</th>
                  <th>Precision</th>
                </tr>
              </thead>
              <tbody>
                {run.per_rule.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td className="mono text-ink">{rule.rule_id}</td>
                    <td className="tabular-nums">{rule.alerts}</td>
                    <td className="tabular-nums text-healthy">{rule.true_positive_events}</td>
                    <td
                      className={clsx(
                        'tabular-nums',
                        rule.false_positive_events > 0 ? 'text-critical' : 'text-ink-faint',
                      )}
                    >
                      {rule.false_positive_events}
                    </td>
                    <td className="tabular-nums text-medium">{rule.ambiguous_events}</td>
                    <td
                      className={clsx(
                        'tabular-nums font-medium',
                        rule.event_precision >= 0.9
                          ? 'text-healthy'
                          : rule.event_precision >= 0.6
                            ? 'text-medium'
                            : 'text-critical',
                      )}
                    >
                      {(rule.event_precision * 100).toFixed(0)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {run.silent_rules.length > 0 && (
            <Callout tone="warning" title="Rules that never fired">
              <p>
                These rules were enabled but produced no alert against this dataset. A silent rule is
                indistinguishable from a working one in any metric that only counts what did happen,
                which is why they are listed:
              </p>
              <div className="flex flex-wrap gap-1 mt-2">
                {run.silent_rules.map((rule) => (
                  <Code key={rule}>{rule}</Code>
                ))}
              </div>
            </Callout>
          )}
        </Panel>

        <div className="space-y-5">
          <Panel title="Dataset composition">
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-ink-muted">Total events</dt>
                <dd className="text-ink tabular-nums font-medium">{run.dataset.size}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-ink-muted">Benign</dt>
                <dd className="text-ink tabular-nums">{run.dataset.benign}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-ink-muted">Malicious</dt>
                <dd className="text-ink tabular-nums">{run.dataset.malicious}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-ink-muted">Ambiguous</dt>
                <dd className="text-ink tabular-nums">{run.dataset.ambiguous}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-ink-muted">Seed</dt>
                <dd className="mono text-ink">{run.dataset.seed}</dd>
              </div>
            </dl>
            <div className="h-2 flex rounded-full overflow-hidden mt-3">
              <div
                className="bg-healthy"
                style={{ width: `${(run.dataset.benign / run.dataset.size) * 100}%` }}
                title={`${run.dataset.benign} benign`}
              />
              <div
                className="bg-critical"
                style={{ width: `${(run.dataset.malicious / run.dataset.size) * 100}%` }}
                title={`${run.dataset.malicious} malicious`}
              />
              <div
                className="bg-medium"
                style={{ width: `${(run.dataset.ambiguous / run.dataset.size) * 100}%` }}
                title={`${run.dataset.ambiguous} ambiguous`}
              />
            </div>
          </Panel>

          <Panel title="Methodology" subtitle="Stated in full, because a metric without one is a claim">
            <dl className="space-y-3 text-xs">
              {Object.entries(methodology).map(([key, value]) => (
                <div key={key}>
                  <dt className="text-ink font-medium capitalize mb-0.5">
                    {key.replace(/_/g, ' ')}
                  </dt>
                  <dd className="text-ink-muted leading-relaxed">{value}</dd>
                </div>
              ))}
            </dl>
          </Panel>
        </div>
      </div>
    </div>
  )
}

function BigMetric({
  label,
  value,
  hint,
  accent,
}: {
  label: string
  value: number
  hint: string
  accent?: boolean
}) {
  return (
    <div className={clsx('panel p-3', accent && 'border-accent/40')}>
      <p className="label">{label}</p>
      <p
        className={clsx(
          'text-2xl font-bold tabular-nums mt-1 leading-none',
          accent ? 'text-accent' : 'text-ink',
        )}
      >
        {(value * 100).toFixed(1)}%
      </p>
      <p className="text-2xs text-ink-faint mt-1.5 leading-snug">{hint}</p>
    </div>
  )
}
