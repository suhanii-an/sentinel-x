import clsx from 'clsx'
import { CheckCircle2, FlaskConical, XCircle } from 'lucide-react'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import {
  useDetectionRule,
  useDetectionRules,
  useDetectionStatus,
  useRuleTests,
  useTestRule,
  useToggleRule,
} from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  CodeBlock,
  ErrorState,
  KeyValue,
  Loading,
  Modal,
  Panel,
  QueryBoundary,
  SeverityBadge,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { RuleTestResult } from '@/types'
import { absoluteTime, relativeTime } from '@/utils/format'

export function Detections() {
  const [params, setParams] = useSearchParams()
  const selected = params.get('rule')
  const [typeFilter, setTypeFilter] = useState('')
  const [enabledOnly, setEnabledOnly] = useState(false)

  const rules = useDetectionRules({
    limit: 300,
    rule_type: typeFilter || undefined,
    enabled: enabledOnly ? true : undefined,
  })
  const status = useDetectionStatus()
  const tests = useRuleTests()

  const open = (ruleId: string) => {
    const next = new URLSearchParams(params)
    next.set('rule', ruleId)
    setParams(next, { replace: true })
  }

  return (
    <>
      <PageHeader
        title="Detection Rules"
        description="Rules are version-controlled YAML, not code and not database rows. This page is the runtime registry: it mirrors the files and owns the operational state."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
              aria-label="Filter by rule type"
              className="input max-w-[150px]"
            >
              <option value="">All types</option>
              {['match', 'threshold', 'sequence', 'ioc', 'anomaly'].map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1.5 text-xs text-ink-muted whitespace-nowrap">
              <input
                type="checkbox"
                checked={enabledOnly}
                onChange={(event) => setEnabledOnly(event.target.checked)}
                className="accent-cyan-400"
              />
              Enabled only
            </label>
          </div>
        }
      />

      <PageBody className="space-y-5">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          <Panel title="Rule health" className="lg:col-span-2">
            {status.isLoading && <Loading rows={2} />}
            {status.data && (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <Stat label="Rules on disk" value={status.data.rules_on_disk} />
                  <Stat label="Registered" value={status.data.rules_registered} />
                  <Stat label="Enabled" value={status.data.rules_enabled} />
                  <Stat
                    label="Load errors"
                    value={status.data.load_errors.length}
                    tone={status.data.load_errors.length ? 'text-critical' : 'text-healthy'}
                  />
                </div>
                <div className="flex flex-wrap gap-2 mt-3">
                  {Object.entries(status.data.by_type).map(([type, count]) => (
                    <Badge key={type} className="border-line text-ink-muted">
                      {type}
                      <span className="tabular-nums">{count}</span>
                    </Badge>
                  ))}
                </div>
                {status.data.load_errors.length > 0 && (
                  <Callout tone="critical" title="Rules failed to load">
                    <p>
                      A rule that fails to parse looks exactly like coverage and provides none, so
                      the errors are surfaced here rather than logged and forgotten.
                    </p>
                    <ul className="mt-2 space-y-1">
                      {status.data.load_errors.map((error, index) => (
                        <li key={index} className="mono">
                          {error}
                        </li>
                      ))}
                    </ul>
                  </Callout>
                )}
              </>
            )}
          </Panel>

          <Panel title="Rule self-tests" subtitle="Run in CI, the test suite and here — same code">
            {tests.isLoading && <Loading rows={2} />}
            {tests.data && (
              <>
                <div className="flex items-baseline gap-2">
                  <span
                    className={clsx(
                      'text-3xl font-bold tabular-nums',
                      tests.data.ok ? 'text-healthy' : 'text-critical',
                    )}
                  >
                    {tests.data.passed}/{tests.data.total}
                  </span>
                  <span className="text-xs text-ink-muted">passing</span>
                </div>
                {tests.data.failed > 0 && (
                  <ul className="mt-3 space-y-1">
                    {tests.data.results
                      .filter((result) => !result.passed)
                      .map((result, index) => (
                        <li key={index} className="text-xs text-critical">
                          <Code>{result.rule_id}</Code> {result.test_name}: expected{' '}
                          {result.expected}, got {result.actual}
                        </li>
                      ))}
                  </ul>
                )}
                {tests.data.rules_without_tests.length > 0 && (
                  <p className="text-2xs text-medium mt-3">
                    Untested rules: {tests.data.rules_without_tests.join(', ')}
                  </p>
                )}
                {tests.data.rules_without_negative_tests.length > 0 && (
                  <p className="text-2xs text-medium mt-1">
                    No negative test: {tests.data.rules_without_negative_tests.join(', ')}
                  </p>
                )}
                {tests.data.ok &&
                  tests.data.rules_without_tests.length === 0 &&
                  tests.data.rules_without_negative_tests.length === 0 && (
                    <p className="text-2xs text-ink-faint mt-3 leading-relaxed">
                      Every rule ships both a positive and a negative case. The negative ones matter
                      more: it is easy to write a rule that fires on the attack, and hard to write
                      one that does not also fire on the administrator doing their job.
                    </p>
                  )}
              </>
            )}
          </Panel>
        </div>

        <Panel dense>
          <QueryBoundary query={rules} context="Could not load rules" empty={{ title: 'No rules match' }}>
            {(page) => (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Severity</th>
                      <th>ATT&CK</th>
                      <th>Triggered</th>
                      <th>Last fired</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.items.map((rule) => (
                      <tr
                        key={rule.rule_id}
                        className="cursor-pointer"
                        onClick={() => open(rule.rule_id)}
                      >
                        <td className="mono text-accent">{rule.rule_id}</td>
                        <td className="text-ink max-w-[280px]">{rule.name}</td>
                        <td>
                          <Badge className="border-line text-ink-muted">{rule.rule_type}</Badge>
                        </td>
                        <td>
                          <SeverityBadge severity={rule.severity} showLabel={false} />
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-1 max-w-[180px]">
                            {rule.mitre_techniques.slice(0, 3).map((technique) => (
                              <Badge key={technique} className="border-accent/25 text-accent/90">
                                {technique}
                              </Badge>
                            ))}
                            {rule.mitre_techniques.length > 3 && (
                              <span className="text-2xs text-ink-faint">
                                +{rule.mitre_techniques.length - 3}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="tabular-nums">{rule.trigger_count}</td>
                        <td
                          className="text-ink-muted whitespace-nowrap"
                          title={absoluteTime(rule.last_triggered_at)}
                        >
                          {rule.last_triggered_at ? relativeTime(rule.last_triggered_at) : 'never'}
                        </td>
                        <td>
                          {rule.enabled ? (
                            <span className="text-xs text-healthy">enabled</span>
                          ) : (
                            <span className="text-xs text-ink-faint">disabled</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </QueryBoundary>
        </Panel>
      </PageBody>

      <RuleModal
        ruleId={selected}
        onClose={() => {
          const next = new URLSearchParams(params)
          next.delete('rule')
          setParams(next, { replace: true })
        }}
      />
    </>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="bg-base border border-line rounded-md p-2.5">
      <p className="label">{label}</p>
      <p className={clsx('text-xl font-bold tabular-nums mt-0.5', tone ?? 'text-ink')}>{value}</p>
    </div>
  )
}

function RuleModal({ ruleId, onClose }: { ruleId: string | null; onClose: () => void }) {
  const query = useDetectionRule(ruleId ?? undefined)
  const toggle = useToggleRule()
  const test = useTestRule()
  const { can } = useAuth()
  const [results, setResults] = useState<RuleTestResult[] | null>(null)

  const rule = query.data

  return (
    <Modal open={Boolean(ruleId)} onClose={onClose} title={ruleId ?? 'Rule'} wide>
      {query.isLoading && <Loading rows={4} />}
      {query.isError && <ErrorState error={query.error} onRetry={query.refetch} />}
      {rule && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={rule.severity} />
            <Badge className="border-line text-ink-muted">{rule.rule_type}</Badge>
            <Badge className="border-line text-ink-muted">{rule.category}</Badge>
            {rule.enabled ? (
              <Badge className="border-healthy/40 text-healthy">enabled</Badge>
            ) : (
              <Badge className="border-line-strong text-ink-faint">disabled</Badge>
            )}
            <div className="ml-auto flex gap-2">
              <button
                type="button"
                className="btn-secondary text-xs"
                disabled={test.isPending}
                onClick={() =>
                  test.mutate(rule.rule_id, { onSuccess: (data) => setResults(data.results) })
                }
              >
                {test.isPending ? <Spinner /> : <FlaskConical className="h-3.5 w-3.5" />}
                Run self-tests
              </button>
              {can('admin') && (
                <button
                  type="button"
                  className={rule.enabled ? 'btn-danger text-xs' : 'btn-primary text-xs'}
                  disabled={toggle.isPending}
                  onClick={() =>
                    toggle.mutate({ ruleId: rule.rule_id, enabled: !rule.enabled })
                  }
                >
                  {rule.enabled ? 'Disable' : 'Enable'}
                </button>
              )}
            </div>
          </div>

          <h3 className="text-base font-semibold text-ink">{rule.name}</h3>
          <p className="text-sm text-ink-muted whitespace-pre-line leading-relaxed">
            {rule.description}
          </p>

          <KeyValue
            columns={3}
            items={[
              { label: 'Confidence', value: `${(rule.confidence * 100).toFixed(0)}%` },
              { label: 'Version', value: rule.version },
              { label: 'Author', value: rule.author },
              { label: 'Times triggered', value: rule.trigger_count },
              {
                label: 'Last fired',
                value: rule.last_triggered_at ? absoluteTime(rule.last_triggered_at) : 'Never',
              },
              { label: 'Source file', value: <Code>{rule.source_path?.split('/').slice(-2).join('/')}</Code> },
            ]}
          />

          {rule.mitre_techniques.length > 0 && (
            <div>
              <p className="label mb-1.5">ATT&CK techniques</p>
              <div className="flex flex-wrap gap-1">
                {rule.mitre_techniques.map((technique) => (
                  <Badge key={technique} className="border-accent/30 text-accent">
                    {technique}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {rule.false_positives.length > 0 && (
            <Callout tone="warning" title="Documented false-positive conditions">
              <ul className="space-y-1">
                {rule.false_positives.map((condition, index) => (
                  <li key={index}>{condition}</li>
                ))}
              </ul>
            </Callout>
          )}

          {results && (
            <section>
              <p className="label mb-2">
                Self-test results ({results.filter((r) => r.passed).length}/{results.length} passing)
              </p>
              <ul className="space-y-1.5">
                {results.map((result, index) => (
                  <li
                    key={index}
                    className="flex items-start gap-2 bg-base border border-line rounded-md px-2.5 py-2"
                  >
                    {result.passed ? (
                      <CheckCircle2 className="h-4 w-4 text-healthy shrink-0 mt-0.5" aria-hidden="true" />
                    ) : (
                      <XCircle className="h-4 w-4 text-critical shrink-0 mt-0.5" aria-hidden="true" />
                    )}
                    <div className="min-w-0">
                      <p className="text-xs text-ink">{result.test_name}</p>
                      <p className="text-2xs text-ink-faint">
                        expected <span className="text-ink-muted">{result.expected}</span>, got{' '}
                        <span className={result.passed ? 'text-healthy' : 'text-critical'}>
                          {result.actual}
                        </span>
                      </p>
                      {result.detail && (
                        <p className="text-2xs text-ink-muted mt-0.5">{result.detail}</p>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <section>
            <p className="label mb-1.5">Rule definition</p>
            <p className="text-2xs text-ink-faint mb-1.5">
              This is a declarative document interpreted by the detection engine. There is no eval,
              no dynamic import, and no path through this interface that can introduce new
              executable logic.
            </p>
            <CodeBlock content={JSON.stringify(rule.definition, null, 2)} maxHeight={320} />
          </section>

          {rule.references.length > 0 && (
            <section>
              <p className="label mb-1.5">References</p>
              <ul className="space-y-0.5">
                {rule.references.map((reference) => (
                  <li key={reference}>
                    <a
                      href={reference}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="link text-xs"
                    >
                      {reference}
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </Modal>
  )
}
