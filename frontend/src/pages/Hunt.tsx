import clsx from 'clsx'
import { Play, Plus, Save, Sparkles, Trash2 } from 'lucide-react'
import { useState } from 'react'

import {
  useHuntSchema,
  useRunHunt,
  useSaveHunt,
  useSavedHunts,
  useTranslateHunt,
} from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  CodeBlock,
  EmptyState,
  ErrorState,
  Loading,
  Panel,
  SectionHeading,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import type { HuntFilter, HuntQuery, HuntResult, SavedHunt } from '@/types'
import { absoluteTime, duration } from '@/utils/format'

const EMPTY_QUERY: HuntQuery = {
  dataset: 'events',
  filters: [],
  logic: 'and',
  time_range: { last_minutes: 1440 },
  order_by: null,
  order: 'desc',
  limit: 100,
  offset: 0,
}

const TIME_RANGES = [
  { label: 'Last hour', minutes: 60 },
  { label: 'Last 24 hours', minutes: 1440 },
  { label: 'Last 7 days', minutes: 10080 },
  { label: 'Last 30 days', minutes: 43200 },
]

export function Hunt() {
  const schema = useHuntSchema()
  const saved = useSavedHunts()
  const run = useRunHunt()
  const translate = useTranslateHunt()
  const saveHunt = useSaveHunt()
  const { can } = useAuth()

  const [query, setQuery] = useState<HuntQuery>(EMPTY_QUERY)
  const [question, setQuestion] = useState('')
  const [result, setResult] = useState<HuntResult | null>(null)
  const [saveName, setSaveName] = useState('')

  const fields = schema.data?.datasets[query.dataset] ?? []
  const operators = schema.data?.operators ?? []

  const execute = (next: HuntQuery = query) => {
    setQuery(next)
    run.mutate(next, { onSuccess: (data) => setResult(data) })
  }

  const loadSaved = (hunt: SavedHunt) => {
    const loaded = { ...EMPTY_QUERY, ...hunt.query }
    setQuery(loaded)
    execute(loaded)
  }

  const updateFilter = (index: number, patch: Partial<HuntFilter>) => {
    setQuery((current) => ({
      ...current,
      filters: current.filters.map((filter, i) => (i === index ? { ...filter, ...patch } : filter)),
    }))
  }

  return (
    <>
      <PageHeader
        title="Threat Hunting"
        description="Search telemetry with structured queries. A hunt is a validated document compiled into a parameterised query — never a SQL string, including when a language model writes it."
      />

      <PageBody className="space-y-5">
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-5">
          <div className="xl:col-span-3 space-y-5">
            <Panel title="Ask in plain English" subtitle="Translated into a validated query, then executed">
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' && question.trim()) {
                      translate.mutate(
                        { question: question.trim(), execute: true },
                        {
                          onSuccess: (data) => {
                            if (data.query) setQuery({ ...EMPTY_QUERY, ...data.query })
                            if (data.results) setResult(data.results)
                          },
                        },
                      )
                    }
                  }}
                  placeholder="e.g. failed logins followed by a successful login from the same address"
                  aria-label="Natural language hunt question"
                  className="input flex-1 min-w-[260px]"
                />
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!question.trim() || translate.isPending || !can('analyst')}
                  onClick={() =>
                    translate.mutate(
                      { question: question.trim(), execute: true },
                      {
                        onSuccess: (data) => {
                          if (data.query) setQuery({ ...EMPTY_QUERY, ...data.query })
                          if (data.results) setResult(data.results)
                        },
                      },
                    )
                  }
                >
                  {translate.isPending ? <Spinner /> : <Sparkles className="h-4 w-4" />}
                  Translate &amp; run
                </button>
              </div>

              {translate.isError && (
                <p className="text-xs text-critical mt-2">{(translate.error as Error).message}</p>
              )}

              {translate.data && (
                <div className="mt-3 space-y-2">
                  {translate.data.interpretation ? (
                    <Callout tone="healthy" title="How the question was understood">
                      <p>{translate.data.interpretation}</p>
                      <p className="mt-1 text-ink-faint">
                        Review this before trusting the results — it is the query that actually ran.
                      </p>
                    </Callout>
                  ) : (
                    <Callout tone="critical" title="Translation rejected">
                      <p>
                        The model's output did not validate against the hunt schema, so nothing was
                        executed.
                      </p>
                      <ul className="mt-1">
                        {translate.data.ai.validation_errors.map((error, index) => (
                          <li key={index}>{error}</li>
                        ))}
                      </ul>
                    </Callout>
                  )}
                </div>
              )}

              <p className="text-2xs text-ink-faint mt-3 leading-relaxed">
                The model emits a JSON query document, which is validated by the same schema a
                hand-written hunt goes through and then compiled into a parameterised query. It never
                produces SQL and its output is never executed directly.
              </p>
            </Panel>

            <Panel
              title="Query builder"
              actions={
                <>
                  <button
                    type="button"
                    className="btn-secondary text-xs"
                    onClick={() =>
                      setQuery((current) => ({
                        ...current,
                        filters: [...current.filters, { field: fields[0] ?? 'event_type', operator: 'eq', value: '' }],
                      }))
                    }
                  >
                    <Plus className="h-3.5 w-3.5" /> Filter
                  </button>
                  <button
                    type="button"
                    className="btn-primary text-xs"
                    onClick={() => execute()}
                    disabled={run.isPending}
                  >
                    {run.isPending ? <Spinner /> : <Play className="h-3.5 w-3.5" />}
                    Run
                  </button>
                </>
              }
            >
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-3">
                  <label className="flex items-center gap-2 text-xs">
                    <span className="label">Dataset</span>
                    <select
                      value={query.dataset}
                      onChange={(event) =>
                        setQuery((current) => ({
                          ...current,
                          dataset: event.target.value as HuntQuery['dataset'],
                          filters: [],
                          order_by: null,
                        }))
                      }
                      className="input max-w-[140px] py-1"
                    >
                      {Object.keys(schema.data?.datasets ?? { events: [] }).map((dataset) => (
                        <option key={dataset} value={dataset}>
                          {dataset}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="flex items-center gap-2 text-xs">
                    <span className="label">Match</span>
                    <select
                      value={query.logic}
                      onChange={(event) =>
                        setQuery((current) => ({
                          ...current,
                          logic: event.target.value as 'and' | 'or',
                        }))
                      }
                      className="input max-w-[90px] py-1"
                    >
                      <option value="and">all</option>
                      <option value="or">any</option>
                    </select>
                  </label>

                  <label className="flex items-center gap-2 text-xs">
                    <span className="label">Window</span>
                    <select
                      value={query.time_range?.last_minutes ?? ''}
                      onChange={(event) =>
                        setQuery((current) => ({
                          ...current,
                          time_range: event.target.value
                            ? { last_minutes: Number(event.target.value) }
                            : null,
                        }))
                      }
                      className="input max-w-[150px] py-1"
                    >
                      <option value="">All time</option>
                      {TIME_RANGES.map((range) => (
                        <option key={range.minutes} value={range.minutes}>
                          {range.label}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="flex items-center gap-2 text-xs">
                    <span className="label">Limit</span>
                    <input
                      type="number"
                      min={1}
                      max={1000}
                      value={query.limit}
                      onChange={(event) =>
                        setQuery((current) => ({ ...current, limit: Number(event.target.value) }))
                      }
                      className="input max-w-[80px] py-1"
                    />
                  </label>
                </div>

                {query.filters.length === 0 ? (
                  <p className="text-xs text-ink-faint">
                    No filters. The query will return the most recent {query.limit} records from{' '}
                    {query.dataset}.
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {query.filters.map((filter, index) => (
                      <li key={index} className="flex flex-wrap items-center gap-2">
                        <input
                          list="hunt-fields"
                          value={filter.field}
                          onChange={(event) => updateFilter(index, { field: event.target.value })}
                          aria-label={`Filter ${index + 1} field`}
                          className="input max-w-[220px] py-1 mono"
                        />
                        <select
                          value={filter.operator}
                          onChange={(event) => updateFilter(index, { operator: event.target.value })}
                          aria-label={`Filter ${index + 1} operator`}
                          className="input max-w-[130px] py-1"
                        >
                          {operators.map((operator) => (
                            <option key={operator} value={operator}>
                              {operator}
                            </option>
                          ))}
                        </select>
                        <input
                          type="text"
                          value={
                            Array.isArray(filter.value)
                              ? (filter.value as string[]).join(', ')
                              : String(filter.value ?? '')
                          }
                          onChange={(event) => {
                            const raw = event.target.value
                            const value =
                              filter.operator === 'in' || filter.operator === 'not_in'
                                ? raw.split(',').map((part) => part.trim()).filter(Boolean)
                                : raw
                            updateFilter(index, { value })
                          }}
                          placeholder={
                            filter.operator === 'in' || filter.operator === 'not_in'
                              ? 'comma, separated, values'
                              : 'value'
                          }
                          aria-label={`Filter ${index + 1} value`}
                          className="input flex-1 min-w-[160px] py-1"
                        />
                        <button
                          type="button"
                          className="btn-ghost p-1"
                          aria-label={`Remove filter ${index + 1}`}
                          onClick={() =>
                            setQuery((current) => ({
                              ...current,
                              filters: current.filters.filter((_, i) => i !== index),
                            }))
                          }
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}

                <datalist id="hunt-fields">
                  {fields.map((field) => (
                    <option key={field} value={field} />
                  ))}
                  {query.dataset === 'events' &&
                    (schema.data?.metadata_fields.common_keys ?? []).map((key) => (
                      <option key={key} value={`metadata.${key}`} />
                    ))}
                </datalist>

                {run.isError && <p className="text-xs text-critical">{(run.error as Error).message}</p>}
              </div>
            </Panel>

            {result && <HuntResults result={result} />}
          </div>

          <div className="space-y-5">
            <Panel title="Saved hunts" dense>
              {saved.isLoading && <Loading rows={3} />}
              {saved.isError && <ErrorState error={saved.error} onRetry={saved.refetch} />}
              {saved.data && (
                <ul className="divide-y divide-line/60">
                  {saved.data.map((hunt) => (
                    <li key={hunt.id}>
                      <button
                        type="button"
                        onClick={() => loadSaved(hunt)}
                        className="w-full text-left px-4 py-2.5 hover:bg-elevated/60 transition-colors"
                      >
                        <div className="flex items-start gap-2">
                          <span className="text-sm text-ink flex-1">{hunt.name}</span>
                          {hunt.is_builtin && (
                            <Badge className="border-line text-ink-faint shrink-0">built-in</Badge>
                          )}
                        </div>
                        <p className="text-2xs text-ink-muted mt-1 leading-relaxed">
                          {hunt.description}
                        </p>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            {can('analyst') && result && (
              <Panel title="Save this hunt">
                <div className="space-y-2">
                  <input
                    type="text"
                    value={saveName}
                    onChange={(event) => setSaveName(event.target.value)}
                    placeholder="Name this hunt"
                    aria-label="Hunt name"
                    className="input"
                  />
                  <button
                    type="button"
                    className="btn-secondary w-full text-xs"
                    disabled={!saveName.trim() || saveHunt.isPending}
                    onClick={() =>
                      saveHunt.mutate(
                        { name: saveName.trim(), description: result.interpretation, query },
                        { onSuccess: () => setSaveName('') },
                      )
                    }
                  >
                    <Save className="h-3.5 w-3.5" /> Save
                  </button>
                </div>
              </Panel>
            )}

            {schema.data && (
              <Panel title="Why this is safe">
                <p className="text-xs text-ink-muted leading-relaxed">{schema.data.safety}</p>
                <p className="text-2xs text-ink-faint mt-2">
                  {schema.data.sequence.note} Correlatable fields:{' '}
                  {schema.data.sequence.correlatable_fields.join(', ')}.
                </p>
              </Panel>
            )}
          </div>
        </div>
      </PageBody>
    </>
  )
}

function HuntResults({ result }: { result: HuntResult }) {
  const [showSql, setShowSql] = useState(false)
  const columns =
    result.rows.length > 0
      ? Object.keys(result.rows[0]).filter(
          (key) => !['metadata', 'raw_event', 'kind'].includes(key),
        )
      : []

  return (
    <Panel
      title="Results"
      subtitle={`${result.returned} of ${result.total} in ${result.duration_ms}ms`}
      actions={
        result.compiled_sql && (
          <button type="button" className="btn-ghost text-xs" onClick={() => setShowSql((v) => !v)}>
            {showSql ? 'Hide' : 'Show'} compiled SQL
          </button>
        )
      }
      dense
    >
      <div className="px-4 py-2 border-b border-line">
        <p className="text-xs text-ink-muted">{result.interpretation}</p>
      </div>

      {showSql && (
        <div className="px-4 py-3 border-b border-line">
          <SectionHeading hint="parameterised — values are bound, never interpolated">
            Compiled query
          </SectionHeading>
          <CodeBlock content={result.compiled_sql} maxHeight={160} />
        </div>
      )}

      {result.matches.length > 0 && (
        <div className="px-4 py-3 border-b border-line">
          <SectionHeading>Sequence matches ({result.matches.length})</SectionHeading>
          <ul className="space-y-2">
            {result.matches.map((match, index) => (
              <li key={index} className="border border-line rounded-md p-2.5 bg-base">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {Object.entries(match.correlation).map(([field, value]) => (
                    <Code key={field}>
                      {field}={value || '(none)'}
                    </Code>
                  ))}
                  <span className="text-ink-faint ml-auto">
                    spanned {duration(match.span_seconds)}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 mt-2">
                  {match.steps.map((step, stepIndex) => (
                    <span key={step.name} className="flex items-center gap-2">
                      {stepIndex > 0 && (
                        <span className="text-ink-faint" aria-hidden="true">
                          →
                        </span>
                      )}
                      <span className="chip border-accent/30 text-accent">
                        {step.name}
                        <span className="text-ink-faint">×{step.count}</span>
                      </span>
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.rows.length === 0 ? (
        <EmptyState
          title="No matching records"
          description="Try widening the time window or relaxing a filter."
        />
      ) : (
        <div className="table-wrap max-h-[520px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                {columns.map((column) => (
                  <th key={column}>{column.replace(/_/g, ' ')}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row, index) => (
                <tr key={index}>
                  {columns.map((column) => {
                    const value = row[column]
                    const isTime = column === 'timestamp'
                    return (
                      <td
                        key={column}
                        className={clsx(
                          'max-w-[260px] truncate',
                          ['id', 'event_id', 'host', 'user', 'source_ip'].includes(column) && 'mono',
                        )}
                        title={String(value ?? '')}
                      >
                        {value === null || value === undefined
                          ? '—'
                          : isTime
                            ? absoluteTime(String(value))
                            : typeof value === 'object'
                              ? JSON.stringify(value)
                              : String(value)}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {result.truncated && (
        <p className="px-4 py-2 text-2xs text-ink-faint border-t border-line">
          Results were truncated at the query limit. Narrow the filters for a complete set.
        </p>
      )}
    </Panel>
  )
}
