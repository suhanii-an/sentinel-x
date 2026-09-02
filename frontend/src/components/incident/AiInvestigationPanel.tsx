import clsx from 'clsx'
import { AlertOctagon, Bot, ShieldCheck, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { useAiHistory, useAiStatus, useAskAi } from '@/api/queries'
import {
  Badge,
  Callout,
  Code,
  ConfidenceBadge,
  EmptyState,
  Loading,
  Panel,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import type { AiResult, IncidentDetail } from '@/types'
import { durationMs, relativeTime } from '@/utils/format'

const TASKS = [
  { id: 'explain', label: 'Why is this critical?' },
  { id: 'summarize', label: 'Summarise the incident' },
  { id: 'next_steps', label: 'What should I check next?' },
] as const

/**
 * The AI panel.
 *
 * Two things this deliberately does that most "AI security copilot" panels do
 * not: it renders the grounding result (which citations were kept, which were
 * stripped) alongside the answer, and it shows prompt-injection findings from
 * the telemetry the model was given. Both are the difference between an answer
 * an analyst can act on and one they have to take on faith.
 */
export function AiInvestigationPanel({ incident }: { incident: IncidentDetail }) {
  const status = useAiStatus()
  const history = useAiHistory(incident.incident_id)
  const ask = useAskAi()
  const { can } = useAuth()

  const [question, setQuestion] = useState('')
  const [strict, setStrict] = useState(false)
  const [result, setResult] = useState<AiResult | null>(null)

  const run = (task: string, text?: string) => {
    ask.mutate(
      { incidentId: incident.incident_id, task, question: text, strict },
      { onSuccess: (data) => setResult(data) },
    )
  }

  if (status.isLoading) return <Loading rows={3} label="Checking assistant availability" />

  if (status.data && !status.data.available) {
    return (
      <div className="space-y-4 max-w-3xl">
        <Panel title="AI assistant unavailable">
          <div className="flex items-start gap-3">
            <Bot className="h-5 w-5 text-ink-faint shrink-0 mt-0.5" aria-hidden="true" />
            <div className="space-y-2">
              <p className="text-sm text-ink">{status.data.message}</p>
              <p className="text-xs text-ink-muted">
                Set <Code>AI_PROVIDER</Code> and <Code>AI_API_KEY</Code> in your environment to
                enable it. Nothing else in the platform changes.
              </p>
            </div>
          </div>
        </Panel>

        <Callout tone="info" title="Why the platform still works without it">
          Detection is deterministic and runs before any model is consulted. Rules, thresholds,
          sequences, indicator matching and statistical baselining decided that this incident exists,
          computed its risk score and mapped its ATT&CK techniques. The assistant explains evidence
          that already exists; it is not part of the detection path.
        </Callout>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
      <div className="xl:col-span-2 space-y-5">
        <Panel
          title="Ask about this incident"
          subtitle={`${status.data?.provider} · answers are validated against the evidence before display`}
        >
          {!can('analyst') ? (
            <p className="text-xs text-ink-faint">
              Your role can read investigations but not start new ones.
            </p>
          ) : (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {TASKS.map((task) => (
                  <button
                    key={task.id}
                    type="button"
                    className="btn-secondary text-xs"
                    disabled={ask.isPending}
                    onClick={() => run(task.id)}
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                    {task.label}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' && question.trim()) run('question', question.trim())
                  }}
                  placeholder="Ask your own question about this incident…"
                  aria-label="Question for the AI assistant"
                  className="input flex-1 min-w-[240px]"
                />
                <button
                  type="button"
                  className="btn-primary"
                  disabled={!question.trim() || ask.isPending}
                  onClick={() => run('question', question.trim())}
                >
                  {ask.isPending ? <Spinner /> : null}
                  Ask
                </button>
              </div>

              {status.data?.suggested_questions?.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {status.data.suggested_questions.slice(0, 6).map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      className="chip border-line text-ink-muted hover:text-ink hover:border-line-strong"
                      onClick={() => {
                        setQuestion(suggestion)
                        run('question', suggestion)
                      }}
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              ) : null}

              <label className="flex items-center gap-2 text-xs text-ink-muted">
                <input
                  type="checkbox"
                  checked={strict}
                  onChange={(event) => setStrict(event.target.checked)}
                  className="accent-cyan-400"
                />
                Strict grounding — discard the entire answer if it cites anything outside the
                supplied evidence, rather than stripping the bad citations
              </label>

              {ask.isError && (
                <p className="text-xs text-critical">{(ask.error as Error).message}</p>
              )}
            </div>
          )}
        </Panel>

        {ask.isPending && <Loading rows={3} label="Waiting for the assistant" />}
        {result && <AnswerCard result={result} incident={incident} />}

        <Panel title="Investigation history" subtitle="Includes rejected responses" dense>
          {history.isLoading && <Loading rows={2} />}
          {history.data && history.data.items.length === 0 && (
            <EmptyState title="No AI interactions yet for this incident" />
          )}
          {history.data && history.data.items.length > 0 && (
            <>
              <div className="px-4 py-2 border-b border-line flex gap-4 text-2xs text-ink-muted">
                <span>{history.data.total} total</span>
                <span className="text-healthy">{history.data.accepted} accepted</span>
                <span className="text-high">{history.data.rejected} rejected</span>
              </div>
              <ul className="divide-y divide-line/60 max-h-80 overflow-y-auto">
                {history.data.items.map((entry) => {
                  const item = entry as Record<string, unknown>
                  const accepted = item.validation_status === 'accepted'
                  return (
                    <li key={String(item.id)} className="px-4 py-2.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge
                          className={
                            accepted
                              ? 'border-healthy/40 text-healthy'
                              : 'border-high/40 text-high'
                          }
                        >
                          {String(item.validation_status).replace(/_/g, ' ')}
                        </Badge>
                        <span className="text-xs text-ink-muted">{String(item.task)}</span>
                        <span className="text-2xs text-ink-faint ml-auto">
                          {relativeTime(String(item.created_at))} · {String(item.created_by)}
                        </span>
                      </div>
                      <p className="text-xs text-ink mt-1 truncate">{String(item.question)}</p>
                      {Boolean(item.injection_flagged) && (
                        <p className="text-2xs text-high mt-1">
                          Prompt-injection content was present in the supplied telemetry.
                        </p>
                      )}
                    </li>
                  )
                })}
              </ul>
            </>
          )}
        </Panel>
      </div>

      <div className="space-y-5">
        <Panel title="How this is kept honest">
          <ul className="space-y-3 text-xs text-ink-muted">
            {Object.entries(status.data?.grounding_policy ?? {}).map(([key, value]) => (
              <li key={key}>
                <p className="text-ink font-medium capitalize mb-0.5">{key.replace(/_/g, ' ')}</p>
                <p className="leading-relaxed">{value}</p>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Evidence the assistant can see">
          <dl className="text-xs space-y-1.5">
            <div className="flex justify-between">
              <dt className="text-ink-faint">Detections</dt>
              <dd className="text-ink tabular-nums">{incident.alerts.length}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-ink-faint">Events</dt>
              <dd className="text-ink tabular-nums">{incident.event_count}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-ink-faint">ATT&CK techniques</dt>
              <dd className="text-ink tabular-nums">{incident.techniques.length}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-ink-faint">Indicator matches</dt>
              <dd className="text-ink tabular-nums">{incident.ioc_matches.length}</dd>
            </div>
          </dl>
          <p className="text-2xs text-ink-faint mt-3 leading-relaxed">
            The assistant receives only these records. It has no database access, no tools and no
            ability to take any action.
          </p>
        </Panel>
      </div>
    </div>
  )
}

function AnswerCard({ result, incident }: { result: AiResult; incident: IncidentDetail }) {
  const rejected = !result.accepted

  return (
    <Panel
      title={rejected ? 'Response rejected' : 'Assistant response'}
      subtitle={`${result.provider} · ${result.model} · ${durationMs(result.latency_ms)}`}
      actions={
        rejected ? (
          <Badge className="border-critical/40 text-critical">
            {result.validation_status.replace(/_/g, ' ')}
          </Badge>
        ) : (
          <Badge className="border-healthy/40 text-healthy">
            <ShieldCheck className="h-3 w-3" /> grounded
          </Badge>
        )
      }
    >
      {result.prompt_injection.flagged && (
        <Callout tone="warning" title="Prompt-injection content detected in this incident's telemetry">
          <p>
            Instruction-shaped text was found in the evidence supplied to the model. It was passed as
            delimited, labelled data and could not reach instruction position. This is worth noting
            in the investigation: an attacker placed it there deliberately.
          </p>
          <ul className="mt-2 space-y-1">
            {result.prompt_injection.signals.slice(0, 5).map((signal, index) => (
              <li key={index}>
                <span className="text-high">{signal.signal}</span> in{' '}
                <Code>{signal.location}</Code>
                <p className="mono text-ink-faint mt-0.5 break-all">{signal.excerpt}</p>
              </li>
            ))}
          </ul>
        </Callout>
      )}

      {rejected ? (
        <div className="mt-3 space-y-2">
          <div className="flex items-start gap-2">
            <AlertOctagon className="h-4 w-4 text-critical shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-sm text-ink">
              The response failed validation and was discarded rather than shown with a caveat.
            </p>
          </div>
          <ul className="text-xs text-ink-muted space-y-1 pl-6">
            {result.validation_errors.map((error, index) => (
              <li key={index}>{error}</li>
            ))}
          </ul>
        </div>
      ) : (
        result.answer && (
          <div className="mt-3 space-y-4">
            <p className="text-sm text-ink leading-relaxed">{result.answer.summary}</p>

            {result.answer.reasoning && (
              <div>
                <p className="label mb-1">Reasoning</p>
                <p className="text-sm text-ink-muted leading-relaxed">{result.answer.reasoning}</p>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-3">
              <span className="label">Confidence</span>
              <ConfidenceBadge value={result.answer.confidence} />
              <span className="text-xs text-ink-muted flex-1">
                {result.answer.confidence_rationale}
              </span>
            </div>

            {result.answer.evidence_ids.length > 0 && (
              <div>
                <p className="label mb-1.5">
                  Evidence cited ({result.answer.evidence_ids.length} of{' '}
                  {result.grounding.evidence_offered} offered)
                </p>
                <div className="flex flex-wrap gap-1">
                  {result.answer.evidence_ids.map((id) => (
                    <EvidenceChip key={id} id={id} incidentId={incident.incident_id} />
                  ))}
                </div>
              </div>
            )}

            {result.answer.mitre_techniques.length > 0 && (
              <div>
                <p className="label mb-1.5">ATT&CK techniques referenced</p>
                <div className="flex flex-wrap gap-1">
                  {result.answer.mitre_techniques.map((technique) => (
                    <Link
                      key={technique}
                      to={`/mitre?technique=${technique}`}
                      className="chip border-accent/30 text-accent"
                    >
                      {technique}
                    </Link>
                  ))}
                </div>
              </div>
            )}

            {result.answer.recommended_actions.length > 0 && (
              <div>
                <p className="label mb-1.5">Suggested next steps</p>
                <ul className="space-y-1">
                  {result.answer.recommended_actions.map((action, index) => (
                    <li key={index} className="text-sm text-ink-muted flex gap-2">
                      <span className="text-accent shrink-0" aria-hidden="true">
                        {index + 1}.
                      </span>
                      <span>{action}</span>
                    </li>
                  ))}
                </ul>
                <p className="text-2xs text-ink-faint mt-2">
                  Proposals for the analyst to evaluate. The assistant cannot take any action.
                </p>
              </div>
            )}

            {result.answer.limitations.length > 0 && (
              <Callout tone="info" title="What the evidence does not establish">
                <ul className="space-y-1">
                  {result.answer.limitations.map((limitation, index) => (
                    <li key={index}>{limitation}</li>
                  ))}
                </ul>
              </Callout>
            )}
          </div>
        )
      )}

      {(result.grounding.citations_removed.length > 0 ||
        result.grounding.techniques_removed.length > 0) && (
        <Callout tone="critical" title="Ungrounded references were removed">
          {result.grounding.citations_removed.length > 0 && (
            <p>
              Identifiers not present in the supplied evidence:{' '}
              <span className="mono">{result.grounding.citations_removed.join(', ')}</span>
            </p>
          )}
          {result.grounding.techniques_removed.length > 0 && (
            <p className="mt-1">
              Techniques not observed in this incident:{' '}
              <span className="mono">{result.grounding.techniques_removed.join(', ')}</span>
            </p>
          )}
          <p className="mt-1 text-ink-faint">
            These were stripped before display. The removal is shown rather than hidden, because how
            often a model over-cites is itself worth knowing.
          </p>
        </Callout>
      )}
    </Panel>
  )
}

function EvidenceChip({ id, incidentId }: { id: string; incidentId: string }) {
  const to = id.startsWith('SX-')
    ? `/incidents/${id}`
    : id.startsWith('ALT-')
      ? `/alerts?alert=${id}`
      : id.startsWith('IOC-')
        ? `/iocs/${id}`
        : `/incidents/${incidentId}?tab=evidence`
  return (
    <Link
      to={to}
      className={clsx('chip border-line-strong text-ink-muted hover:text-accent hover:border-accent/50')}
      title="Open the cited evidence"
    >
      {id}
    </Link>
  )
}
