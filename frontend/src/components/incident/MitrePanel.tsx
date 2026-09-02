import { ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'

import { Badge, Callout, Code, ConfidenceBadge, EmptyState, Panel } from '@/components/ui'
import type { IncidentDetail } from '@/types'
import { absoluteTime, timeOnly } from '@/utils/format'

export function MitrePanel({ incident }: { incident: IncidentDetail }) {
  if (!incident.techniques.length) {
    return (
      <Panel>
        <EmptyState
          title="No ATT&CK techniques mapped"
          description="Technique mappings come from the detection rules that fired. No rule in this incident declares one."
        />
      </Panel>
    )
  }

  const byTactic = new Map<string, typeof incident.techniques>()
  for (const technique of incident.techniques) {
    const key = technique.tactic_name ?? 'Unclassified'
    if (!byTactic.has(key)) byTactic.set(key, [])
    byTactic.get(key)!.push(technique)
  }

  return (
    <div className="space-y-5 max-w-5xl">
      <Panel
        title="ATT&CK mapping"
        subtitle={`${incident.techniques.length} techniques across ${byTactic.size} tactics, each backed by named evidence`}
      >
        <div className="space-y-5">
          {[...byTactic.entries()].map(([tactic, techniques]) => (
            <section key={tactic}>
              <div className="flex items-baseline gap-2 mb-2">
                <h3 className="text-sm font-medium text-ink">{tactic}</h3>
                <span className="text-2xs text-ink-faint">
                  {techniques.length} technique{techniques.length === 1 ? '' : 's'}
                </span>
              </div>
              <ul className="space-y-2">
                {techniques.map((technique) => (
                  <li key={technique.technique_id} className="border border-line rounded-md p-3 bg-base">
                    <div className="flex flex-wrap items-start gap-2">
                      <Code className="text-accent border-accent/30">{technique.technique_id}</Code>
                      <span className="text-sm text-ink flex-1 min-w-[180px]">{technique.name}</span>
                      <ConfidenceBadge value={technique.confidence} />
                      {technique.url && (
                        <a
                          href={technique.url}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="link text-xs inline-flex items-center gap-1"
                        >
                          attack.mitre.org
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>

                    <dl className="grid grid-cols-1 sm:grid-cols-3 gap-x-5 gap-y-1 mt-2.5 text-2xs">
                      <div>
                        <dt className="text-ink-faint">First observed</dt>
                        <dd className="text-ink-muted" title={absoluteTime(technique.first_observed)}>
                          {timeOnly(technique.first_observed)}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-ink-faint">Became detectable</dt>
                        <dd className="text-ink-muted" title={absoluteTime(technique.detected_at)}>
                          {timeOnly(technique.detected_at)}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-ink-faint">Evidence</dt>
                        <dd className="text-ink-muted">
                          {technique.evidence_event_ids.length} event
                          {technique.evidence_event_ids.length === 1 ? '' : 's'}
                        </dd>
                      </div>
                    </dl>

                    <div className="flex flex-wrap items-center gap-1.5 mt-2">
                      <span className="text-2xs text-ink-faint">Detected by</span>
                      {technique.source_rule_ids.map((rule) => (
                        <Link
                          key={rule}
                          to={`/detections?rule=${rule}`}
                          className="chip border-line text-ink-muted hover:text-ink"
                        >
                          {rule}
                        </Link>
                      ))}
                    </div>

                    {technique.evidence_event_ids.length > 0 && (
                      <details className="mt-2">
                        <summary className="text-2xs text-ink-faint cursor-pointer hover:text-ink-muted">
                          Show supporting event IDs
                        </summary>
                        <div className="flex flex-wrap gap-1 mt-1.5">
                          {technique.evidence_event_ids.map((eventId) => (
                            <span key={eventId} className="mono text-ink-faint">
                              {eventId}
                            </span>
                          ))}
                        </div>
                      </details>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </Panel>

      <Callout tone="info" title="How these mappings are produced">
        Every technique above comes from a detection rule that declared it and fired on real
        evidence. Nothing is inferred: a technique appears only when a rule mapped to it matched.
        Technique identifiers are validated against the bundled ATT&CK catalogue at rule load time,
        so the platform cannot mint an identifier that does not exist.
      </Callout>

      <div className="flex flex-wrap gap-1.5">
        <span className="label mr-1">All technique IDs</span>
        {incident.technique_ids.map((id) => (
          <Badge key={id} className="border-accent/25 text-accent/90">
            {id}
          </Badge>
        ))}
      </div>
    </div>
  )
}
