import clsx from 'clsx'
import { ChevronRight, Radar } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { useEvent } from '@/api/queries'
import {
  Badge,
  Code,
  CodeBlock,
  CopyButton,
  EmptyState,
  KeyValue,
  Loading,
  Modal,
  SeverityBadge,
} from '@/components/ui'
import type { TimelineEntry } from '@/types'
import { absoluteTime, timeOnly } from '@/utils/format'
import { EVENT_TYPE_LABEL, severityMeta } from '@/utils/severity'

/**
 * The event timeline.
 *
 * Every row is clickable through to the raw record. That is the whole point:
 * a platform that shows an analyst a conclusion without a route back to the
 * underlying log line is asking to be trusted rather than verified.
 */
export function EventTimeline({
  entries,
  maxHeight = 480,
  showAlerts = true,
}: {
  entries: TimelineEntry[]
  maxHeight?: number
  showAlerts?: boolean
}) {
  const [selected, setSelected] = useState<TimelineEntry | null>(null)

  if (!entries.length) {
    return <EmptyState title="No events" description="Nothing has been recorded in this window." />
  }

  return (
    <>
      <ol className="overflow-y-auto divide-y divide-line/50" style={{ maxHeight }}>
        {entries.map((entry) => {
          const meta = severityMeta(entry.severity)
          const alertCount = entry.alert_count ?? entry.alerts?.length ?? 0
          return (
            <li key={entry.event_id}>
              <button
                type="button"
                onClick={() => setSelected(entry)}
                className="w-full text-left px-4 py-2 flex items-start gap-3 hover:bg-elevated/60 transition-colors group"
              >
                <span
                  className="mono text-ink-faint tabular-nums shrink-0 pt-0.5"
                  title={absoluteTime(entry.timestamp)}
                >
                  {timeOnly(entry.timestamp)}
                </span>

                <span
                  className={clsx('shrink-0 pt-0.5 text-sm leading-none', meta.text)}
                  aria-hidden="true"
                  title={`Severity: ${meta.label}`}
                >
                  {alertCount > 0 ? meta.glyph : '·'}
                </span>

                <span className="min-w-0 flex-1">
                  <span className="block text-sm text-ink truncate">{entry.summary}</span>
                  <span className="flex flex-wrap items-center gap-1.5 mt-1">
                    <Badge className="border-line/70">
                      {EVENT_TYPE_LABEL[entry.event_type] ?? entry.event_type}
                    </Badge>
                    {entry.host && (
                      <span className="mono text-ink-faint">{entry.host}</span>
                    )}
                    {entry.user && <span className="mono text-ink-faint">{entry.user}</span>}
                    {entry.status === 'failure' && (
                      <span className="text-2xs text-high">failed</span>
                    )}
                    {showAlerts && alertCount > 0 && (
                      <span className={clsx('text-2xs font-medium', meta.text)}>
                        {alertCount} detection{alertCount === 1 ? '' : 's'}
                      </span>
                    )}
                    {entry.ioc_matches && entry.ioc_matches.length > 0 && (
                      <span className="text-2xs text-critical inline-flex items-center gap-1">
                        <Radar className="h-3 w-3" aria-hidden="true" />
                        indicator match
                      </span>
                    )}
                  </span>
                </span>

                <ChevronRight
                  className="h-4 w-4 text-ink-faint shrink-0 opacity-0 group-hover:opacity-100 transition-opacity mt-0.5"
                  aria-hidden="true"
                />
              </button>
            </li>
          )
        })}
      </ol>

      <EventDetailModal entry={selected} onClose={() => setSelected(null)} />
    </>
  )
}

function EventDetailModal({
  entry,
  onClose,
}: {
  entry: TimelineEntry | null
  onClose: () => void
}) {
  const detail = useEvent(entry?.event_id)

  return (
    <Modal open={Boolean(entry)} onClose={onClose} title={entry?.event_id ?? 'Event'} wide>
      {!entry ? null : (
        <div className="space-y-4">
          <p className="text-sm text-ink">{entry.summary}</p>

          <KeyValue
            columns={3}
            items={[
              { label: 'Event ID', value: <Code>{entry.event_id}</Code> },
              { label: 'Timestamp (UTC)', value: absoluteTime(entry.timestamp) },
              { label: 'Type', value: EVENT_TYPE_LABEL[entry.event_type] ?? entry.event_type },
              { label: 'Action', value: entry.action ?? '—' },
              { label: 'Status', value: entry.status },
              { label: 'Source', value: detail.data?.source ?? '—' },
              {
                label: 'Host',
                value: entry.host ? (
                  <Link to={`/hosts/${entry.host}`} className="link">
                    {entry.host}
                  </Link>
                ) : (
                  '—'
                ),
              },
              {
                label: 'Account',
                value: entry.user ? (
                  <Link to={`/users/${entry.user}`} className="link">
                    {entry.user}
                  </Link>
                ) : (
                  '—'
                ),
              },
              { label: 'Source address', value: entry.source_ip ?? '—' },
            ]}
          />

          {(entry.alerts?.length ?? 0) > 0 && (
            <section>
              <h3 className="label mb-2">Detections triggered by this event</h3>
              <ul className="space-y-1.5">
                {entry.alerts!.map((alert) => (
                  <li
                    key={alert.alert_id}
                    className="flex items-center gap-2 flex-wrap bg-base border border-line rounded-md px-2.5 py-1.5"
                  >
                    <SeverityBadge severity={alert.severity} />
                    <Code>{alert.rule_id}</Code>
                    {alert.step && (
                      <span className="text-2xs text-ink-faint">step: {alert.step}</span>
                    )}
                    <span className="mono text-ink-faint ml-auto">{alert.alert_id}</span>
                    {alert.technique_ids.length > 0 && (
                      <span className="text-2xs text-accent w-full">
                        {alert.technique_ids.join(', ')}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {entry.ioc_matches && entry.ioc_matches.length > 0 && (
            <section>
              <h3 className="label mb-2">Indicator matches</h3>
              <ul className="space-y-1">
                {entry.ioc_matches.map((match) => (
                  <li key={match.ioc_id} className="text-xs text-ink-muted">
                    <Code>{match.indicator}</Code> matched on field{' '}
                    <span className="text-ink">{match.field}</span> ({match.ioc_id})
                  </li>
                ))}
              </ul>
            </section>
          )}

          {detail.isLoading && <Loading rows={2} label="Loading raw record" />}

          {detail.data && (
            <>
              {detail.data.command_line && (
                <section>
                  <h3 className="label mb-1">Command line</h3>
                  <CodeBlock content={detail.data.command_line} maxHeight={120} />
                </section>
              )}

              <section>
                <div className="flex items-center justify-between mb-1">
                  <h3 className="label">Normalized event</h3>
                  <CopyButton
                    value={JSON.stringify(detail.data, null, 2)}
                    label="Copy normalized event"
                  />
                </div>
                <CodeBlock
                  content={JSON.stringify(
                    {
                      event_id: detail.data.event_id,
                      timestamp: detail.data.timestamp,
                      event_type: detail.data.event_type,
                      source: detail.data.source,
                      host: detail.data.host_ref,
                      user: detail.data.user_ref,
                      source_ip: detail.data.source_ip,
                      destination_ip: detail.data.destination_ip,
                      destination_port: detail.data.destination_port,
                      process: detail.data.process_name,
                      command_line: detail.data.command_line,
                      file_path: detail.data.file_path,
                      cloud_account: detail.data.cloud_account,
                      action: detail.data.action,
                      status: detail.data.status,
                      metadata: detail.data.metadata,
                    },
                    null,
                    2,
                  )}
                  maxHeight={240}
                />
              </section>

              <section>
                <div className="flex items-center justify-between mb-1">
                  <h3 className="label">Raw source record</h3>
                  <CopyButton
                    value={JSON.stringify(detail.data.raw_event, null, 2)}
                    label="Copy raw record"
                  />
                </div>
                <p className="text-2xs text-ink-faint mb-1">
                  Preserved verbatim from the telemetry source. This is what the normalizer parsed.
                </p>
                <CodeBlock content={JSON.stringify(detail.data.raw_event, null, 2)} maxHeight={200} />
              </section>
            </>
          )}
        </div>
      )}
    </Modal>
  )
}
