import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { useIoc, useIocProvenance, useIocs } from '@/api/queries'
import {
  Badge,
  Callout,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  Loading,
  Modal,
  Pagination,
  Panel,
  QueryBoundary,
  SeverityBadge,
} from '@/components/ui'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, relativeTime } from '@/utils/format'

const PAGE_SIZE = 50

export function Indicators() {
  const { iocId } = useParams<{ iocId: string }>()
  const [offset, setOffset] = useState(0)
  const [type, setType] = useState('')
  const [matchedOnly, setMatchedOnly] = useState(false)
  const [selected, setSelected] = useState<string | null>(iocId ?? null)

  const query = useIocs({
    limit: PAGE_SIZE,
    offset,
    ioc_type: type || undefined,
    matched_only: matchedOnly || undefined,
  })
  const provenance = useIocProvenance()

  return (
    <>
      <PageHeader
        title="Indicators"
        description="Known-bad values matched against incoming telemetry. Indicator hits are corroboration, not proof — an alert inherits the indicator's own confidence."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={type}
              onChange={(event) => {
                setType(event.target.value)
                setOffset(0)
              }}
              aria-label="Filter by indicator type"
              className="input max-w-[140px]"
            >
              <option value="">All types</option>
              {['ip', 'domain', 'url', 'hash', 'username', 'hostname'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1.5 text-xs text-ink-muted whitespace-nowrap">
              <input
                type="checkbox"
                checked={matchedOnly}
                onChange={(event) => {
                  setMatchedOnly(event.target.checked)
                  setOffset(0)
                }}
                className="accent-cyan-400"
              />
              Matched only
            </label>
          </div>
        }
      />

      <PageBody className="space-y-5">
        {provenance.data && (
          <Callout tone="warning" title={`Provenance: ${provenance.data.provenance}`}>
            <p>{provenance.data.notice}</p>
            <p className="mt-2 text-ink-faint">
              External feed support: {provenance.data.external_feed_support}
            </p>
          </Callout>
        )}

        <Panel dense>
          <QueryBoundary
            query={query}
            empty={{ title: 'No indicators', description: 'Load the bundled dataset from the API or add one manually.' }}
            context="Could not load indicators"
          >
            {(page) => (
              <>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Indicator</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Feed confidence</th>
                        <th>Matches</th>
                        <th>Source</th>
                        <th>Tags</th>
                        <th>State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((ioc) => (
                        <tr
                          key={ioc.ioc_id}
                          className="cursor-pointer"
                          onClick={() => setSelected(ioc.ioc_id)}
                        >
                          <td className="mono text-accent">{ioc.indicator}</td>
                          <td className="text-ink-muted">{ioc.ioc_type}</td>
                          <td>
                            <SeverityBadge severity={ioc.severity} showLabel={false} />
                          </td>
                          <td>
                            <ConfidenceBadge value={ioc.confidence} />
                          </td>
                          <td className="tabular-nums">
                            {ioc.match_count > 0 ? (
                              <span className="text-critical font-medium">{ioc.match_count}</span>
                            ) : (
                              <span className="text-ink-faint">0</span>
                            )}
                          </td>
                          <td className="text-ink-muted">{ioc.source}</td>
                          <td>
                            <div className="flex flex-wrap gap-1 max-w-[220px]">
                              {ioc.tags.slice(0, 3).map((tag) => (
                                <Badge key={tag} className="border-line text-ink-faint">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          </td>
                          <td>
                            {ioc.is_blocked ? (
                              <Badge className="border-high/40 text-high">blocked (sim)</Badge>
                            ) : ioc.is_active ? (
                              <span className="text-xs text-healthy">active</span>
                            ) : (
                              <span className="text-xs text-ink-faint">inactive</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pagination total={page.total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
              </>
            )}
          </QueryBoundary>
        </Panel>
      </PageBody>

      <IndicatorModal iocId={selected} onClose={() => setSelected(null)} />
    </>
  )
}

function IndicatorModal({ iocId, onClose }: { iocId: string | null; onClose: () => void }) {
  const query = useIoc(iocId ?? undefined)

  return (
    <Modal open={Boolean(iocId)} onClose={onClose} title={iocId ?? 'Indicator'} wide>
      {query.isLoading && <Loading rows={3} />}
      {query.isError && <ErrorState error={query.error} onRetry={query.refetch} />}
      {query.data && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-accent text-base">{query.data.indicator}</span>
            <Badge>{query.data.ioc_type}</Badge>
            <SeverityBadge severity={query.data.severity} />
            <ConfidenceBadge value={query.data.confidence} />
          </div>

          {query.data.description && (
            <p className="text-sm text-ink-muted">{query.data.description}</p>
          )}

          <KeyValue
            columns={3}
            items={[
              { label: 'Indicator ID', value: query.data.ioc_id },
              { label: 'Source', value: query.data.source },
              { label: 'Matches observed', value: query.data.match_count },
              { label: 'First seen', value: absoluteTime(query.data.first_seen) },
              { label: 'Last matched', value: absoluteTime(query.data.last_seen) },
              {
                label: 'State',
                value: query.data.is_blocked
                  ? 'Blocked (simulated)'
                  : query.data.is_active
                    ? 'Active'
                    : 'Inactive',
              },
            ]}
          />

          {query.data.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {query.data.tags.map((tag) => (
                <Badge key={tag} className="border-line text-ink-faint">
                  {tag}
                </Badge>
              ))}
            </div>
          )}

          {query.data.related_incidents.length > 0 && (
            <section>
              <h3 className="label mb-2">Related incidents</h3>
              <ul className="space-y-1.5">
                {query.data.related_incidents.map((incident) => (
                  <li key={incident.incident_id}>
                    <Link
                      to={`/incidents/${incident.incident_id}`}
                      className="flex items-center gap-2 bg-base border border-line rounded-md px-2.5 py-1.5 hover:border-line-strong"
                      onClick={onClose}
                    >
                      <SeverityBadge severity={incident.severity} showLabel={false} />
                      <span className="mono text-accent">{incident.incident_id}</span>
                      <span className="text-xs text-ink-muted truncate flex-1">{incident.title}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {query.data.affected_hosts.length > 0 && (
            <section>
              <h3 className="label mb-2">Hosts that touched this indicator</h3>
              <div className="flex flex-wrap gap-1">
                {query.data.affected_hosts.map((host) => (
                  <Link
                    key={host}
                    to={`/hosts/${host}`}
                    className="chip border-accent/30 text-accent"
                    onClick={onClose}
                  >
                    {host}
                  </Link>
                ))}
              </div>
            </section>
          )}

          <section>
            <h3 className="label mb-2">Matched events ({query.data.matched_events.length})</h3>
            {query.data.matched_events.length === 0 ? (
              <EmptyState title="This indicator has never matched" />
            ) : (
              <div className="table-wrap max-h-64 overflow-y-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Event</th>
                      <th>Type</th>
                      <th>Host</th>
                      <th>Account</th>
                      <th>Source</th>
                      <th>Destination</th>
                    </tr>
                  </thead>
                  <tbody>
                    {query.data.matched_events.map((event) => (
                      <tr key={event.event_id}>
                        <td className="mono whitespace-nowrap" title={absoluteTime(event.timestamp)}>
                          {relativeTime(event.timestamp)}
                        </td>
                        <td className="mono text-ink-faint">{event.event_id}</td>
                        <td>{event.event_type}</td>
                        <td className="mono">{event.host_ref ?? '—'}</td>
                        <td className="mono">{event.user_ref ?? '—'}</td>
                        <td className="mono text-ink-muted">{event.source_ip ?? '—'}</td>
                        <td className="mono text-ink-muted">{event.destination_ip ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}
    </Modal>
  )
}
