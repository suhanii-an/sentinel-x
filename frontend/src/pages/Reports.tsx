/**
 * Report library.
 *
 * Reports are the artefact an analyst hands to somebody who was not in the
 * console — a manager, an auditor, the next shift. Two properties matter:
 * every figure is read back from the stored report rather than recomputed
 * (so the report and the console can never disagree), and a report that used
 * the AI to draft its executive summary says so on its face.
 */
import clsx from 'clsx'
import { Download, FileText, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import { downloadBlob, requestBlob } from '@/api/client'
import {
  useAiStatus,
  useGenerateReport,
  useIncidents,
  useReport,
  useReports,
} from '@/api/queries'
import { SafeMarkdown } from '@/components/SafeMarkdown'
import {
  Badge,
  Callout,
  EmptyState,
  ErrorState,
  Loading,
  Pagination,
  Panel,
  QueryBoundary,
  SeverityBadge,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { PageBody, PageHeader } from '@/layouts/AppLayout'
import { absoluteTime, compactNumber, relativeTime } from '@/utils/format'

const PAGE_SIZE = 25

export function Reports() {
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const [downloading, setDownloading] = useState<string | null>(null)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  const reports = useReports({ limit: PAGE_SIZE, offset })
  const detail = useReport(selected ?? undefined)
  const { can } = useAuth()

  const download = async (reportId: string, format: 'markdown' | 'pdf') => {
    setDownloading(`${reportId}-${format}`)
    setDownloadError(null)
    try {
      const blob = await requestBlob(`/reports/${reportId}/${format}`)
      downloadBlob(blob, `${reportId}.${format === 'pdf' ? 'pdf' : 'md'}`)
    } catch (error) {
      setDownloadError(error instanceof Error ? error.message : 'The download failed.')
    } finally {
      setDownloading(null)
    }
  }

  return (
    <>
      <PageHeader
        title="Reports"
        description="Incident reports assembled from stored records. Fifteen fixed sections, every number read from the database, every export recorded in the audit log."
      />

      <PageBody className="space-y-5">
        {can('analyst') && <GenerateCard onGenerated={(id) => setSelected(id)} />}

        {downloadError && (
          <Callout tone="critical" title="Export failed">
            {downloadError}
          </Callout>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
          <Panel title="Report library" dense className="xl:col-span-1">
            <QueryBoundary
              query={reports}
              context="Could not load reports"
              empty={{
                title: 'No reports yet',
                description: 'Generate one from an incident above, or from the Report tab of any incident.',
              }}
            >
              {(page) => (
                <>
                  <ul className="divide-y divide-line/60 max-h-[520px] overflow-y-auto">
                    {page.items.map((report) => (
                      <li key={report.report_id}>
                        <button
                          type="button"
                          onClick={() => setSelected(report.report_id)}
                          className={clsx(
                            'w-full text-left px-4 py-3 hover:bg-raised/60 transition-colors',
                            selected === report.report_id && 'bg-raised',
                          )}
                        >
                          <div className="flex items-center gap-2">
                            <span className="mono text-2xs text-ink-faint">{report.report_id}</span>
                            {report.ai_assisted && (
                              <Sparkles
                                className="h-3 w-3 text-accent shrink-0"
                                aria-label="AI-drafted executive summary"
                              />
                            )}
                          </div>
                          <p className="text-xs text-ink mt-0.5 line-clamp-2">{report.title}</p>
                          <p className="text-2xs text-ink-faint mt-1">
                            {report.generated_by} · {relativeTime(report.created_at)} ·{' '}
                            {report.sections.length} sections
                            {report.length_chars
                              ? ` · ${compactNumber(report.length_chars)} chars`
                              : ''}
                          </p>
                        </button>
                      </li>
                    ))}
                  </ul>
                  <Pagination
                    total={page.total}
                    limit={PAGE_SIZE}
                    offset={offset}
                    onChange={setOffset}
                  />
                </>
              )}
            </QueryBoundary>
          </Panel>

          <div className="xl:col-span-2">
            {!selected && (
              <Panel>
                <EmptyState
                  title="Select a report"
                  description="Choose a report from the library to read it here, or generate a new one."
                  icon={<FileText className="h-7 w-7" />}
                />
              </Panel>
            )}

            {selected && detail.isLoading && (
              <Panel>
                <Loading rows={6} label="Loading report" />
              </Panel>
            )}

            {selected && detail.isError && (
              <Panel>
                <ErrorState
                  error={detail.error}
                  onRetry={detail.refetch}
                  context="Could not load this report"
                />
              </Panel>
            )}

            {detail.data && (
              <Panel
                title={detail.data.title}
                subtitle={
                  <>
                    <span className="mono">{detail.data.report_id}</span> · generated by{' '}
                    {detail.data.generated_by} on {absoluteTime(detail.data.created_at, false)}
                  </>
                }
                actions={
                  <>
                    <button
                      type="button"
                      className="btn-secondary text-xs"
                      onClick={() => download(detail.data.report_id, 'markdown')}
                      disabled={downloading === `${detail.data.report_id}-markdown`}
                    >
                      {downloading === `${detail.data.report_id}-markdown` ? (
                        <Spinner />
                      ) : (
                        <Download className="h-3.5 w-3.5" />
                      )}
                      Markdown
                    </button>
                    <button
                      type="button"
                      className="btn-secondary text-xs"
                      onClick={() => download(detail.data.report_id, 'pdf')}
                      disabled={downloading === `${detail.data.report_id}-pdf`}
                    >
                      {downloading === `${detail.data.report_id}-pdf` ? (
                        <Spinner />
                      ) : (
                        <Download className="h-3.5 w-3.5" />
                      )}
                      PDF
                    </button>
                  </>
                }
              >
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  {detail.data.incident_id && (
                    <Link
                      to={`/incidents/${detail.data.incident_id}`}
                      className="chip border-accent/40 text-accent"
                    >
                      {detail.data.incident_id}
                    </Link>
                  )}
                  {detail.data.ai_assisted ? (
                    <Badge className="border-accent/40 text-accent">
                      <Sparkles className="h-3 w-3" /> AI-drafted executive summary
                    </Badge>
                  ) : (
                    <Badge className="border-healthy/40 text-healthy">Fully deterministic</Badge>
                  )}
                  <Badge className="border-line text-ink-faint">
                    {detail.data.sections.length} sections
                  </Badge>
                </div>

                {detail.data.note && (
                  <Callout tone="info" title="Note">
                    {detail.data.note}
                  </Callout>
                )}

                <div className="mt-3 max-h-[660px] overflow-y-auto border border-line rounded-md bg-base px-4 py-3">
                  <SafeMarkdown
                    content={detail.data.content}
                    className="text-sm text-ink-muted"
                  />
                </div>

                <p className="text-2xs text-ink-faint mt-3 leading-relaxed">
                  Report content is rendered without HTML. Attacker-controlled strings — command
                  lines, usernames, user agents — reach the page as text nodes, so a crafted log
                  entry cannot execute script in the report viewer.
                </p>
              </Panel>
            )}
          </div>
        </div>
      </PageBody>
    </>
  )
}

function GenerateCard({ onGenerated }: { onGenerated: (reportId: string) => void }) {
  const incidents = useIncidents({ limit: 50 })
  const aiStatus = useAiStatus()
  const generate = useGenerateReport()

  const [incidentId, setIncidentId] = useState('')
  const [useAi, setUseAi] = useState(false)

  const selected = incidents.data?.items.find((item) => item.incident_id === incidentId)

  return (
    <Panel
      title="Generate a report"
      subtitle="Pick an incident; the generator reads its stored alerts, evidence, techniques and response actions"
    >
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[260px] flex-1">
          <label htmlFor="report-incident" className="label block mb-1">
            Incident
          </label>
          <select
            id="report-incident"
            value={incidentId}
            onChange={(event) => setIncidentId(event.target.value)}
            className="input w-full"
            disabled={incidents.isLoading}
          >
            <option value="">
              {incidents.isLoading ? 'Loading incidents…' : 'Select an incident'}
            </option>
            {incidents.data?.items.map((incident) => (
              <option key={incident.incident_id} value={incident.incident_id}>
                {incident.incident_id} — {incident.title}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          className="btn-primary"
          disabled={!incidentId || generate.isPending}
          onClick={() =>
            generate.mutate(
              { incident_id: incidentId, use_ai_summary: useAi },
              { onSuccess: (data) => onGenerated(data.report_id) },
            )
          }
        >
          {generate.isPending ? <Spinner /> : <FileText className="h-4 w-4" />}
          Generate report
        </button>
      </div>

      {selected && (
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <SeverityBadge severity={selected.severity} />
          <span className="text-xs text-ink-muted">
            {selected.alert_count} alerts · {selected.event_count} events ·{' '}
            {selected.technique_ids.length} techniques
          </span>
          <span className="text-2xs text-ink-faint">
            first seen {absoluteTime(selected.first_seen, false)}
          </span>
        </div>
      )}

      {aiStatus.data?.available ? (
        <label className="flex items-start gap-2 text-xs text-ink-muted mt-3">
          <input
            type="checkbox"
            checked={useAi}
            onChange={(event) => setUseAi(event.target.checked)}
            className="accent-cyan-400 mt-0.5"
          />
          <span>
            Let the AI assistant draft the executive summary. The other fourteen sections stay
            deterministic. If the drafted summary fails grounding validation the deterministic
            summary is used instead, and the report records which one it shipped with.
          </span>
        </label>
      ) : (
        <p className="text-2xs text-ink-faint mt-3">
          {aiStatus.data?.message ??
            'No AI provider is configured. Reports are generated deterministically, which is the only mode the platform requires.'}
        </p>
      )}

      {generate.isError && (
        <Callout tone="critical" title="Could not generate the report">
          {(generate.error as Error).message}
        </Callout>
      )}
    </Panel>
  )
}
