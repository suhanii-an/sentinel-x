import { Download, FileText, Sparkles } from 'lucide-react'
import { useState } from 'react'

import { downloadBlob, requestBlob } from '@/api/client'
import { useAiStatus, useGenerateReport, useReports } from '@/api/queries'
import {
  Badge,
  Callout,
  EmptyState,
  Loading,
  Panel,
  Spinner,
} from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import type { IncidentDetail, ReportDetail } from '@/types'
import { absoluteTime, relativeTime } from '@/utils/format'

export function ReportPanel({ incident }: { incident: IncidentDetail }) {
  const reports = useReports({ incident_id: incident.incident_id })
  const generate = useGenerateReport()
  const aiStatus = useAiStatus()
  const { can } = useAuth()

  const [useAi, setUseAi] = useState(false)
  const [current, setCurrent] = useState<ReportDetail | null>(null)
  const [downloading, setDownloading] = useState<string | null>(null)

  const download = async (reportId: string, format: 'markdown' | 'pdf') => {
    setDownloading(`${reportId}-${format}`)
    try {
      const blob = await requestBlob(`/reports/${reportId}/${format}`)
      downloadBlob(blob, `${reportId}.${format === 'pdf' ? 'pdf' : 'md'}`)
    } finally {
      setDownloading(null)
    }
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
      <div className="xl:col-span-2 space-y-5">
        <Panel
          title="Generate an incident report"
          subtitle="Fifteen sections, assembled from stored records"
        >
          <div className="space-y-3">
            <p className="text-sm text-ink-muted">
              Every figure in the report — counts, durations, scores, latencies — is read from the
              database rather than recomputed at render time, so the report and this interface can
              never disagree.
            </p>

            {aiStatus.data?.available && (
              <label className="flex items-start gap-2 text-xs text-ink-muted">
                <input
                  type="checkbox"
                  checked={useAi}
                  onChange={(event) => setUseAi(event.target.checked)}
                  className="accent-cyan-400 mt-0.5"
                />
                <span>
                  Let the AI assistant draft the executive summary. Every other section stays
                  deterministic, and the report records which summary was used. If the AI response
                  fails validation the deterministic summary is used instead.
                </span>
              </label>
            )}

            {can('analyst') && (
              <button
                type="button"
                className="btn-primary"
                disabled={generate.isPending}
                onClick={() =>
                  generate.mutate(
                    { incident_id: incident.incident_id, use_ai_summary: useAi },
                    { onSuccess: (data) => setCurrent(data) },
                  )
                }
              >
                {generate.isPending ? <Spinner /> : <FileText className="h-4 w-4" />}
                Generate report
              </button>
            )}

            {generate.isError && (
              <p className="text-xs text-critical">{(generate.error as Error).message}</p>
            )}
            {current?.note && <Callout tone="info">{current.note}</Callout>}
          </div>
        </Panel>

        {current && (
          <Panel
            title={current.title}
            subtitle={`${current.report_id} · ${current.sections.length} sections`}
            actions={
              <>
                <button
                  type="button"
                  className="btn-secondary text-xs"
                  onClick={() => download(current.report_id, 'markdown')}
                  disabled={downloading === `${current.report_id}-markdown`}
                >
                  <Download className="h-3.5 w-3.5" /> Markdown
                </button>
                <button
                  type="button"
                  className="btn-secondary text-xs"
                  onClick={() => download(current.report_id, 'pdf')}
                  disabled={downloading === `${current.report_id}-pdf`}
                >
                  <Download className="h-3.5 w-3.5" /> PDF
                </button>
              </>
            }
          >
            {current.ai_assisted && (
              <Badge className="border-accent/40 text-accent mb-3">
                <Sparkles className="h-3 w-3" /> AI-drafted executive summary
              </Badge>
            )}
            <div className="max-h-[640px] overflow-y-auto border border-line rounded-md bg-base p-4">
              <pre className="mono text-ink-muted whitespace-pre-wrap break-words leading-relaxed">
                {current.content}
              </pre>
            </div>
          </Panel>
        )}
      </div>

      <div className="space-y-5">
        <Panel title="Report sections">
          <ol className="space-y-1 text-xs text-ink-muted">
            {[
              'Executive Summary',
              'Incident Overview',
              'Severity and Risk Assessment',
              'Attack Timeline',
              'Affected Assets',
              'Accounts Involved',
              'Indicators of Compromise',
              'MITRE ATT&CK Mapping',
              'Evidence',
              'Root Cause Hypothesis',
              'Detection Logic',
              'Response Actions',
              'Recommendations',
              'Analyst Notes',
              'Methodology and Limitations',
            ].map((section, index) => (
              <li key={section} className="flex gap-2">
                <span className="text-ink-faint tabular-nums w-4">{index + 1}</span>
                <span>{section}</span>
              </li>
            ))}
          </ol>
        </Panel>

        <Panel title="Previous reports" dense>
          {reports.isLoading && <Loading rows={2} />}
          {reports.data && reports.data.items.length === 0 && (
            <EmptyState title="No reports generated yet" />
          )}
          {reports.data && reports.data.items.length > 0 && (
            <ul className="divide-y divide-line/60">
              {reports.data.items.map((report) => (
                <li key={report.report_id} className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <span className="mono text-ink-faint">{report.report_id}</span>
                    {report.ai_assisted && (
                      <Sparkles className="h-3 w-3 text-accent" aria-label="AI-assisted summary" />
                    )}
                  </div>
                  <p className="text-2xs text-ink-faint mt-0.5">
                    {report.generated_by} · {relativeTime(report.created_at)}
                  </p>
                  <div className="flex gap-2 mt-1.5">
                    <button
                      type="button"
                      className="btn-ghost text-2xs px-1.5 py-0.5"
                      onClick={() => download(report.report_id, 'markdown')}
                    >
                      .md
                    </button>
                    <button
                      type="button"
                      className="btn-ghost text-2xs px-1.5 py-0.5"
                      onClick={() => download(report.report_id, 'pdf')}
                    >
                      .pdf
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Incident at a glance">
          <dl className="text-xs space-y-1.5">
            <div className="flex justify-between gap-2">
              <dt className="text-ink-faint">Severity</dt>
              <dd className="text-ink uppercase">{incident.severity}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-faint">Risk score</dt>
              <dd className="text-ink tabular-nums">{incident.risk_score.toFixed(1)} / 100</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-faint">First observed</dt>
              <dd className="text-ink">{absoluteTime(incident.first_seen, false)}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-faint">Detections</dt>
              <dd className="text-ink tabular-nums">{incident.alert_count}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-ink-faint">Events</dt>
              <dd className="text-ink tabular-nums">{incident.event_count}</dd>
            </div>
          </dl>
        </Panel>
      </div>
    </div>
  )
}
