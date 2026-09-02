import type { Severity } from '@/types'

/**
 * Severity presentation.
 *
 * Every entry pairs a colour with a glyph and a label. Colour is never the only
 * channel: a red chip and an amber chip are indistinguishable to a red-green
 * colour-blind analyst, and severity is precisely the signal they cannot afford
 * to miss.
 */
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_META: Record<
  Severity,
  { label: string; glyph: string; text: string; bg: string; border: string; hex: string; rank: number }
> = {
  critical: {
    label: 'Critical',
    glyph: '▲',
    text: 'text-critical',
    bg: 'bg-critical/12',
    border: 'border-critical/40',
    hex: '#f43f5e',
    rank: 4,
  },
  high: {
    label: 'High',
    glyph: '▲',
    text: 'text-high',
    bg: 'bg-high/12',
    border: 'border-high/40',
    hex: '#fb7c3c',
    rank: 3,
  },
  medium: {
    label: 'Medium',
    glyph: '■',
    text: 'text-medium',
    bg: 'bg-medium/12',
    border: 'border-medium/40',
    hex: '#fbbf24',
    rank: 2,
  },
  low: {
    label: 'Low',
    glyph: '●',
    text: 'text-low',
    bg: 'bg-low/12',
    border: 'border-low/40',
    hex: '#38bdf8',
    rank: 1,
  },
  info: {
    label: 'Info',
    glyph: '·',
    text: 'text-info',
    bg: 'bg-info/12',
    border: 'border-info/40',
    hex: '#64748b',
    rank: 0,
  },
}

export function severityMeta(value: string | null | undefined) {
  const key = (value ?? 'info').toLowerCase() as Severity
  return SEVERITY_META[key] ?? SEVERITY_META.info
}

export function riskBand(score: number): Severity {
  if (score >= 76) return 'critical'
  if (score >= 51) return 'high'
  if (score >= 26) return 'medium'
  return 'low'
}

/** Status presentation for alerts and incidents. */
export const STATUS_META: Record<string, { label: string; text: string; bg: string; border: string }> = {
  new: { label: 'New', text: 'text-accent', bg: 'bg-accent/10', border: 'border-accent/40' },
  open: { label: 'Open', text: 'text-accent', bg: 'bg-accent/10', border: 'border-accent/40' },
  investigating: {
    label: 'Investigating',
    text: 'text-medium',
    bg: 'bg-medium/10',
    border: 'border-medium/40',
  },
  escalated: { label: 'Escalated', text: 'text-high', bg: 'bg-high/10', border: 'border-high/40' },
  contained: {
    label: 'Contained',
    text: 'text-healthy',
    bg: 'bg-healthy/10',
    border: 'border-healthy/40',
  },
  resolved: {
    label: 'Resolved',
    text: 'text-healthy',
    bg: 'bg-healthy/10',
    border: 'border-healthy/40',
  },
  false_positive: {
    label: 'False positive',
    text: 'text-ink-faint',
    bg: 'bg-ink-faint/10',
    border: 'border-line-strong',
  },
}

export function statusMeta(value: string | null | undefined) {
  const key = (value ?? '').toLowerCase()
  return (
    STATUS_META[key] ?? {
      label: value ?? 'Unknown',
      text: 'text-ink-muted',
      bg: 'bg-raised',
      border: 'border-line',
    }
  )
}

/** Event-type glyphs for the timeline. */
export const EVENT_TYPE_LABEL: Record<string, string> = {
  authentication: 'Auth',
  process: 'Process',
  network: 'Network',
  file: 'File',
  cloud_audit: 'Cloud',
  account: 'Account',
  privilege: 'Privilege',
  scheduled_task: 'Task',
  service: 'Service',
  discovery: 'Discovery',
}
