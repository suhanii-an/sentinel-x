import { format, formatDistanceToNowStrict, parseISO } from 'date-fns'

export function parseTime(value: string | null | undefined): Date | null {
  if (!value) return null
  try {
    const parsed = parseISO(value)
    return Number.isNaN(parsed.getTime()) ? null : parsed
  } catch {
    return null
  }
}

/** Absolute UTC timestamp. Analysts correlate across systems, so UTC always. */
export function absoluteTime(value: string | null | undefined, withSeconds = true): string {
  const date = parseTime(value)
  if (!date) return '—'
  return format(date, withSeconds ? 'yyyy-MM-dd HH:mm:ss' : 'yyyy-MM-dd HH:mm')
}

export function timeOnly(value: string | null | undefined): string {
  const date = parseTime(value)
  return date ? format(date, 'HH:mm:ss') : '—'
}

export function relativeTime(value: string | null | undefined): string {
  const date = parseTime(value)
  if (!date) return '—'
  try {
    return `${formatDistanceToNowStrict(date)} ago`
  } catch {
    return '—'
  }
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—'
  if (seconds < 1) return '<1s'
  if (seconds < 60) return `${Math.round(seconds)}s`
  const minutes = Math.floor(seconds / 60)
  const remaining = Math.round(seconds % 60)
  if (minutes < 60) return remaining ? `${minutes}m ${remaining}s` : `${minutes}m`
  const hours = Math.floor(minutes / 60)
  const leftover = minutes % 60
  if (hours < 24) return leftover ? `${hours}h ${leftover}m` : `${hours}h`
  const days = Math.floor(hours / 24)
  return `${days}d ${hours % 24}h`
}

export function durationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return duration(ms / 1000)
}

export function percent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined) return '—'
  return `${(value * 100).toFixed(digits)}%`
}

export function compactNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  if (Math.abs(value) < 1000) return String(value)
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value)
}

export function bytes(value: number | null | undefined): string {
  if (!value) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = value
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(size < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`
}

export function titleCase(value: string | null | undefined): string {
  if (!value) return '—'
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Truncate in the middle, keeping both ends — better for paths and commands. */
export function middleTruncate(value: string, max = 64): string {
  if (value.length <= max) return value
  const half = Math.floor((max - 1) / 2)
  return `${value.slice(0, half)}…${value.slice(-half)}`
}
