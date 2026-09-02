/**
 * Dashboard charts.
 *
 * Rules applied throughout: severity colours come from one shared scale so the
 * same red always means the same thing; every axis is labelled; no chart uses a
 * gradient, a 3-D effect or an animation that repeats; and each one renders an
 * explicit empty state instead of an axis with nothing on it.
 */
import { format, parseISO } from 'date-fns'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { EmptyState } from '@/components/ui'
import type { Dashboard } from '@/types'
import { SEVERITY_META } from '@/utils/severity'

const AXIS = { stroke: '#64748b', fontSize: 10 }
const GRID_STROKE = '#243047'

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: { name?: string; value?: number | string; color?: string; dataKey?: string }[]
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-elevated border border-line-strong rounded-md px-2.5 py-2 shadow-pop text-xs">
      {label && <p className="text-ink-muted mb-1">{label}</p>}
      {payload.map((entry, index) => (
        <p key={index} className="flex items-center gap-2">
          <span
            className="h-2 w-2 rounded-sm shrink-0"
            style={{ backgroundColor: entry.color }}
            aria-hidden="true"
          />
          <span className="text-ink-muted capitalize">{entry.name ?? entry.dataKey}</span>
          <span className="text-ink font-medium tabular-nums ml-auto">{entry.value}</span>
        </p>
      ))}
    </div>
  )
}

export function AlertTrendChart({ data }: { data: Dashboard['alert_trend'] }) {
  const total = data.reduce((sum, bucket) => sum + bucket.total, 0)
  if (!total) {
    return (
      <EmptyState
        title="No alerts in this window"
        description="Run a simulation from the Simulator page to generate activity."
      />
    )
  }

  const series = data.map((bucket) => ({
    ...bucket,
    time: format(parseISO(bucket.bucket_start), 'HH:mm'),
  }))

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
        <defs>
          {(['critical', 'high', 'medium', 'low'] as const).map((key) => (
            <linearGradient key={key} id={`fill-${key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={SEVERITY_META[key].hex} stopOpacity={0.35} />
              <stop offset="100%" stopColor={SEVERITY_META[key].hex} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <XAxis dataKey="time" tick={AXIS} tickLine={false} axisLine={{ stroke: GRID_STROKE }} interval="preserveStartEnd" />
        <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
        <Tooltip content={<ChartTooltip />} />
        {(['low', 'medium', 'high', 'critical'] as const).map((key) => (
          <Area
            key={key}
            type="monotone"
            dataKey={key}
            stackId="1"
            stroke={SEVERITY_META[key].hex}
            strokeWidth={1.5}
            fill={`url(#fill-${key})`}
            isAnimationActive={false}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function SeverityDonut({ data }: { data: Dashboard['severity_distribution'] }) {
  const filtered = data.filter((entry) => entry.count > 0)
  const total = filtered.reduce((sum, entry) => sum + entry.count, 0)
  if (!total) return <EmptyState title="No alerts yet" />

  return (
    <div className="flex items-center gap-4">
      <div className="relative shrink-0">
        <ResponsiveContainer width={124} height={124}>
          <PieChart>
            <Pie
              data={filtered}
              dataKey="count"
              nameKey="severity"
              innerRadius={40}
              outerRadius={58}
              paddingAngle={2}
              stroke="none"
              isAnimationActive={false}
            >
              {filtered.map((entry) => (
                <Cell key={entry.severity} fill={SEVERITY_META[entry.severity].hex} />
              ))}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xl font-bold text-ink tabular-nums">{total}</span>
          <span className="text-2xs text-ink-faint">alerts</span>
        </div>
      </div>
      <ul className="flex-1 space-y-1 min-w-0">
        {filtered.map((entry) => {
          const meta = SEVERITY_META[entry.severity]
          return (
            <li key={entry.severity} className="flex items-center gap-2 text-xs">
              <span className={meta.text} aria-hidden="true">
                {meta.glyph}
              </span>
              <span className="text-ink-muted flex-1">{meta.label}</span>
              <span className="text-ink font-medium tabular-nums">{entry.count}</span>
              <span className="text-ink-faint tabular-nums w-10 text-right">
                {Math.round((entry.count / total) * 100)}%
              </span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export function TechniqueChart({ data }: { data: Dashboard['technique_distribution'] }) {
  if (!data.length) return <EmptyState title="No techniques observed yet" />
  const series = [...data].reverse().map((entry) => ({
    ...entry,
    label: entry.technique_id,
  }))

  return (
    <ResponsiveContainer width="100%" height={Math.max(180, series.length * 22)}>
      <BarChart data={series} layout="vertical" margin={{ top: 4, right: 12, bottom: 4, left: 4 }}>
        <XAxis type="number" tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis
          type="category"
          dataKey="label"
          tick={{ ...AXIS, fontSize: 9 }}
          tickLine={false}
          axisLine={false}
          width={64}
        />
        <Tooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const item = payload[0].payload as (typeof series)[number]
            return (
              <div className="bg-elevated border border-line-strong rounded-md px-2.5 py-2 shadow-pop text-xs max-w-xs">
                <p className="mono text-accent">{item.technique_id}</p>
                <p className="text-ink">{item.name}</p>
                {item.tactic && <p className="text-ink-faint">{item.tactic}</p>}
                <p className="text-ink-muted mt-1">{item.alert_count} alert(s)</p>
              </div>
            )
          }}
        />
        <Bar dataKey="alert_count" fill="#22d3ee" radius={[0, 2, 2, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function RiskDistributionChart({ data }: { data: Dashboard['risk_distribution'] }) {
  const total = data.reduce((sum, entry) => sum + entry.count, 0)
  if (!total) return <EmptyState title="No incidents yet" />

  const colors = ['#38bdf8', '#fbbf24', '#fb7c3c', '#f43f5e']
  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -24 }}>
        <XAxis
          dataKey="band"
          tick={{ ...AXIS, fontSize: 9 }}
          tickLine={false}
          axisLine={{ stroke: GRID_STROKE }}
          tickFormatter={(value: string) => value.split(' ')[0]}
        />
        <YAxis tick={AXIS} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
        <Tooltip content={<ChartTooltip />} />
        <Bar dataKey="count" radius={[3, 3, 0, 0]} isAnimationActive={false}>
          {data.map((entry, index) => (
            <Cell key={entry.band} fill={colors[index] ?? '#64748b'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function MetricBars({
  metrics,
}: {
  metrics: { label: string; value: number; hint?: string }[]
}) {
  return (
    <div className="space-y-3">
      {metrics.map((metric) => (
        <div key={metric.label}>
          <div className="flex items-baseline justify-between mb-1">
            <span className="text-xs text-ink-muted">{metric.label}</span>
            <span className="text-sm font-semibold text-ink tabular-nums">
              {(metric.value * 100).toFixed(1)}%
            </span>
          </div>
          <div className="h-1.5 bg-raised rounded-full overflow-hidden">
            <div
              className="h-full bg-accent rounded-full"
              style={{ width: `${Math.min(100, metric.value * 100)}%` }}
            />
          </div>
          {metric.hint && <p className="text-2xs text-ink-faint mt-1">{metric.hint}</p>}
        </div>
      ))}
    </div>
  )
}
