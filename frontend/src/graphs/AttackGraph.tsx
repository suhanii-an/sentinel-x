import clsx from 'clsx'
import { useCallback, useEffect, useMemo, useState } from 'react'
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  type Edge,
  type Node,
  type NodeProps,
} from 'reactflow'
import 'reactflow/dist/style.css'

import { Badge, Callout, EmptyState } from '@/components/ui'
import type { AttackGraph as AttackGraphData, GraphEdge, GraphNode } from '@/types'
import { severityMeta } from '@/utils/severity'

/**
 * Attack graph.
 *
 * Laid out in kill-chain columns rather than by a force simulation. A force
 * layout looks impressive and tells an analyst nothing: it puts the same
 * incident in a different shape every render, and position carries no meaning.
 * Here the x-axis is the attack's progression — where it came from, what it
 * landed on, what ran, what fired — so position is information.
 */

const KIND_META: Record<
  string,
  { label: string; column: number; color: string; glyph: string }
> = {
  ip: { label: 'Address', column: 0, color: '#38bdf8', glyph: '◇' },
  user: { label: 'Account', column: 1, color: '#a78bfa', glyph: '◆' },
  cloud_account: { label: 'Cloud account', column: 1, color: '#818cf8', glyph: '☁' },
  host: { label: 'Host', column: 2, color: '#22d3ee', glyph: '▢' },
  process: { label: 'Process', column: 3, color: '#fbbf24', glyph: '▷' },
  file: { label: 'File', column: 3, color: '#fb923c', glyph: '▤' },
  alert: { label: 'Detection', column: 4, color: '#f43f5e', glyph: '⚑' },
  technique: { label: 'ATT&CK technique', column: 5, color: '#34d399', glyph: '⬡' },
  ioc: { label: 'Indicator', column: 5, color: '#f472b6', glyph: '◉' },
}

const COLUMN_WIDTH = 230
const ROW_HEIGHT = 74

function EntityNode({ data, selected }: NodeProps<GraphNode & { onSelect?: () => void }>) {
  const meta = KIND_META[data.kind] ?? { label: data.kind, column: 0, color: '#64748b', glyph: '•' }
  const severity = severityMeta(data.severity)

  return (
    <div
      className={clsx(
        'rounded-md border bg-surface px-2.5 py-1.5 min-w-[150px] max-w-[200px] shadow-panel transition-all',
        selected ? 'border-accent ring-1 ring-accent/50' : 'border-line hover:border-line-strong',
      )}
      style={{ borderLeftColor: meta.color, borderLeftWidth: 3 }}
    >
      <Handle type="target" position={Position.Left} />
      <div className="flex items-center gap-1.5">
        <span style={{ color: meta.color }} aria-hidden="true" className="text-xs">
          {meta.glyph}
        </span>
        <span className="label truncate">{meta.label}</span>
        {data.kind === 'alert' && (
          <span className={clsx('ml-auto text-2xs', severity.text)} aria-hidden="true">
            {severity.glyph}
          </span>
        )}
      </div>
      <p className="mono text-ink truncate mt-0.5" title={data.label}>
        {data.label}
      </p>
      <Handle type="source" position={Position.Right} />
    </div>
  )
}

const nodeTypes = { entity: EntityNode }

function buildLayout(graph: AttackGraphData): { nodes: Node[]; edges: Edge[] } {
  const byColumn = new Map<number, GraphNode[]>()
  for (const node of graph.nodes) {
    const column = KIND_META[node.kind]?.column ?? 0
    if (!byColumn.has(column)) byColumn.set(column, [])
    byColumn.get(column)!.push(node)
  }

  // Within a column, order by how much evidence a node carries so the busiest
  // entities sit together near the top rather than scattering.
  const positions = new Map<string, { x: number; y: number }>()
  for (const [column, nodes] of byColumn) {
    const ordered = [...nodes].sort((a, b) => b.event_count - a.event_count)
    const offset = -((ordered.length - 1) * ROW_HEIGHT) / 2
    ordered.forEach((node, index) => {
      positions.set(node.id, { x: column * COLUMN_WIDTH, y: offset + index * ROW_HEIGHT })
    })
  }

  const nodes: Node[] = graph.nodes.map((node) => ({
    id: node.id,
    type: 'entity',
    position: positions.get(node.id) ?? { x: 0, y: 0 },
    data: node,
    draggable: true,
  }))

  const edges: Edge[] = graph.edges.map((edge: GraphEdge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.relation,
    labelShowBg: true,
    animated: false,
    markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12, color: '#334158' },
    style: { strokeWidth: Math.min(3, 1 + Math.log1p(edge.count)) },
    data: edge,
  }))

  return { nodes, edges }
}

export function AttackGraph({ graph }: { graph: AttackGraphData }) {
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const [hiddenKinds, setHiddenKinds] = useState<Set<string>>(new Set())

  const visible = useMemo(() => {
    if (hiddenKinds.size === 0) return graph
    const nodes = graph.nodes.filter((node) => !hiddenKinds.has(node.kind))
    const ids = new Set(nodes.map((node) => node.id))
    return {
      ...graph,
      nodes,
      edges: graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)),
    }
  }, [graph, hiddenKinds])

  const layout = useMemo(() => buildLayout(visible), [visible])

  const kinds = useMemo(() => {
    const counts = new Map<string, number>()
    for (const node of graph.nodes) counts.set(node.kind, (counts.get(node.kind) ?? 0) + 1)
    return [...counts.entries()].sort(
      (a, b) => (KIND_META[a[0]]?.column ?? 9) - (KIND_META[b[0]]?.column ?? 9),
    )
  }, [graph.nodes])

  const toggleKind = useCallback((kind: string) => {
    setHiddenKinds((current) => {
      const next = new Set(current)
      if (next.has(kind)) next.delete(kind)
      else next.add(kind)
      return next
    })
  }, [])

  useEffect(() => setSelected(null), [graph.incident_id])

  if (!graph.nodes.length) {
    return (
      <EmptyState
        title="No graph to draw"
        description="This incident has no evidence with entity relationships yet."
      />
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="label mr-1">Show</span>
        {kinds.map(([kind, count]) => {
          const meta = KIND_META[kind]
          const hidden = hiddenKinds.has(kind)
          return (
            <button
              key={kind}
              type="button"
              onClick={() => toggleKind(kind)}
              aria-pressed={!hidden}
              className={clsx(
                'chip transition-opacity',
                hidden ? 'border-line text-ink-faint opacity-50' : 'border-line-strong text-ink-muted',
              )}
              style={hidden ? undefined : { borderLeftColor: meta?.color, borderLeftWidth: 3 }}
            >
              {meta?.label ?? kind}
              <span className="tabular-nums opacity-70">{count}</span>
            </button>
          )
        })}
      </div>

      {graph.truncated && (
        <Callout tone="warning">
          This graph shows {graph.nodes.length} of {graph.total_nodes} nodes and{' '}
          {graph.edges.length} of {graph.total_edges} edges. Beyond this size the picture stops
          communicating — use the Evidence tab for the complete record.
        </Callout>
      )}

      <div className="h-[560px] border border-line rounded-lg overflow-hidden bg-base">
        <ReactFlow
          nodes={layout.nodes}
          edges={layout.edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.2}
          maxZoom={1.6}
          proOptions={{ hideAttribution: true }}
          onNodeClick={(_event, node) => setSelected(node.data as GraphNode)}
          onPaneClick={() => setSelected(null)}
          nodesConnectable={false}
          edgesFocusable={false}
        >
          <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#1c2536" />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>

      {selected ? (
        <div className="panel p-3">
          <div className="flex items-center gap-2 mb-2">
            <span
              style={{ color: KIND_META[selected.kind]?.color }}
              aria-hidden="true"
            >
              {KIND_META[selected.kind]?.glyph ?? '•'}
            </span>
            <span className="label">{KIND_META[selected.kind]?.label ?? selected.kind}</span>
            <span className="mono text-ink">{selected.label}</span>
            <Badge className="ml-auto">{selected.event_count} event references</Badge>
          </div>
          {Object.keys(selected.attributes).length > 0 && (
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
              {Object.entries(selected.attributes).map(([key, value]) => (
                <div key={key} className="flex gap-2 min-w-0">
                  <dt className="text-ink-faint shrink-0">{key.replace(/_/g, ' ')}</dt>
                  <dd className="text-ink-muted truncate" title={String(value)}>
                    {String(value)}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      ) : (
        <p className="text-2xs text-ink-faint">
          Columns follow the attack's progression: source address → account → host → what ran →
          detections → ATT&CK techniques and indicators. Click a node for its attributes.
        </p>
      )}
    </div>
  )
}
