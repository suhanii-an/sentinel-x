import clsx from 'clsx'
import { Search, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { useSearch } from '@/api/queries'
import { Spinner } from '@/components/ui'
import type { SearchHit } from '@/types'
import { severityMeta } from '@/utils/severity'

const CATEGORY_LABEL: Record<string, string> = {
  incidents: 'Incidents',
  alerts: 'Alerts',
  events: 'Events',
  hosts: 'Hosts',
  users: 'Identities',
  indicators: 'Indicators',
  techniques: 'ATT&CK techniques',
}

/** Debounce so a fast typist does not issue a request per keystroke. */
function useDebounced<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

export function GlobalSearch() {
  const [term, setTerm] = useState('')
  const [open, setOpen] = useState(false)
  const [highlight, setHighlight] = useState(0)
  const debounced = useDebounced(term, 220)
  const inputRef = useRef<HTMLInputElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  const query = useSearch(debounced)

  const flat = useMemo(() => {
    if (!query.data) return [] as { category: string; hit: SearchHit }[]
    const rows: { category: string; hit: SearchHit }[] = []
    for (const [category, hits] of Object.entries(query.data.results)) {
      for (const hit of hits) rows.push({ category, hit })
    }
    return rows
  }, [query.data])

  useEffect(() => setHighlight(0), [debounced])

  // "/" focuses search from anywhere, the way every analyst tool works.
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const typing =
        target &&
        (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)
      if (event.key === '/' && !typing) {
        event.preventDefault()
        inputRef.current?.focus()
      }
      if (event.key === 'Escape') {
        setOpen(false)
        inputRef.current?.blur()
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  useEffect(() => {
    const handler = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const go = (hit: SearchHit) => {
    setOpen(false)
    setTerm('')
    navigate(hit.href)
  }

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (!flat.length) return
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setHighlight((h) => (h + 1) % flat.length)
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setHighlight((h) => (h - 1 + flat.length) % flat.length)
    } else if (event.key === 'Enter') {
      event.preventDefault()
      go(flat[highlight].hit)
    }
  }

  return (
    <div ref={containerRef} className="relative flex-1 max-w-xl">
      <div className="relative">
        <Search
          className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-ink-faint pointer-events-none"
          aria-hidden="true"
        />
        <input
          ref={inputRef}
          type="search"
          value={term}
          onChange={(event) => {
            setTerm(event.target.value)
            setOpen(true)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
          placeholder="Search incidents, alerts, hosts, accounts, addresses, techniques…"
          aria-label="Global search"
          aria-expanded={open}
          role="combobox"
          aria-controls="global-search-results"
          className="input pl-8 pr-16"
        />
        <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
          {query.isFetching && <Spinner className="text-ink-faint" />}
          {term ? (
            <button
              type="button"
              className="btn-ghost p-0.5"
              onClick={() => {
                setTerm('')
                inputRef.current?.focus()
              }}
              aria-label="Clear search"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          ) : (
            <kbd className="hidden sm:inline text-2xs text-ink-faint border border-line rounded px-1">
              /
            </kbd>
          )}
        </div>
      </div>

      {open && debounced.trim().length >= 2 && (
        <div
          id="global-search-results"
          role="listbox"
          className="absolute top-full left-0 right-0 mt-1 bg-surface border border-line rounded-lg shadow-pop max-h-[70vh] overflow-y-auto z-50 animate-slide-up"
        >
          {query.isLoading && <p className="px-3 py-3 text-xs text-ink-muted">Searching…</p>}
          {query.isError && (
            <p className="px-3 py-3 text-xs text-critical">Search failed. Try again.</p>
          )}
          {query.data && flat.length === 0 && (
            <p className="px-3 py-3 text-xs text-ink-muted">
              {query.data.message ?? `No results for “${debounced}”.`}
            </p>
          )}
          {query.data && flat.length > 0 && (
            <>
              <p className="px-3 py-1.5 text-2xs text-ink-faint border-b border-line">
                {query.data.total} result{query.data.total === 1 ? '' : 's'} · interpreted as{' '}
                <span className="text-ink-muted">{query.data.kind.replace(/_/g, ' ')}</span>
              </p>
              {Object.entries(query.data.results).map(([category, hits]) => (
                <div key={category}>
                  <p className="label px-3 pt-2 pb-1">{CATEGORY_LABEL[category] ?? category}</p>
                  <ul>
                    {hits.map((hit) => {
                      const index = flat.findIndex(
                        (row) => row.category === category && row.hit.id === hit.id,
                      )
                      return (
                        <li key={`${category}-${hit.id}`}>
                          <button
                            type="button"
                            role="option"
                            aria-selected={index === highlight}
                            onMouseEnter={() => setHighlight(index)}
                            onClick={() => go(hit)}
                            className={clsx(
                              'w-full text-left px-3 py-1.5 flex items-center gap-2 transition-colors',
                              index === highlight ? 'bg-raised' : 'hover:bg-elevated',
                            )}
                          >
                            <SearchHitRow hit={hit} />
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}

function SearchHitRow({ hit }: { hit: SearchHit }) {
  const severity = typeof hit.severity === 'string' ? severityMeta(hit.severity) : null
  const primary =
    (hit.title as string) ??
    (hit.hostname as string) ??
    (hit.indicator as string) ??
    (hit.name as string) ??
    (hit.display_name as string) ??
    (hit.summary as string) ??
    hit.id

  return (
    <>
      {severity && (
        <span className={clsx('shrink-0', severity.text)} aria-hidden="true">
          {severity.glyph}
        </span>
      )}
      <span className="mono text-ink-faint shrink-0">{hit.id}</span>
      <span className="text-xs text-ink truncate flex-1">{String(primary)}</span>
      {typeof hit.alert_count === 'number' && (
        <span className="text-2xs text-ink-faint shrink-0">{hit.alert_count} alerts</span>
      )}
    </>
  )
}
