/**
 * A deliberately small Markdown renderer.
 *
 * SENTINEL-X reports contain attacker-controlled strings: process command
 * lines, usernames, user-agent headers, file paths. Rendering that through a
 * general-purpose Markdown library and into `dangerouslySetInnerHTML` would
 * turn the report viewer into a stored-XSS sink — the exact class of bug a
 * security tool must not ship.
 *
 * So this renderer never produces HTML. It parses a small, fixed subset of
 * Markdown (the subset the report generator actually emits) into React
 * elements, and every piece of text ends up as a React text node, which React
 * escapes by construction. Inline emphasis and code are handled by splitting on
 * delimiters rather than by building markup. Links are rendered as plain text
 * with the URL beside them, because an anchor built from report content could
 * carry a `javascript:` target and there is no reason a report needs clickable
 * outbound links.
 *
 * Anything outside the supported subset degrades to a paragraph of literal
 * text. That is the right failure mode: a slightly plain heading is a cosmetic
 * problem, an injected script is not.
 */
import { Fragment, type ReactNode } from 'react'

const HEADING = /^(#{1,6})\s+(.*)$/
const BULLET = /^\s*[-*]\s+(.*)$/
const ORDERED = /^\s*(\d+)[.)]\s+(.*)$/
const TABLE_DIVIDER = /^\s*\|?[\s:-]*\|[\s|:-]*$/
const QUOTE = /^>\s?(.*)$/

/** Split inline `code`, **bold** and *italic* into React nodes, never markup. */
function inline(text: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = []
  // One pass, one regex: alternation keeps the delimiters mutually exclusive so
  // a `**` inside a code span cannot open an emphasis run.
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\n]+\*|__[^_]+__)/g
  let last = 0
  let match: RegExpExecArray | null
  let index = 0

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) nodes.push(text.slice(last, match.index))
    const token = match[0]
    const key = `${keyPrefix}-i${index++}`
    if (token.startsWith('`')) {
      nodes.push(
        <code key={key} className="mono bg-raised border border-line rounded px-1 py-0.5 text-ink">
          {token.slice(1, -1)}
        </code>,
      )
    } else if (token.startsWith('**') || token.startsWith('__')) {
      nodes.push(
        <strong key={key} className="font-semibold text-ink">
          {token.slice(2, -2)}
        </strong>,
      )
    } else {
      nodes.push(
        <em key={key} className="italic">
          {token.slice(1, -1)}
        </em>,
      )
    }
    last = match.index + token.length
  }
  if (last < text.length) nodes.push(text.slice(last))
  return nodes
}

function splitRow(line: string): string[] {
  return line
    .replace(/^\s*\|/, '')
    .replace(/\|\s*$/, '')
    .split('|')
    .map((cell) => cell.trim())
}

export function SafeMarkdown({ content, className }: { content: string; className?: string }) {
  const lines = content.replace(/\r\n/g, '\n').split('\n')
  const blocks: ReactNode[] = []
  let index = 0
  let key = 0

  while (index < lines.length) {
    const line = lines[index]

    if (!line.trim()) {
      index += 1
      continue
    }

    // Fenced code: consumed verbatim, rendered as preformatted text.
    if (line.trimStart().startsWith('```')) {
      const body: string[] = []
      index += 1
      while (index < lines.length && !lines[index].trimStart().startsWith('```')) {
        body.push(lines[index])
        index += 1
      }
      index += 1
      blocks.push(
        <pre
          key={`b${key++}`}
          className="mono bg-base border border-line rounded-md p-3 overflow-x-auto text-ink-muted my-3 whitespace-pre"
        >
          {body.join('\n')}
        </pre>,
      )
      continue
    }

    // Horizontal rule.
    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) {
      blocks.push(<hr key={`b${key++}`} className="border-line my-4" />)
      index += 1
      continue
    }

    const heading = HEADING.exec(line)
    if (heading) {
      const level = heading[1].length
      const text = heading[2]
      const sizes = ['text-xl', 'text-lg', 'text-base', 'text-sm', 'text-sm', 'text-xs']
      const Tag = (`h${Math.min(level + 1, 6)}`) as 'h2' | 'h3' | 'h4' | 'h5' | 'h6'
      blocks.push(
        <Tag
          key={`b${key++}`}
          className={`${sizes[level - 1]} font-semibold text-ink mt-5 mb-2 first:mt-0`}
        >
          {inline(text, `h${key}`)}
        </Tag>,
      )
      index += 1
      continue
    }

    // Table: a header row followed by a divider row.
    if (line.includes('|') && index + 1 < lines.length && TABLE_DIVIDER.test(lines[index + 1])) {
      const header = splitRow(line)
      index += 2
      const rows: string[][] = []
      while (index < lines.length && lines[index].includes('|') && lines[index].trim()) {
        rows.push(splitRow(lines[index]))
        index += 1
      }
      blocks.push(
        <div key={`b${key++}`} className="table-wrap my-3">
          <table className="data-table">
            <thead>
              <tr>
                {header.map((cell, i) => (
                  <th key={i}>{inline(cell, `th${i}`)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, r) => (
                <tr key={r}>
                  {row.map((cell, c) => (
                    <td key={c} className="align-top">
                      {inline(cell, `td${r}-${c}`)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      )
      continue
    }

    if (QUOTE.test(line)) {
      const body: string[] = []
      while (index < lines.length && QUOTE.test(lines[index])) {
        body.push(QUOTE.exec(lines[index])![1])
        index += 1
      }
      blocks.push(
        <blockquote
          key={`b${key++}`}
          className="border-l-2 border-accent/50 pl-3 my-3 text-ink-muted italic"
        >
          {body.map((text, i) => (
            <p key={i}>{inline(text, `q${i}`)}</p>
          ))}
        </blockquote>,
      )
      continue
    }

    if (BULLET.test(line)) {
      const items: string[] = []
      while (index < lines.length && BULLET.test(lines[index])) {
        items.push(BULLET.exec(lines[index])![1])
        index += 1
      }
      blocks.push(
        <ul key={`b${key++}`} className="my-2 space-y-1">
          {items.map((text, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-ink-faint shrink-0" aria-hidden="true">
                ·
              </span>
              <span className="flex-1">{inline(text, `li${i}`)}</span>
            </li>
          ))}
        </ul>,
      )
      continue
    }

    if (ORDERED.test(line)) {
      const items: string[] = []
      while (index < lines.length && ORDERED.test(lines[index])) {
        items.push(ORDERED.exec(lines[index])![2])
        index += 1
      }
      blocks.push(
        <ol key={`b${key++}`} className="my-2 space-y-1 list-decimal pl-5">
          {items.map((text, i) => (
            <li key={i}>{inline(text, `ol${i}`)}</li>
          ))}
        </ol>,
      )
      continue
    }

    // Paragraph: consume until a blank line or the start of another block.
    const paragraph: string[] = []
    while (
      index < lines.length &&
      lines[index].trim() &&
      !HEADING.test(lines[index]) &&
      !BULLET.test(lines[index]) &&
      !ORDERED.test(lines[index]) &&
      !QUOTE.test(lines[index]) &&
      !lines[index].trimStart().startsWith('```')
    ) {
      paragraph.push(lines[index])
      index += 1
    }
    blocks.push(
      <p key={`b${key++}`} className="my-2 leading-relaxed">
        {paragraph.map((text, i) => (
          <Fragment key={i}>
            {i > 0 && ' '}
            {inline(text, `p${i}`)}
          </Fragment>
        ))}
      </p>,
    )
  }

  return <div className={className}>{blocks}</div>
}
