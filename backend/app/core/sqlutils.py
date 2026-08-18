"""LIKE pattern construction.

There is one rule here and a dialect trap behind it.

**The rule.** A value supplied by a caller is *data*. If it reaches a `LIKE`
pattern unescaped, then `%` means "match everything" and `_` means "match any
character" — so `GET /incidents?host=%` returns every incident regardless of
host, and `host=WEB-0_` does single-character wildcarding. That is not SQL
injection (the value still travels as a bound parameter) but it is a filter
bypass, and on a security console a filter that silently ignores itself is a
filter an analyst will trust while it shows them the wrong set.

**The trap.** Escaping alone is not enough. LIKE's escape character is not
standardised: PostgreSQL defaults to backslash, SQLite has *no* default escape
at all. So `.ilike("we\\%")` matches on Postgres and silently matches nothing on
SQLite — the worst failure mode, because an empty result looks like a clean
answer. Every pattern built here must therefore be passed with an explicit
`escape=LIKE_ESCAPE`, and the helpers below exist so no call site has to
remember both halves.

    from app.core.sqlutils import LIKE_ESCAPE, contains, json_member

    Host.hostname.ilike(contains(q), escape=LIKE_ESCAPE)
"""

from __future__ import annotations

from typing import Any

#: Passed as ``escape=`` on every ``like``/``ilike`` in this codebase.
LIKE_ESCAPE = "\\"


def escape_like(value: Any) -> str:
    """Neutralise LIKE metacharacters in a caller-supplied value.

    Backslash first, or the escapes introduced below would themselves be
    escaped.
    """
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def contains(value: Any) -> str:
    """`%value%` — a substring match."""
    return f"%{escape_like(value)}%"


def starts_with(value: Any) -> str:
    """`value%` — a prefix match, which an index can serve."""
    return f"{escape_like(value)}%"


def json_member(value: Any) -> str:
    """Match one exact element of a JSON array stored as text.

    The surrounding quotes are what make it exact: `%"T1110"%` matches the
    element `T1110` but not `T1110.001`, which a bare `%T1110%` would. The
    value is escaped, so a caller cannot smuggle a wildcard between the quotes
    and turn an exact membership test into a prefix scan.
    """
    return f'%"{escape_like(value)}"%'
