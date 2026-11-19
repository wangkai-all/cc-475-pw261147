"""A deliberately small SQL dialect used by the query-history analyzer.

Supported grammar (case-insensitive)::

    SELECT <item>[, ...] FROM <table>
      [WHERE <expr>]
      [GROUP BY <column>[, ...]]
      [ORDER BY <column> [ASC|DESC]]
      [LIMIT <n>]

    <item>      := <expr> [AS <alias>]
    <expr>      := <or>
    <or>        := <and> (OR <and>)*
    <and>       := <not> (AND <not>)*
    <not>       := NOT <not> | <predicate>
    <predicate> := <operand> [ (=|<>|!=|<|<=|>|>=) <operand>
                             | BETWEEN <operand> AND <operand>
                             | [NOT] IN ( <literal> [, ...] )
                             | [NOT] LIKE <literal> ]
    <operand>   := <literal> | <column> | <function>(<expr>[, ...]) | '(' <expr> ')'

Aggregates: count, sum, avg, min, max (optional DISTINCT).
Functions: substr, lower, upper, year, month.

The parser is intentionally strict: anything outside this subset raises
``QueryError`` instead of silently mis-parsing.  The analyzer needs to reason
about predicates, so a trustworthy AST matters more than SQL coverage.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


class QueryError(ValueError):
    """Raised for unsupported or invalid SQL."""


AGGREGATES = {"count", "sum", "avg", "min", "max"}
FUNCTIONS = {"substr", "lower", "upper", "year", "month"}
KEYWORDS = {
    "select", "from", "where", "group", "by", "order", "limit", "and", "or",
    "not", "as", "between", "in", "asc", "desc", "distinct", "true", "false",
    "null", "like",
}

# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Column:
    name: str


@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class Star:
    pass


@dataclass(frozen=True)
class Func:
    name: str
    args: tuple["Node", ...]
    distinct: bool = False

    @property
    def is_aggregate(self) -> bool:
        return self.name in AGGREGATES


@dataclass(frozen=True)
class BinaryOp:
    op: str  # and / or / = / <> / < / <= / > / >= / like
    left: "Node"
    right: "Node"


@dataclass(frozen=True)
class NotOp:
    expr: "Node"


@dataclass(frozen=True)
class Between:
    expr: "Node"
    low: "Node"
    high: "Node"


@dataclass(frozen=True)
class InList:
    expr: "Node"
    values: tuple["Node", ...]
    negated: bool = False


@dataclass(frozen=True)
class SelectItem:
    expr: "Node"
    alias: str | None = None


Node = Column | Literal | Star | Func | BinaryOp | NotOp | Between | InList


@dataclass(frozen=True)
class Select:
    table: str
    items: tuple[SelectItem, ...]
    where: Node | None = None
    group_by: tuple[str, ...] = ()
    order_by: tuple[str, ...] = ()
    limit: int | None = None

    # -- derived helpers ---------------------------------------------------

    def columns_used(self) -> set[str]:
        cols: set[str] = set()
        for item in self.items:
            _collect_columns(item.expr, cols)
        if self.where is not None:
            _collect_columns(self.where, cols)
        cols.update(self.group_by)
        cols.update(self.order_by)
        return cols

    def aggregate_calls(self) -> list[Func]:
        found: list[Func] = []

        def walk(n: Node) -> None:
            if isinstance(n, Func):
                if n.is_aggregate:
                    found.append(n)
                for a in n.args:
                    walk(a)
            elif isinstance(n, BinaryOp):
                walk(n.left)
                walk(n.right)
            elif isinstance(n, NotOp):
                walk(n.expr)
            elif isinstance(n, (Between,)):
                walk(n.expr)
                walk(n.low)
                walk(n.high)
            elif isinstance(n, InList):
                walk(n.expr)

        for item in self.items:
            walk(item.expr)
        return found

    def has_aggregation(self) -> bool:
        return bool(self.group_by) or bool(self.aggregate_calls())

    def equalities(self) -> list[tuple[str, Node]]:
        """Top-level AND-ed column equality / IN predicates (for pruning)."""
        out: list[tuple[str, Node]] = []
        conjuncts = _split_and(self.where) if self.where is not None else []
        for c in conjuncts:
            if isinstance(c, BinaryOp) and c.op == "=":
                if isinstance(c.left, Column) and not isinstance(c.right, Column):
                    out.append((c.left.name, c.right))
                elif isinstance(c.right, Column) and not isinstance(c.left, Column):
                    out.append((c.right.name, c.left))
            elif isinstance(c, InList) and not c.negated and isinstance(c.expr, Column):
                out.append((c.expr.name, c))
        return out

    def ranges(self) -> list[tuple[str, str, Node]]:
        """Top-level AND-ed range predicates on bare columns."""
        out: list[tuple[str, str, Node]] = []
        conjuncts = _split_and(self.where) if self.where is not None else []
        for c in conjuncts:
            if not isinstance(c, BinaryOp):
                continue
            if c.op not in {"<", "<=", ">", ">="}:
                continue
            if isinstance(c.left, Column) and not isinstance(c.right, Column):
                out.append((c.left.name, c.op, c.right))
            elif isinstance(c.right, Column) and not isinstance(c.left, Column):
                flipped = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[c.op]
                out.append((c.right.name, flipped, c.left))
            elif isinstance(c.left, Func) and c.op in {"<", "<=", ">", ">="}:
                # e.g. year(event_time) >= 2024 -> still prune on function result
                if c.left.name in {"year", "month"} and c.left.args and isinstance(
                    c.left.args[0], Column
                ):
                    out.append(("__func__:" + c.left.name + ":" + _column_name(c.left), c.op, c.right))
        return out

    def fingerprint(self) -> str:
        norm = normalize(self)
        return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]


def _column_name(node: Func) -> str:
    if node.args and isinstance(node.args[0], Column):
        return node.args[0].name
    return "?"


def _collect_columns(n: Node | None, out: set[str]) -> None:
    if n is None:
        return
    if isinstance(n, Column):
        out.add(n.name)
    elif isinstance(n, Func):
        for a in n.args:
            _collect_columns(a, out)
    elif isinstance(n, BinaryOp):
        _collect_columns(n.left, out)
        _collect_columns(n.right, out)
    elif isinstance(n, NotOp):
        _collect_columns(n.expr, out)
    elif isinstance(n, Between):
        _collect_columns(n.expr, out)
        _collect_columns(n.low, out)
        _collect_columns(n.high, out)
    elif isinstance(n, InList):
        _collect_columns(n.expr, out)
        for v in n.values:
            _collect_columns(v, out)


def _split_and(n: Node) -> list[Node]:
    if isinstance(n, BinaryOp) and n.op == "and":
        return _split_and(n.left) + _split_and(n.right)
    return [n]


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<str>'(?:[^']|'')*')
  | (?P<num>-?\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op><=|>=|<>|!=|=|<|>)
  | (?P<punct>[(),.*])
    """,
    re.VERBOSE,
)


@dataclass
class Token:
    kind: str
    value: str
    pos: int


def tokenize(sql: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    text = sql.rstrip().rstrip(";")
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise QueryError(f"unexpected character {text[pos]!r} at offset {pos}")
        kind = m.lastgroup
        assert kind is not None
        if kind != "ws":
            tokens.append(Token(kind, m.group(), pos))
        pos = m.end()
    return tokens


# ---------------------------------------------------------------------------
# Recursive-descent parser
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, sql: str):
        self.tokens = tokenize(sql)
        self.i = 0

    # -- token access ------------------------------------------------------

    def peek(self) -> Token | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def peek_kw(self, *words: str) -> bool:
        t = self.peek()
        return t is not None and t.kind == "ident" and t.value.lower() in words

    def pop(self) -> Token:
        t = self.peek()
        if t is None:
            raise QueryError("unexpected end of query")
        self.i += 1
        return t

    def expect_kw(self, word: str) -> None:
        t = self.pop()
        if t.kind != "ident" or t.value.lower() != word:
            raise QueryError(f"expected {word.upper()} near {t.value!r} (offset {t.pos})")

    def expect_punct(self, ch: str) -> None:
        t = self.pop()
        if t.kind != "punct" or t.value != ch:
            raise QueryError(f"expected {ch!r} near {t.value!r} (offset {t.pos})")

    # -- grammar -----------------------------------------------------------

    def parse(self) -> Select:
        self.expect_kw("select")
        items = [self.parse_item()]
        while self.peek() is not None and not self.peek_kw("from"):
            if self.peek().kind == "punct" and self.peek().value == ",":
                self.pop()
                items.append(self.parse_item())
            else:
                break
        self.expect_kw("from")
        table_tok = self.pop()
        if table_tok.kind != "ident":
            raise QueryError(f"expected table name near {table_tok.value!r}")
        table = table_tok.value.lower()

        where = None
        if self.peek_kw("where"):
            self.pop()
            where = self.parse_expr()

        group_by: tuple[str, ...] = ()
        if self.peek_kw("group"):
            self.pop()
            self.expect_kw("by")
            group_by = tuple(self.parse_ident_list())

        order_by: tuple[str, ...] = ()
        if self.peek_kw("order"):
            self.pop()
            self.expect_kw("by")
            cols = []
            while True:
                tok = self.pop()
                if tok.kind != "ident":
                    raise QueryError(f"expected ORDER BY column near {tok.value!r}")
                if tok.value.lower() in KEYWORDS:
                    raise QueryError(f"unsupported ORDER BY term {tok.value!r}")
                cols.append(tok.value.lower())
                if self.peek_kw("asc", "desc"):
                    self.pop()
                if self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ",":
                    self.pop()
                    continue
                break
            order_by = tuple(cols)

        limit = None
        if self.peek_kw("limit"):
            self.pop()
            tok = self.pop()
            if tok.kind != "num":
                raise QueryError("LIMIT requires an integer literal")
            limit = int(tok.value)

        if self.peek() is not None:
            t = self.peek()
            raise QueryError(f"unsupported trailing token {t.value!r} (offset {t.pos})")

        return Select(
            table=table,
            items=tuple(items),
            where=where,
            group_by=group_by,
            order_by=order_by,
            limit=limit,
        )

    def parse_item(self) -> SelectItem:
        expr = self.parse_expr()
        alias = None
        if self.peek_kw("as"):
            self.pop()
            tok = self.pop()
            if tok.kind != "ident":
                raise QueryError("expected alias after AS")
            alias = tok.value.lower()
        elif (
            self.peek() is not None
            and self.peek().kind == "ident"
            and self.peek().value.lower() not in KEYWORDS
        ):
            alias = self.pop().value.lower()
        return SelectItem(expr=expr, alias=alias)

    def parse_ident_list(self) -> list[str]:
        cols = []
        while True:
            tok = self.pop()
            if tok.kind != "ident":
                raise QueryError(f"expected column name near {tok.value!r}")
            if tok.value.lower() in KEYWORDS:
                raise QueryError(f"unsupported column {tok.value!r}")
            cols.append(tok.value.lower())
            if self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ",":
                self.pop()
                continue
            return cols

    def parse_expr(self) -> Node:
        return self.parse_or()

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek_kw("or"):
            self.pop()
            node = BinaryOp("or", node, self.parse_and())
        return node

    def parse_and(self) -> Node:
        node = self.parse_not()
        while self.peek_kw("and"):
            self.pop()
            node = BinaryOp("and", node, self.parse_not())
        return node

    def parse_not(self) -> Node:
        if self.peek_kw("not"):
            self.pop()
            return NotOp(self.parse_not())
        return self.parse_predicate()

    def parse_predicate(self) -> Node:
        left = self.parse_operand()
        tok = self.peek()
        if tok is None:
            return left
        if tok.kind == "op":
            self.pop()
            right = self.parse_operand()
            return BinaryOp(tok.value, left, right)
        if tok.kind == "ident" and tok.value.lower() == "between":
            self.pop()
            low = self.parse_operand()
            self.expect_kw("and")
            high = self.parse_operand()
            return Between(left, low, high)
        if tok.kind == "ident" and tok.value.lower() == "like":
            self.pop()
            return BinaryOp("like", left, self.parse_operand())
        if tok.kind == "ident" and tok.value.lower() == "in":
            self.pop()
            self.expect_punct("(")
            values = [self.parse_operand()]
            while self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ",":
                self.pop()
                values.append(self.parse_operand())
            self.expect_punct(")")
            return InList(left, tuple(values))
        if tok.kind == "ident" and tok.value.lower() == "not":
            # NOT IN / NOT LIKE
            save = self.i
            self.pop()
            if self.peek_kw("in"):
                self.pop()
                self.expect_punct("(")
                values = [self.parse_operand()]
                while self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ",":
                    self.pop()
                    values.append(self.parse_operand())
                self.expect_punct(")")
                return InList(left, tuple(values), negated=True)
            if self.peek_kw("like"):
                self.pop()
                return NotOp(BinaryOp("like", left, self.parse_operand()))
            self.i = save
        return left

    def parse_operand(self) -> Node:
        tok = self.pop()
        if tok.kind == "punct" and tok.value == "(":
            inner = self.parse_expr()
            self.expect_punct(")")
            return inner
        if tok.kind == "punct" and tok.value == "*":
            return Star()
        if tok.kind == "str":
            return Literal(tok.value[1:-1].replace("''", "'"))
        if tok.kind == "num":
            value: Any = float(tok.value) if "." in tok.value else int(tok.value)
            return Literal(value)
        if tok.kind == "ident":
            low = tok.value.lower()
            if low in {"true", "false"}:
                return Literal(low == "true")
            if low == "null":
                return Literal(None)
            if self.peek() is not None and self.peek().kind == "punct" and self.peek().value == "(":
                self.pop()
                distinct = False
                if self.peek_kw("distinct"):
                    self.pop()
                    distinct = True
                args: list[Node] = []
                if not (self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ")"):
                    args.append(self.parse_operand())
                    while self.peek() is not None and self.peek().kind == "punct" and self.peek().value == ",":
                        self.pop()
                        args.append(self.parse_operand())
                self.expect_punct(")")
                if low not in AGGREGATES and low not in FUNCTIONS:
                    raise QueryError(f"unsupported function {low}()")
                return Func(low, tuple(args), distinct)
            if low in KEYWORDS:
                raise QueryError(f"unexpected keyword {tok.value!r} in expression")
            return Column(low)
        raise QueryError(f"unexpected token {tok.value!r} (offset {tok.pos})")


def parse(sql: str) -> Select:
    if not sql or not sql.strip():
        raise QueryError("empty query")
    return _Parser(sql).parse()


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def _fmt_literal(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, str):
        return "'" + v.replace("'", "''") + "'"
    return repr(v)


def format_expr(n: Node) -> str:
    if isinstance(n, Column):
        return n.name
    if isinstance(n, Literal):
        return _fmt_literal(n.value)
    if isinstance(n, Star):
        return "*"
    if isinstance(n, Func):
        inner = ",".join(format_expr(a) for a in n.args)
        return f"{n.name}({'distinct ' if n.distinct else ''}{inner})"
    if isinstance(n, BinaryOp):
        return f"{format_expr(n.left)} {n.op} {format_expr(n.right)}"
    if isinstance(n, NotOp):
        return f"not ({format_expr(n.expr)})"
    if isinstance(n, Between):
        return f"{format_expr(n.expr)} between {format_expr(n.low)} and {format_expr(n.high)}"
    if isinstance(n, InList):
        vals = ",".join(format_expr(v) for v in n.values)
        return f"{format_expr(n.expr)} {'not in' if n.negated else 'in'} ({vals})"
    raise TypeError(n)


def normalize(sel: Select) -> str:
    """Stable identity for a query: literals replaced, aliases dropped.

    Two executions of the same logical query with different filters share a
    fingerprint, which is what makes "repeated aggregation" detectable.
    """
    parts = []
    for item in sel.items:
        parts.append(format_expr(_strip_literals(item.expr)))
    out = ["select", ",".join(parts), "from", sel.table]
    if sel.where is not None:
        out += ["where", format_expr(_strip_literals(sel.where))]
    if sel.group_by:
        out += ["group by", ",".join(sel.group_by)]
    if sel.order_by:
        out += ["order by", ",".join(sel.order_by)]
    if sel.limit is not None:
        out += ["limit", str(sel.limit)]
    return " ".join(out)


def _strip_literals(n: Node) -> Node:
    if isinstance(n, Literal):
        return Literal("?")
    if isinstance(n, Func):
        return Func(n.name, tuple(_strip_literals(a) for a in n.args), n.distinct)
    if isinstance(n, BinaryOp):
        return BinaryOp(n.op, _strip_literals(n.left), _strip_literals(n.right))
    if isinstance(n, NotOp):
        return NotOp(_strip_literals(n.expr))
    if isinstance(n, Between):
        return Between(_strip_literals(n.expr), _strip_literals(n.low), _strip_literals(n.high))
    if isinstance(n, InList):
        return InList(_strip_literals(n.expr), tuple(_strip_literals(v) for v in n.values), n.negated)
    return n


def literal_values(n: Node) -> list[Any]:
    """All literal values appearing in an expression (used for zone maps)."""
    vals: list[Any] = []
    if isinstance(n, Literal):
        if n.value is not None:
            vals.append(n.value)
    elif isinstance(n, Func):
        for a in n.args:
            vals.extend(literal_values(a))
    elif isinstance(n, BinaryOp):
        vals.extend(literal_values(n.left))
        vals.extend(literal_values(n.right))
    elif isinstance(n, NotOp):
        vals.extend(literal_values(n.expr))
    elif isinstance(n, Between):
        vals.extend(literal_values(n.expr))
        vals.extend(literal_values(n.low))
        vals.extend(literal_values(n.high))
    elif isinstance(n, InList):
        vals.extend(literal_values(n.expr))
        for v in n.values:
            vals.extend(literal_values(v))
    return vals
