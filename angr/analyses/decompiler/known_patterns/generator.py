"""PatternGenerator: build a KnownPattern from a decompilation text selection.

This is the inverse of :class:`KnownPatternFinder`. Given a range of the
generated C source (``Decompiler.codegen``) and a target call, it resolves the
selection back to AIL statements/expressions and emits the corresponding DSL
pattern:

- an expression selection (a sub-expression of one statement) → a
  :class:`~.dsl.PatternExpr` tree;
- a straight-line statement selection (statements of one basic block) → a
  :class:`~.dsl.PStmtSeq`;
- a selection spanning several basic blocks → a :class:`~.dsl.PGraphPat`
  (requires the finder's ``ail_graph`` for the block/edge structure).

Text offsets are resolved through the codegen position maps
(``map_pos_to_node`` / ``ailexpr2cnode`` / ``cnode2ailexpr``); the rendered AIL
objects are ``.likes()``-equal to the finder's graph objects, so a generated
pattern re-matches via ``KnownPatternFinder`` on the same ``ail_graph`` (the
round-trip is the acceptance test).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    Reinterpret,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Label, SideEffectStatement, Statement, Store

from .dsl import (
    PAny,
    PAssign,
    PatternExpr,
    PatternStmt,
    PBinOp,
    PBlockPat,
    PCondJump,
    PConst,
    PGraphPat,
    PLoad,
    PPhi,
    PStmtSeq,
    PStore,
    PUnaryOp,
    PVVar,
)
from .finder import _iter_expr_children, _iter_stmt_subexprs, _stmt_defs, _stmt_uses
from .pattern import KnownPattern, PatternParam

if TYPE_CHECKING:
    import networkx

    from .pattern import TypeRef


class PatternGenerationError(Exception):
    """Raised when a selection cannot be turned into a KnownPattern (ambiguous,
    unsupported, or inconsistent with the given arguments)."""


Span = "tuple[int, int]"


def _slug(call_name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in call_name).strip("_").lower()


class PatternGenerator:
    """Generate a :class:`KnownPattern` from a text selection in
    ``codegen.text``.

    :param codegen:   the ``Decompiler.codegen`` (a ``CStructuredCodeGenerator``).
    :param ail_graph: the graph the generated pattern will be matched against
                      (``Decompiler.ail_graph``). Required for multi-block
                      (control-flow-spanning) selections; optional otherwise.
    """

    def __init__(self, codegen, ail_graph: networkx.DiGraph | None = None):
        self.codegen = codegen
        self.ail_graph = ail_graph
        self.text: str = codegen.text
        # id(cnode) -> (min_start, max_end) merged over its text chunks
        self._cnode_span: dict[int, tuple[int, int]] = {}
        for start, elem in codegen.map_pos_to_node.items():
            key = id(elem.obj)
            end = start + elem.length
            if key in self._cnode_span:
                s0, e0 = self._cnode_span[key]
                self._cnode_span[key] = (min(s0, start), max(e0, end))
            else:
                self._cnode_span[key] = (start, end)

    #
    # public helpers
    #

    def vvar_id_at(self, offset: int) -> int | None:
        """The AIL vvar id of the variable rendered at ``offset``, or None."""
        elem = self.codegen.map_pos_to_node.get_element(offset)
        if elem is None:
            return None
        return getattr(elem.obj, "vvar_id", None)

    def offset_of(self, needle: str, start: int = 0) -> int:
        """Convenience: the offset of ``needle`` in the rendered text."""
        return self.text.index(needle, start)

    #
    # span helpers
    #

    def _cnode_of(self, node: Expression) -> object | None:
        return self.codegen.ailexpr2cnode.get((node, True))

    def _node_span(self, node: Expression, memo: dict[int, tuple[int, int] | None]) -> tuple[int, int] | None:
        """The text extent of an AIL expression node = union of its own wrapper
        span and all descendants' spans (bottom-up; handles synthesized nodes
        that have no direct wrapper)."""
        key = id(node)
        if key in memo:
            return memo[key]
        memo[key] = None  # guard against cycles
        spans: list[tuple[int, int]] = []
        cnode = self._cnode_of(node)
        if cnode is not None and id(cnode) in self._cnode_span:
            spans.append(self._cnode_span[id(cnode)])
        for _, child in _iter_expr_children(node):
            cs = self._node_span(child, memo)
            if cs is not None:
                spans.append(cs)
        result = (min(s for s, _ in spans), max(e for _, e in spans)) if spans else None
        memo[key] = result
        return result

    def _stmt_span(self, stmt: Statement, memo: dict[int, tuple[int, int] | None]) -> tuple[int, int] | None:
        spans = []
        for _, root in _iter_stmt_subexprs(stmt):
            cs = self._node_span(root, memo)
            if cs is not None:
                spans.append(cs)
        return (min(s for s, _ in spans), max(e for _, e in spans)) if spans else None

    #
    # generation entry point
    #

    def generate(
        self,
        start_offset: int,
        end_offset: int,
        call_name: str,
        arg_offsets: Sequence[int],
        *,
        name: str | None = None,
        display_name: str | None = None,
        returnty: TypeRef | None = None,
        param_types: Sequence[TypeRef | None] | None = None,
        const_arg_offsets: Sequence[int] = (),
        arches: tuple[str, ...] | None = None,
        platforms: tuple[str, ...] | None = None,
        binary_guard=None,
        enabled_by_default: bool = True,
    ) -> KnownPattern:
        if start_offset >= end_offset:
            raise PatternGenerationError("empty selection")

        # resolve the ordered argument vvars from their offsets
        arg_varids: list[int] = []
        for off in arg_offsets:
            vid = self.vvar_id_at(off)
            if vid is None:
                raise PatternGenerationError(f"offset {off} does not point at a variable")
            arg_varids.append(vid)
        if len(set(arg_varids)) != len(arg_varids):
            raise PatternGenerationError("duplicate argument variables in arg_offsets")

        const_promote = {id(c) for c in self._consts_at(const_arg_offsets)}

        # classify: how many graph basic blocks does the selection touch?
        n_blocks = 0
        if self.ail_graph is not None:
            n_blocks = len(self._blocks_for_ins(self._selected_ins_addrs(start_offset, end_offset)))
        if n_blocks >= 2:
            return self._generate_graph(
                start_offset,
                end_offset,
                call_name,
                arg_varids,
                const_promote,
                name,
                display_name,
                returnty,
                param_types,
                arches,
                platforms,
                binary_guard,
                enabled_by_default,
            )

        rendered_stmts = self._rendered_statements()
        memo: dict[int, tuple[int, int] | None] = {}

        # patternable statements (Assignment/Store) fully inside the selection.
        # Return / side-effect statements are not patternable: a selection that
        # lands on a return's expression is treated as an expression selection.
        selected_stmts = [
            s
            for s in rendered_stmts
            if isinstance(s, (Assignment, Store))
            and (sp := self._stmt_span(s, memo)) is not None
            and start_offset <= sp[0]
            and sp[1] <= end_offset
        ]

        if selected_stmts:
            return self._generate_stmt_seq(
                selected_stmts,
                call_name,
                arg_varids,
                const_promote,
                name,
                display_name,
                returnty,
                param_types,
                arches,
                platforms,
                binary_guard,
                enabled_by_default,
            )

        # otherwise: a sub-expression selection
        return self._generate_expr(
            start_offset,
            end_offset,
            rendered_stmts,
            memo,
            call_name,
            arg_varids,
            const_promote,
            name,
            display_name,
            returnty,
            param_types,
            arches,
            platforms,
            binary_guard,
            enabled_by_default,
        )

    #
    # rendered-object access
    #

    def _rendered_statements(self) -> list[Statement]:
        seen: dict[int, Statement] = {}
        for ail in self.codegen.cnode2ailexpr.values():
            if isinstance(ail, Statement) and id(ail) not in seen:
                seen[id(ail)] = ail
        return list(seen.values())

    def _rendered_expressions(self) -> list[Expression]:
        seen: dict[int, Expression] = {}
        for ail in self.codegen.cnode2ailexpr.values():
            if isinstance(ail, Expression) and id(ail) not in seen:
                seen[id(ail)] = ail
        return list(seen.values())

    def _consts_at(self, offsets: Sequence[int]) -> list[Const]:
        out = []
        for off in offsets:
            elem = self.codegen.map_pos_to_node.get_element(off)
            ail = self.codegen.cnode2ailexpr.get(elem.obj) if elem is not None else None
            if not isinstance(ail, Const):
                raise PatternGenerationError(f"offset {off} does not point at a constant")
            out.append(ail)
        return out

    #
    # AIL -> DSL recursion
    #

    def _gen_expr(self, expr: Expression, capture_of: dict[int, str], const_promote: set[int]) -> PatternExpr:
        if isinstance(expr, (Convert, Reinterpret)):
            # mirror the matcher, which skips conversions by default
            return self._gen_expr(expr.operand, capture_of, const_promote)
        if isinstance(expr, VirtualVariable):
            nm = capture_of.get(expr.varid)
            return PVVar(name=nm)
        if isinstance(expr, Const):
            if id(expr) in const_promote:
                return PConst(name=self._extra_name_of(expr))
            return PConst(value=expr.value)
        if isinstance(expr, Load):
            return PLoad(addr=self._gen_expr(expr.addr, capture_of, const_promote), size=expr.size)
        if isinstance(expr, BinaryOp):
            return PBinOp(
                expr.op,
                (
                    self._gen_expr(expr.operands[0], capture_of, const_promote),
                    self._gen_expr(expr.operands[1], capture_of, const_promote),
                ),
            )
        if isinstance(expr, UnaryOp):
            return PUnaryOp(expr.op, self._gen_expr(expr.operand, capture_of, const_promote))
        if isinstance(expr, Phi):
            return PPhi()
        return PAny()

    def _gen_stmt(self, stmt: Statement, capture_of: dict[int, str], const_promote: set[int]) -> PatternStmt:
        if isinstance(stmt, Assignment):
            return PAssign(
                self._gen_expr(stmt.dst, capture_of, const_promote),
                self._gen_expr(stmt.src, capture_of, const_promote),
            )
        if isinstance(stmt, Store):
            return PStore(
                self._gen_expr(stmt.addr, capture_of, const_promote),
                self._gen_expr(stmt.data, capture_of, const_promote),
                size=stmt.size,
            )
        if isinstance(stmt, ConditionalJump):
            return PCondJump(self._gen_expr(stmt.condition, capture_of, const_promote))
        if isinstance(stmt, SideEffectStatement):
            # not directly representable; fall back to a wildcard sequence element
            raise PatternGenerationError("side-effect statements are not supported in generated patterns")
        raise PatternGenerationError(f"unsupported statement type {type(stmt).__name__}")

    #
    # capture / param plumbing
    #

    _extra_names: dict[int, str]

    def _extra_name_of(self, const: Const) -> str:
        names = getattr(self, "_extra_names", None)
        if names is None:
            names = self._extra_names = {}
        if id(const) not in names:
            names[id(const)] = f"c{len(names)}"
        return names[id(const)]

    @staticmethod
    def _leaf_vvar_ids(expr: Expression) -> list[int]:
        out: list[int] = []
        stack = [expr]
        while stack:
            e = stack.pop()
            if isinstance(e, VirtualVariable):
                out.append(e.varid)
            for _, c in _iter_expr_children(e):
                stack.append(c)
        return out

    def _build_captures(self, input_varids: list[int], arg_varids: list[int]) -> dict[int, str]:
        if set(arg_varids) != set(input_varids):
            raise PatternGenerationError(
                f"argument variables {sorted(arg_varids)} do not match the selection's inputs {sorted(input_varids)}"
            )
        return {vid: f"a{i}" for i, vid in enumerate(arg_varids)}

    def _finish(
        self,
        pattern,
        call_name,
        capture_of,
        arg_varids,
        const_promote,
        name,
        display_name,
        returnty,
        param_types,
        arches,
        platforms,
        binary_guard,
        enabled_by_default,
    ) -> KnownPattern:
        params = tuple(
            PatternParam(
                capture_of[vid],
                type=(param_types[i] if param_types is not None and i < len(param_types) else None),
            )
            for i, vid in enumerate(arg_varids)
        )
        extra_names = getattr(self, "_extra_names", {})
        extra_args = tuple(extra_names[k] for k in extra_names)
        return KnownPattern(
            name=name or _slug(call_name),
            display_name=display_name or call_name,
            call_name=call_name,
            pattern=pattern,
            params=params,
            returnty=returnty,
            extra_args=extra_args,
            arches=arches,
            platforms=platforms,
            binary_guard=binary_guard,
            enabled_by_default=enabled_by_default,
        )

    #
    # expression selection
    #

    def _generate_expr(
        self,
        start,
        end,
        rendered_stmts,
        memo,
        call_name,
        arg_varids,
        const_promote,
        name,
        display_name,
        returnty,
        param_types,
        arches,
        platforms,
        binary_guard,
        enabled_by_default,
    ) -> KnownPattern:
        # the root is the widest rendered expression whose text extent is fully
        # inside the selection (the outermost by containment)
        root = None
        best_width = -1
        for ex in self._rendered_expressions():
            sp = self._node_span(ex, memo)
            if sp is not None and start <= sp[0] and sp[1] <= end:
                width = sp[1] - sp[0]
                if width > best_width:
                    best_width = width
                    root = ex

        # a bare-atom root usually means the real expression was rendered as a
        # struct-field / array access whose structure is not recoverable from the
        # rendered tree; fall back to the enclosing graph statement's value
        if root is None or isinstance(root, (VirtualVariable, Const)):
            g_root = self._enclosing_graph_expr(start, end)
            if g_root is not None:
                root = g_root
        if root is None:
            raise PatternGenerationError("selection does not enclose a whole sub-expression")

        input_varids = self._leaf_vvar_ids(root)
        capture_of = self._build_captures(input_varids, arg_varids)
        pattern = self._gen_expr(root, capture_of, const_promote)
        return self._finish(
            pattern,
            call_name,
            capture_of,
            arg_varids,
            const_promote,
            name,
            display_name,
            returnty,
            param_types,
            arches,
            platforms,
            binary_guard,
            enabled_by_default,
        )

    def _covered_atoms(self, start: int, end: int) -> tuple[set[int], set[int]]:
        """The vvar ids and constant values whose wrappers lie in the selection."""
        varids: set[int] = set()
        consts: set[int] = set()
        for s, elem in self.codegen.map_pos_to_node.items():
            if not (start <= s and s + elem.length <= end):
                continue
            vid = getattr(elem.obj, "vvar_id", None)
            if vid is not None:
                varids.add(vid)
            ail = self.codegen.cnode2ailexpr.get(elem.obj)
            if isinstance(ail, Const) and isinstance(ail.value, int):
                consts.add(ail.value)
        return varids, consts

    def _enclosing_graph_expr(self, start: int, end: int) -> Expression | None:
        """Recover the value expression the selection computes from the finder's
        graph, matched by the atoms the selection covers. Used when the rendered
        tree has lost the structure (struct-field / array-index rendering)."""
        if self.ail_graph is None:
            return None
        varids, _ = self._covered_atoms(start, end)
        if not varids:
            return None
        candidates: list[Expression] = []
        for block in self.ail_graph.nodes:
            for stmt in block.statements:
                for ex in self._primary_exprs(stmt):
                    leaves = set(self._leaf_vvar_ids(ex))
                    if varids <= leaves and not isinstance(ex, (VirtualVariable, Const)):
                        candidates.append(ex)
        if not candidates:
            return None
        # tightest match: fewest extra leaves, then smallest tree
        candidates.sort(key=lambda e: (len(set(self._leaf_vvar_ids(e)) - varids), len(self._leaf_vvar_ids(e))))
        return candidates[0]

    @staticmethod
    def _primary_exprs(stmt: Statement):
        from angr.ailment.statement import Return  # pylint:disable=import-outside-toplevel

        if isinstance(stmt, Return):
            yield from stmt.ret_exprs
        elif isinstance(stmt, Assignment):
            yield stmt.src
        elif isinstance(stmt, Store):
            yield stmt.data
        elif isinstance(stmt, SideEffectStatement):
            yield stmt.expr

    #
    # statement-sequence selection (single block)
    #

    def _generate_stmt_seq(
        self,
        selected_stmts,
        call_name,
        arg_varids,
        const_promote,
        name,
        display_name,
        returnty,
        param_types,
        arches,
        platforms,
        binary_guard,
        enabled_by_default,
    ) -> KnownPattern:
        # order by text position
        memo: dict[int, tuple[int, int] | None] = {}
        selected_stmts = sorted(selected_stmts, key=lambda s: (self._stmt_span(s, memo) or (0, 0))[0])
        capture_of = self._stmt_captures(selected_stmts, arg_varids)
        stmt_pats = tuple(self._gen_stmt(s, capture_of, const_promote) for s in selected_stmts)
        pattern = stmt_pats[0] if len(stmt_pats) == 1 else PStmtSeq(stmt_pats)
        return self._finish(
            pattern,
            call_name,
            capture_of,
            arg_varids,
            const_promote,
            name,
            display_name,
            returnty,
            param_types,
            arches,
            platforms,
            binary_guard,
            enabled_by_default,
        )

    def _stmt_captures(self, stmts, arg_varids) -> dict[int, str]:
        defs: set[int] = set()
        uses: set[int] = set()
        for s in stmts:
            defs |= _stmt_defs(s)
            uses |= _stmt_uses(s)
        inputs = uses - defs
        capture_of = self._build_captures(list(inputs), arg_varids)
        # interior (defined-and-used) vvars get internal names so repeated uses unify
        for k, vid in enumerate(sorted(defs)):
            capture_of.setdefault(vid, f"_t{k}")
        return capture_of

    #
    # multi-block selection
    #

    def _generate_graph(
        self,
        start,
        end,
        call_name,
        arg_varids,
        const_promote,
        name,
        display_name,
        returnty,
        param_types,
        arches,
        platforms,
        binary_guard,
        enabled_by_default,
    ) -> KnownPattern:
        if self.ail_graph is None:
            raise PatternGenerationError("multi-block selection requires ail_graph")

        ins_addrs = self._selected_ins_addrs(start, end)
        blocks = self._blocks_for_ins(ins_addrs)
        if len(blocks) < 2:
            raise PatternGenerationError("multi-block generation expected >= 2 blocks")

        selected = set(blocks)
        # per-block non-label statements
        block_stmts = {b: [s for s in b.statements if not isinstance(s, Label)] for b in blocks}

        # inputs across all selected statements
        defs: set[int] = set()
        uses: set[int] = set()
        for b in blocks:
            for s in block_stmts[b]:
                defs |= _stmt_defs(s)
                uses |= _stmt_uses(s)
        inputs = uses - defs
        capture_of = self._build_captures(list(inputs), arg_varids)
        for k, vid in enumerate(sorted(defs)):
            capture_of.setdefault(vid, f"_t{k}")

        # entry = the unique selected block with no selected predecessor
        entries = [b for b in blocks if not any(p in selected for p in self.ail_graph.predecessors(b))]
        if len(entries) != 1:
            raise PatternGenerationError(f"selection has {len(entries)} entry blocks; need exactly one")
        entry = entries[0]

        label_of = {b: f"b{i}" for i, b in enumerate(sorted(blocks, key=lambda x: (x.addr, x.idx or -1)))}
        pblocks: dict[str, PBlockPat] = {}
        edges: list[tuple[str, str]] = []
        ext = 0
        for b in blocks:
            lbl = label_of[b]
            seq = PStmtSeq(tuple(self._gen_stmt(s, capture_of, const_promote) for s in block_stmts[b]))
            pblocks[lbl] = PBlockPat(lbl, seq)
            for succ in self.ail_graph.successors(b):
                if succ in selected:
                    edges.append((lbl, label_of[succ]))
                else:
                    edges.append((lbl, f"OUT{ext}"))
                    ext += 1

        pattern = PGraphPat(blocks=pblocks, edges=edges, entry=label_of[entry])
        return self._finish(
            pattern,
            call_name,
            capture_of,
            arg_varids,
            const_promote,
            name,
            display_name,
            returnty,
            param_types,
            arches,
            platforms,
            binary_guard,
            enabled_by_default,
        )

    def _selected_ins_addrs(self, start: int, end: int) -> set[int]:
        addrs: set[int] = set()
        for s, elem in self.codegen.map_pos_to_node.items():
            if s < end and start < s + elem.length:
                ins = (getattr(elem.obj, "tags", None) or {}).get("ins_addr")
                if ins is not None:
                    addrs.add(ins)
        for s, elem in self.codegen.map_pos_to_addr.items():
            if s < end and start < s + elem.length:
                ins = (getattr(elem.obj, "tags", None) or {}).get("ins_addr")
                if ins is not None:
                    addrs.add(ins)
        return addrs

    def _blocks_for_ins(self, ins_addrs: set[int]) -> list:
        assert self.ail_graph is not None
        blocks = []
        for b in self.ail_graph.nodes:
            lo = b.addr
            hi = b.addr + (b.original_size or 0)
            if any(lo <= a < hi for a in ins_addrs):
                blocks.append(b)
        return blocks
