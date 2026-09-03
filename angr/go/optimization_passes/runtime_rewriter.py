"""
Turn calls into the Go runtime for maps, channels, goroutines, defer and panic/recover back into the Go statements
they were compiled from. See :mod:`angr.go.codegen_builtins` for the ``go_render`` tag protocol the results use.
"""

from __future__ import annotations

import contextlib
import logging
from collections import Counter, defaultdict

import networkx

from angr.ailment import AILBlockRewriter, AILBlockViewer, Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Expression,
    Load,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Statement, Store
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeChan, GoSimTypeFunction, GoSimTypeMap, GoSimTypeTuple
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_at, go_type_name_at
from angr.sim_type import SimType
from angr.utils.go_runtime import normalize_go_func_name

l = logging.getLogger(__name__)

_MAKEMAP = frozenset({"runtime.makemap", "runtime.makemap64", "runtime.makemap_small"})
_MAKECHAN = frozenset({"runtime.makechan", "runtime.makechan64"})
_DEFERPROC = frozenset({"runtime.deferproc", "runtime.deferprocat"})
_EXACT = {
    "runtime.mapclear": "mapclear",
    "runtime.chansend1": "chansend",
    "runtime.chanrecv1": "chanrecv1",
    "runtime.chanrecv2": "chanrecv2",
    "runtime.closechan": "closechan",
    "runtime.newproc": "newproc",
    "runtime.deferprocStack": "deferprocstack",
    "runtime.deferreturn": "deferreturn",
    "runtime.gopanic": "gopanic",
    "runtime.gorecover": "gorecover",
}
_PREFIXES = (
    ("runtime.mapaccess1", "mapaccess1"),
    ("runtime.mapaccess2", "mapaccess2"),
    ("runtime.mapassign", "mapassign"),
    ("runtime.mapdelete", "mapdelete"),
)
_INT_KINDS = frozenset(
    {"int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "bool"}
)


def classify_runtime_call(name: str | None) -> str | None:
    if name is None:
        return None
    name = normalize_go_func_name(name)
    if name in _MAKEMAP:
        return "makemap"
    if name in _MAKECHAN:
        return "makechan"
    if name in _DEFERPROC:
        return "deferproc"
    kind = _EXACT.get(name)
    if kind is not None:
        return kind
    for prefix, kind in _PREFIXES:
        if name.startswith(prefix):
            return kind
    return None


def _addr_and_offset(expr) -> tuple[Expression, int]:
    if isinstance(expr, BinaryOp) and expr.op == "Add":
        a, b = expr.operands
        if isinstance(b, Const):
            return a, b.value_int
        if isinstance(a, Const):
            return b, a.value_int
    return expr, 0


def _ref_vvar(expr) -> VirtualVariable | None:
    if isinstance(expr, UnaryOp) and expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
        return expr.operand
    return None


def _call_def(stmt) -> tuple[VirtualVariable, Call] | None:
    """(vvar, call) when the statement defines a vvar with the result of a call."""
    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Call):
        return stmt.dst, stmt.src
    if (
        isinstance(stmt, SideEffectStatement)
        and isinstance(stmt.ret_expr, VirtualVariable)
        and isinstance(stmt.expr, Call)
    ):
        return stmt.ret_expr, stmt.expr
    return None


class _UseIndex(AILBlockViewer):
    """Per-vvar definition sites and use shapes (loads through it, stores through it, references to it)."""

    def __init__(self):
        super().__init__()
        self.defs: dict[int, tuple[Block, int]] = {}
        self.total: Counter = Counter()
        self.loads: dict[int, Counter] = defaultdict(Counter)
        self.stores: Counter = Counter()
        self.refs: Counter = Counter()
        self.sites: dict[int, list[tuple[Block, int]]] = defaultdict(list)

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if isinstance(stmt.dst, VirtualVariable):
            self.defs[stmt.dst.varid] = (block, stmt_idx)
        else:
            self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_SideEffectStatement(self, stmt_idx, stmt, block):
        if isinstance(stmt.ret_expr, VirtualVariable):
            self.defs[stmt.ret_expr.varid] = (block, stmt_idx)
        self._handle_expr(0, stmt.expr, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx, stmt, block):
        if isinstance(stmt.addr, VirtualVariable):
            self.stores[stmt.addr.varid] += 1
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.addr, VirtualVariable):
            self.loads[expr.addr.varid][expr.size] += 1
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            self.refs[expr.operand.varid] += 1
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.total[expr.varid] += 1
        self.sites[expr.varid].append((block, stmt_idx))


class _CallFinder(AILBlockViewer):
    """All Call expressions inside a statement, outermost first."""

    def __init__(self):
        super().__init__()
        self.calls: list[Call] = []

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.calls.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class GoRuntimeRewriter(OptimizationPass):
    """
    Rewrite Go runtime calls into map, channel, goroutine, defer and panic/recover statements.

    Map slot pointers returned by ``mapaccess1``/``mapassign`` are folded into the loads and the store that go through
    them (``m[k]``, ``m[k] = v``); results the runtime writes through a stack pointer (``chanrecv``) become the value
    of the rewritten call; open-coded defers (a deferBits byte plus an inline call at every exit) become ``defer``.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rewrite Go runtime calls into Go statements"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._index: _UseIndex | None = None
        self._idoms: dict | None = None
        self._changed = False
        # map slot pointer vvar -> (map, key)
        self._slots: dict[int, tuple[Expression, Expression]] = {}
        # pointer vvar whose loads become the vvar itself
        self._deref: set[int] = set()
        # vvar -> replacement expression
        self._replace: dict[int, Expression] = {}
        self._map_vvars: dict[int, str | None] = {}
        self._chan_vvars: dict[int, str | None] = {}
        self._dropped_defs: set[int] = set()
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    #
    # Driver
    #

    def _analyze(self, cache=None):
        if self._graph is None or not self._graph.nodes:
            return
        self._reindex()
        self._collect_reference_types()
        self._collect_slots()
        for block in list(self._graph.nodes):
            self._rewrite_statements(block)
        self._rewrite_open_coded_defers()
        rewriter = _ExprRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        if self._changed or rewriter.changed:
            self.out_graph = self._graph

    #
    # Helpers
    #

    def _new_idx(self) -> int:
        return self.manager.next_atom()

    def _reindex(self) -> None:
        self._index = _UseIndex()
        for block in self._graph.nodes:
            self._index.walk(block)

    def _new_varid(self) -> int:
        varid = self.vvar_id_start
        self.vvar_id_start += 1
        return varid

    def _kind(self, call: Call) -> str | None:
        return classify_runtime_call(call_target_name(self.project, call))

    def _const_bits(self, value: int, bits: int | None = None) -> Const:
        return Const(self._new_idx(), value, bits or self.project.arch.bits)

    def _type_name(self, expr) -> str | None:
        if isinstance(expr, Const):
            return go_type_name_at(self.project, expr.value_int)
        return None

    def _go_type(self, name: str | None) -> SimType | None:
        if name is None:
            return None
        try:
            return self.kb.go_signatures.type(name).with_arch(self.project.arch)
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def _type_size(self, ty: SimType | None, default: int) -> int:
        if ty is None or not ty.size:
            return default
        return ty.size // self.project.arch.byte_width

    def _is_readonly(self, addr: int) -> bool:
        section = self.project.loader.find_section_containing(addr)
        return section is not None and section.is_readable and not section.is_writable

    def _dominates(self, a: Block, b: Block) -> bool:
        if self._idoms is None:
            entry = next((n for n in self._graph.nodes if (n.addr, n.idx) == self.entry_node_addr), None)
            if entry is None:
                entry = next(iter(self._graph.nodes))
            self._idoms = networkx.immediate_dominators(self._graph, entry)
        node = b
        while True:
            if node is a:
                return True
            parent = self._idoms.get(node)
            if parent is None or parent is node:
                return False
            node = parent

    def _uses_dominated_by(self, varid: int, block: Block, stmt_idx: int) -> bool:
        """Every use of the vvar is reached only after the statement at (block, stmt_idx)."""
        assert self._index is not None
        for use_block, use_idx in self._index.sites.get(varid, []):
            if use_block is block:
                if use_idx <= stmt_idx:
                    return False
            elif not self._dominates(block, use_block):
                return False
        return True

    def _set_prototype(self, call: Call, args: list[SimType | None], returnty: SimType | None) -> None:
        if any(a is None for a in args):
            return
        proto = GoSimTypeFunction(list(args), returnty).with_arch(self.project.arch)
        variable_map_of(self.manager).set_prototype(call, proto)

    def _builtin(self, name: str, args: list, bits: int | None, tags: dict, **extra) -> Call:
        tags = {k: v for k, v in tags.items() if k not in ("go_render", "go_type_args")}
        tags.update(extra)
        return Call(self._new_idx(), name, args=list(args), bits=bits, **tags)

    def _stmt(self, call: Call, idx: int | None = None, ret_expr=None) -> SideEffectStatement:
        # the code generator reads the render tags off the statement, not the call; variable recovery types the
        # result of a SideEffectStatement from the call-site prototype, which an Assignment does not
        return SideEffectStatement(
            idx if idx is not None else self._new_idx(), call, ret_expr=ret_expr, **dict(call.tags)
        )

    #
    # Type bookkeeping for map and channel values
    #

    def _collect_reference_types(self) -> None:
        """Vvars known to hold a map or a channel, with the Go type spelling when a descriptor names it."""
        proto = self._func.prototype
        if isinstance(proto, GoSimTypeFunction) and self._arg_vvars:
            for (vvar, _), ty in zip(self._arg_vvars.values(), proto.args):
                if not isinstance(vvar, VirtualVariable):
                    continue
                if isinstance(ty, GoSimTypeMap):
                    self._map_vvars[vvar.varid] = ty.go_repr()
                elif isinstance(ty, GoSimTypeChan):
                    self._chan_vvars[vvar.varid] = ty.go_repr()
        copies: list[tuple[int, list[int]]] = []
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Return) and stmt.ret_exprs:
                    for expr, ty in zip(stmt.ret_exprs, self._result_types(proto)):
                        self._note_typed(expr, ty)
                calls = self._calls_in(stmt)
                for call in calls:
                    kind = self._kind(call)
                    if kind is None:
                        self._note_from_callee(stmt, call)
                        continue
                    args = list(call.args or [])
                    typ = self._type_name(args[0]) if args else None
                    call_def = _call_def(stmt)
                    if kind in ("makemap", "makechan") and call_def is not None:
                        self._note(self._map_vvars if kind == "makemap" else self._chan_vvars, call_def[0], typ)
                    elif kind in ("mapaccess1", "mapaccess2", "mapassign", "mapdelete", "mapclear") and len(args) > 1:
                        self._note(self._map_vvars, args[1], typ)
                    elif kind in ("chansend", "chanrecv1", "chanrecv2", "closechan") and args:
                        self._note(self._chan_vvars, args[0], None)
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    src = stmt.src
                    if isinstance(src, VirtualVariable):
                        copies.append((stmt.dst.varid, [src.varid]))
                    elif hasattr(src, "src_and_vvars"):
                        copies.append((stmt.dst.varid, [v.varid for _, v in src.src_and_vvars if v is not None]))
        for table in (self._map_vvars, self._chan_vvars):
            changed = True
            while changed:
                changed = False
                for dst, srcs in copies:
                    group = [dst, *srcs]
                    if not any(v in table for v in group):
                        continue
                    name = next((table[v] for v in group if table.get(v) is not None), None)
                    for v in group:
                        if v not in table or (table[v] is None and name is not None):
                            table[v] = name
                            changed = True

    @staticmethod
    def _note(table: dict[int, str | None], expr, name: str | None) -> None:
        if isinstance(expr, VirtualVariable) and (expr.varid not in table or table[expr.varid] is None):
            table[expr.varid] = name

    def _note_typed(self, expr, ty) -> None:
        if isinstance(ty, GoSimTypeMap):
            self._note(self._map_vvars, expr, ty.go_repr())
        elif isinstance(ty, GoSimTypeChan):
            self._note(self._chan_vvars, expr, ty.go_repr())

    @staticmethod
    def _result_types(proto) -> list:
        if not isinstance(proto, GoSimTypeFunction) or proto.returnty is None:
            return []
        if isinstance(proto.returnty, GoSimTypeTuple):
            return list(proto.returnty.elems)
        return [proto.returnty]

    def _callee_prototype(self, call: Call) -> GoSimTypeFunction | None:
        name = call_target_name(self.project, call)
        if name is None:
            return None
        if isinstance(call.target, Const) and self.kb.functions.contains_addr(call.target.value_int):
            proto = self.kb.functions.get_by_addr(call.target.value_int).prototype
            if isinstance(proto, GoSimTypeFunction):
                return proto
        return self.kb.go_signatures.prototype(name)

    def _note_from_callee(self, stmt: Statement, call: Call) -> None:
        """Map/channel arguments and results of calls to functions with known Go prototypes."""
        proto = self._callee_prototype(call)
        if proto is None:
            return
        if call.args and len(call.args) == len(proto.args):
            for arg, ty in zip(call.args, proto.args):
                self._note_typed(arg, ty)
        results = self._result_types(proto)
        if len(results) != 1:
            return
        dst = None
        if isinstance(stmt, Assignment) and stmt.src.idx == call.idx:
            dst = stmt.dst
        elif isinstance(stmt, SideEffectStatement) and stmt.expr.idx == call.idx:
            dst = stmt.ret_expr
        self._note_typed(dst, results[0])

    @staticmethod
    def _calls_in(stmt: Statement) -> list[Call]:
        finder = _CallFinder()
        finder.walk_statement(stmt)
        return finder.calls

    def _map_type_of(self, expr) -> GoSimTypeMap | None:
        name = self._map_vvars.get(expr.varid) if isinstance(expr, VirtualVariable) else None
        ty = self._go_type(name)
        return ty if isinstance(ty, GoSimTypeMap) else None

    def _chan_type_of(self, expr) -> GoSimTypeChan | None:
        name = self._chan_vvars.get(expr.varid) if isinstance(expr, VirtualVariable) else None
        ty = self._go_type(name)
        return ty if isinstance(ty, GoSimTypeChan) else None

    #
    # Map slot pointers
    #

    def _collect_slots(self) -> None:
        """mapaccess1/mapassign results that are only ever dereferenced can be folded into their loads and store."""
        assert self._index is not None
        idx = self._index
        for block in self._graph.nodes:
            for stmt in block.statements:
                call_def = _call_def(stmt)
                if call_def is None:
                    continue
                dst, call = call_def
                kind = self._kind(call)
                if kind not in ("mapaccess1", "mapassign") or len(call.args) < 3:
                    continue
                varid = dst.varid
                loads = idx.loads.get(varid, Counter())
                n_loads = sum(loads.values())
                n_stores = idx.stores.get(varid, 0)
                if idx.total.get(varid, 0) != n_loads + n_stores or len(loads) > 1:
                    continue
                if kind == "mapaccess1" and n_stores:
                    continue
                if kind == "mapassign" and n_stores != 1:
                    continue
                self._slots[varid] = (call.args[1], call.args[2])

    def _elem_type(self, typ_expr) -> SimType | None:
        ty = go_type_at(self.project, typ_expr.value_int) if isinstance(typ_expr, Const) else None
        if isinstance(ty, GoSimTypeMap):
            return ty.elem_type.with_arch(self.project.arch)
        return None

    def index_call(self, m: Expression, k: Expression, bits: int, tags: dict) -> Call:
        return self._builtin("mapindex", [m, k], bits, tags, go_render="index")

    def assign_call(self, m: Expression, k: Expression, v: Expression, tags: dict) -> Call:
        return self._builtin("mapassign", [m, k, v], None, tags, go_render="assign")

    #
    # Statement-level rewrites
    #

    def _rewrite_statements(self, block: Block) -> None:
        new_stmts: list[Statement] = []
        changed = False
        for stmt_idx, stmt in enumerate(block.statements):
            result = self._rewrite_statement(block, stmt_idx, stmt, new_stmts)
            if result is stmt:
                new_stmts.append(stmt)
                continue
            changed = True
            if result is None:
                continue
            if isinstance(result, list):
                new_stmts.extend(result)
            else:
                new_stmts.append(result)
        if changed:
            block.statements = new_stmts
            self._changed = True

    def _rewrite_statement(self, block: Block, stmt_idx: int, stmt: Statement, emitted: list[Statement]):
        if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call) and stmt.ret_expr is None:
            call = stmt.expr
            result = self._rewrite_call_statement(block, stmt_idx, call, emitted)
            if result is call:
                return stmt
            if isinstance(result, Call):
                return self._stmt(result, stmt.idx)
            return result
        call_def = _call_def(stmt)
        if call_def is not None:
            return self._rewrite_call_result(block, stmt_idx, stmt, *call_def)
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.varid in self._dropped_defs
        ):
            return None
        # chanrecv2 nested in a condition or return: hoist it into a tuple-valued receive
        for call in self._calls_in(stmt):
            if self._kind(call) == "chanrecv2" and len(call.args) == 2:
                hoisted = self._hoist_chanrecv2(block, stmt_idx, stmt, call)
                if hoisted is not None:
                    return hoisted
        return stmt

    def _rewrite_call_statement(self, block: Block, stmt_idx: int, call: Call, emitted: list[Statement]):
        kind = self._kind(call)
        args = list(call.args or [])
        tags = dict(call.tags)
        if kind == "mapdelete" and len(args) >= 3:
            return self._builtin("delete", args[1:3], None, tags)
        if kind == "mapclear" and len(args) >= 2:
            return self._builtin("clear", args[1:2], None, tags)
        if kind == "closechan" and len(args) >= 1:
            return self._builtin("close", args[:1], None, tags)
        if kind == "deferreturn":
            return None
        if kind == "gopanic" and len(args) >= 1:
            return self._builtin("panic", [self._panic_value(args[0])], None, tags)
        if kind == "chansend" and len(args) == 2:
            value = self._value_behind_pointer(args[1], self._chan_elem_size(args[0]), emitted)
            if value is not None:
                return self._builtin("chansend", [args[0], value], None, tags, go_render="send")
            return call
        if kind in ("chanrecv1", "chanrecv2") and len(args) == 2:
            return self._rewrite_chanrecv_statement(block, stmt_idx, call, tags)
        if kind == "newproc" and len(args) >= 1:
            return self._builtin("go", self._closure_call(args[0]), None, tags, go_render="go")
        if kind == "deferproc" and len(args) >= 1:
            return self._builtin("defer", self._closure_call(args[0]), None, tags, go_render="defer")
        if kind == "deferprocstack" and len(args) >= 1:
            fn = self._defer_record_fn(args[0], emitted)
            if fn is not None:
                return self._builtin("defer", self._closure_call(fn), None, tags, go_render="defer")
            return call
        return call

    def _rewrite_call_result(self, block: Block, stmt_idx: int, stmt: Statement, dst: VirtualVariable, call: Call):
        kind = self._kind(call)
        args = list(call.args or [])
        tags = dict(call.tags)
        if kind in ("mapaccess1", "mapassign"):
            if dst.varid in self._slots:
                self._dropped_defs.add(dst.varid)
                return None
            return stmt
        if kind == "mapaccess2" and len(args) >= 3 and dst.was_combo_reg and dst.reg_vvars:
            return self._rewrite_tuple_access(stmt, dst, args[1], args[2], self._elem_type(args[0]), tags)
        if kind == "makemap":
            type_name = self._type_name(args[0]) if args else self._map_vvars.get(dst.varid)
            if type_name is None:
                return stmt
            hint = [args[1]] if len(args) > 1 and not (isinstance(args[1], Const) and args[1].value_int == 0) else []
            new_call = self._builtin(
                "make", hint, call.bits, tags, go_type_args=[type_name], is_prototype_guessed=False
            )
            self._set_prototype(new_call, [self._go_type("int")] * len(hint), self._go_type(type_name))
            return self._stmt(new_call, stmt.idx, ret_expr=dst)
        if kind == "makechan" and args:
            type_name = self._type_name(args[0])
            if type_name is None:
                # a channel typed by its consumers carries their direction; make needs the bidirectional type
                derived = self._chan_vvars.get(dst.varid)
                type_name = "chan " + derived.split("chan ", 1)[1] if derived and "chan " in derived else derived
            if type_name is None:
                return stmt
            size = [args[1]] if len(args) > 1 and not (isinstance(args[1], Const) and args[1].value_int == 0) else []
            new_call = self._builtin(
                "make", size, call.bits, tags, go_type_args=[type_name], is_prototype_guessed=False
            )
            self._set_prototype(new_call, [self._go_type("int")] * len(size), self._go_type(type_name))
            return self._stmt(new_call, stmt.idx, ret_expr=dst)
        if kind == "gorecover":
            new_call = self._builtin("recover", [], call.bits, tags, is_prototype_guessed=False)
            self._set_prototype(new_call, [], self._go_type("any"))
            return self._stmt(new_call, stmt.idx, ret_expr=dst)
        if kind in ("chanrecv1", "chanrecv2") and len(args) == 2:
            # the value is written through the pointer, only the ok flag is assigned
            return self._rewrite_chanrecv_statement(block, stmt_idx, call, tags, ok_dst=dst)
        return stmt

    def _rewrite_tuple_access(self, stmt: Statement, dst: VirtualVariable, m, k, elem: SimType | None, tags: dict):
        """``ptr, ok = mapaccess2(...)`` where ``ptr`` is only dereferenced becomes ``t = m[k]`` with ``t.~r0`` the value."""
        assert self._index is not None
        ptr = dst.reg_vvars[0]
        loads = self._index.loads.get(ptr.varid, Counter())
        n_loads = sum(loads.values())
        if n_loads != self._index.total.get(ptr.varid, 0) or (loads and set(loads) != {ptr.size}):
            return stmt
        self._deref.add(ptr.varid)
        new_call = self._builtin("mapindex", [m, k], dst.bits, tags, go_render="index", is_prototype_guessed=False)
        value_ty = elem if elem is not None and self._type_size(elem, 8) == ptr.size else self._go_type("int")
        self._set_prototype(
            new_call, [self._map_type_of(m), self._key_type(m)], GoSimTypeTuple([value_ty, self._go_type("bool")])
        )
        return self._stmt(new_call, stmt.idx, ret_expr=dst)

    def _key_type(self, m) -> SimType | None:
        ty = self._map_type_of(m)
        return ty.key_type.with_arch(self.project.arch) if ty is not None else None

    #
    # Values passed by pointer
    #

    def _chan_elem_size(self, chan_expr) -> int:
        ty = self._chan_type_of(chan_expr)
        return self._type_size(ty.elem_type if ty is not None else None, self.project.arch.bytes)

    def _chan_elem_type(self, chan_expr) -> SimType | None:
        ty = self._chan_type_of(chan_expr)
        return ty.elem_type.with_arch(self.project.arch) if ty is not None else None

    def _value_behind_pointer(self, ptr, size: int, emitted: list[Statement]) -> Expression | None:
        """The value a callee reads through ``ptr``: a stack slot assigned just before the call or a read-only constant."""
        assert self._index is not None
        slot = _ref_vvar(ptr)
        if slot is not None and slot.was_stack:
            for i in range(len(emitted) - 1, -1, -1):
                prev = emitted[i]
                if (
                    isinstance(prev, Assignment)
                    and isinstance(prev.dst, VirtualVariable)
                    and prev.dst.varid == slot.varid
                ):
                    if self._index.total.get(slot.varid, 0) == 1 and self._index.refs.get(slot.varid, 0) == 1:
                        del emitted[i]
                    return prev.src
                if isinstance(prev, (SideEffectStatement, Store)):
                    break
            return None
        if isinstance(ptr, Const) and self._is_readonly(ptr.value_int):
            return self._read_constant(ptr.value_int, size)
        return Load(self._new_idx(), ptr, size, self.project.arch.memory_endness)

    def _read_constant(self, addr: int, size: int) -> Const | None:
        if size not in (1, 2, 4, 8):
            return None
        with contextlib.suppress(KeyError):
            value = self.project.loader.memory.unpack_word(addr, size=size)
            return Const(self._new_idx(), value, size * self.project.arch.byte_width)
        return None

    def _read_string(self, addr: int, printable_only: bool = False) -> StringLiteral | None:
        with contextlib.suppress(KeyError, UnicodeDecodeError):
            ptr = self.project.loader.memory.unpack_word(addr, size=self.project.arch.bytes)
            length = self.project.loader.memory.unpack_word(
                addr + self.project.arch.bytes, size=self.project.arch.bytes
            )
            if 0 <= length <= 0x10000 and (length == 0 or self._is_readonly(ptr)):
                data = self.project.loader.memory.load(ptr, length).decode("utf-8") if length else ""
                if printable_only and not (data and data.isprintable()):
                    return None
                return StringLiteral(self._new_idx(), data, 128)
        return None

    def _panic_value(self, value) -> Expression:
        """A constant interface ``any{type, &data}`` becomes the literal it boxes."""
        if not isinstance(value, Struct):
            return value
        fields = list(value.fields.values()) if hasattr(value.fields, "values") else list(value.fields)
        if len(fields) != 2 or not all(isinstance(f, Const) for f in fields):
            return value
        type_name = go_type_name_at(self.project, fields[0].value_int)
        data = fields[1].value_int
        if type_name == "string" or (type_name is None and self._is_readonly(data)):
            # without a descriptor name, a read-only (pointer, length) header holding text is taken as a string
            lit = self._read_string(data, printable_only=type_name is None)
            return lit if lit is not None else value
        if type_name in _INT_KINDS and self._is_readonly(data):
            ty = self._go_type(type_name)
            const = self._read_constant(data, self._type_size(ty, 8))
            return const if const is not None else value
        return value

    #
    # Channel receives: the runtime writes the element through a stack pointer
    #

    def _rewrite_chanrecv_statement(self, block: Block, stmt_idx: int, call: Call, tags: dict, ok_dst=None):
        chan, ptr = call.args
        if isinstance(ptr, Const) and ptr.value_int == 0:
            recv = self._builtin("chanrecv", [chan], call.bits, tags, go_render="recv")
            return self._stmt(recv, ret_expr=ok_dst)
        slot = _ref_vvar(ptr)
        if slot is None or not slot.was_stack or not self._uses_dominated_by(slot.varid, block, stmt_idx):
            return call
        if ok_dst is None:
            value = VirtualVariable(self._new_idx(), self._new_varid(), slot.bits, VVC.REGISTER, oident=16)
            recv = self._builtin("chanrecv", [chan], slot.bits, tags, go_render="recv", is_prototype_guessed=False)
            self._set_prototype(recv, [self._chan_type_of(chan)], self._chan_elem_type(chan))
            self._replace[slot.varid] = value
            return self._stmt(recv, ret_expr=value)
        combo, value, ok = self._tuple_vvars(slot.bits)
        recv = self._builtin("chanrecv", [chan], combo.bits, tags, go_render="recv", is_prototype_guessed=False)
        self._set_prototype(
            recv,
            [self._chan_type_of(chan)],
            GoSimTypeTuple([self._chan_elem_type(chan) or self._go_type("int"), self._go_type("bool")]),
        )
        self._replace[slot.varid] = value
        ok_use = self._narrow(ok, ok_dst.bits)
        return [self._stmt(recv, ret_expr=combo), Assignment(self._new_idx(), ok_dst, ok_use, **tags)]

    def _hoist_chanrecv2(self, block: Block, stmt_idx: int, stmt: Statement, call: Call):
        chan, ptr = call.args
        slot = _ref_vvar(ptr)
        if slot is None or not slot.was_stack:
            return None
        if not self._uses_dominated_by(slot.varid, block, stmt_idx - 1):
            return None
        combo, value, ok = self._tuple_vvars(slot.bits)
        recv = self._builtin(
            "chanrecv", [chan], combo.bits, dict(call.tags), go_render="recv", is_prototype_guessed=False
        )
        self._set_prototype(
            recv,
            [self._chan_type_of(chan)],
            GoSimTypeTuple([self._chan_elem_type(chan) or self._go_type("int"), self._go_type("bool")]),
        )
        self._replace[slot.varid] = value
        replacer = _CallReplacer(call, self._narrow(ok, call.bits), self)
        new_stmt = replacer.walk_statement(stmt, block, stmt_idx)
        return [self._stmt(recv, ret_expr=combo), new_stmt]

    def _narrow(self, vvar: VirtualVariable, bits: int) -> VirtualVariable:
        if bits == vvar.bits:
            return vvar
        return VirtualVariable(self._new_idx(), vvar.varid, bits, vvar.category, oident=vvar.oident)

    def _tuple_vvars(self, value_bits: int) -> tuple[VirtualVariable, VirtualVariable, VirtualVariable]:
        bits = self.project.arch.bits
        rax, rbx = self.project.arch.registers["rax"][0], self.project.arch.registers["rbx"][0]
        value = VirtualVariable(self._new_idx(), self._new_varid(), max(value_bits, bits), VVC.REGISTER, oident=rax)
        ok = VirtualVariable(self._new_idx(), self._new_varid(), bits, VVC.REGISTER, oident=rbx)
        combo = VirtualVariable(
            self._new_idx(),
            self._new_varid(),
            value.bits + ok.bits,
            VVC.COMBO_REGISTER,
            oident=(rax, rbx),
            reg_vvars=[value, ok],
        )
        return combo, value, ok

    #
    # Goroutines and defer
    #

    def _closure_call(self, fn) -> list[Expression]:
        """``[callee, args...]`` for a ``*funcval``: a static funcval names its function, a heap closure is called as is."""
        if isinstance(fn, Const):
            with contextlib.suppress(KeyError):
                code = self.project.loader.memory.unpack_word(fn.value_int, size=self.project.arch.bytes)
                if self.kb.functions.contains_addr(code):
                    return [self._const_bits(code)]
            return [fn]
        if isinstance(fn, VirtualVariable):
            code = self._closure_code_pointer(fn)
            if code is not None and not self._closure_has_captures(fn):
                return [code]
        return [fn]

    def _closure_code_pointer(self, closure: VirtualVariable) -> Const | None:
        assert self._index is not None
        loc = self._index.defs.get(closure.varid)
        if loc is None:
            return None
        block, _ = loc
        for stmt in block.statements:
            if (
                isinstance(stmt, Store)
                and isinstance(stmt.addr, VirtualVariable)
                and stmt.addr.varid == closure.varid
                and isinstance(stmt.data, Const)
                and self.kb.functions.contains_addr(stmt.data.value_int)
            ):
                return stmt.data
        return None

    def _closure_has_captures(self, closure: VirtualVariable) -> bool:
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Store):
                    base, off = _addr_and_offset(stmt.addr)
                    if isinstance(base, VirtualVariable) and base.varid == closure.varid and off:
                        return True
        return False

    def _defer_record_fn(self, record, emitted: list[Statement]):
        """The ``fn`` field stored into a stack ``_defer`` record before deferprocStack."""
        slot = _ref_vvar(record)
        if slot is None:
            return None
        for prev in reversed(emitted):
            if not (isinstance(prev, Assignment) and isinstance(prev.dst, VirtualVariable) and prev.dst.was_stack):
                continue
            if slot.stack_offset < prev.dst.stack_offset < slot.stack_offset + 0x40 and isinstance(
                prev.src, (Const, VirtualVariable)
            ):
                if isinstance(prev.src, Const) and not self.kb.functions.contains_addr(prev.src.value_int):
                    continue
                return prev.src
        return None

    def _rewrite_open_coded_defers(self) -> None:
        """
        An open-coded defer keeps a deferBits byte on the stack: set to a bit after the closure is materialized, cleared
        right before the closure is called inline at each exit. Replace the bit set by ``defer`` and drop the exit calls.
        """
        self._reindex()
        exits: list[tuple[Statement, Statement, int]] = []  # (bits clear, inline call, closure slot varid)
        for block in self._graph.nodes:
            stmts = block.statements
            for i in range(len(stmts) - 1):
                bits_stmt, call = stmts[i], stmts[i + 1]
                if not (self._is_bits_assign(bits_stmt) and isinstance(call, SideEffectStatement)):
                    continue
                slot = self._deferred_closure_slot(call.expr)
                if slot is not None:
                    exits.append((bits_stmt, call, slot.varid))
        if not exits:
            return
        drop: set[int] = set()
        replace: dict[int, Statement] = {}
        for bits_stmt, call_stmt, slot_varid in exits:
            bits_offset = bits_stmt.dst.stack_offset
            setup = self._find_defer_setup(slot_varid, bits_offset)
            if setup is None:
                continue
            setup_stmt, fn = setup
            defer_call = self._builtin("defer", self._closure_call(fn), None, dict(setup_stmt.tags), go_render="defer")
            replace[setup_stmt.idx] = self._stmt(defer_call)
            drop.update({bits_stmt.idx, call_stmt.idx})
            drop |= self._defer_scaffolding(slot_varid, bits_offset)
        if not replace:
            return
        drop -= set(replace)
        for block in self._graph.nodes:
            block.statements = [replace.get(stmt.idx, stmt) for stmt in block.statements if stmt.idx not in drop]
        self._changed = True

    @staticmethod
    def _deferred_closure_slot(call) -> VirtualVariable | None:
        """
        The stack vvar an inline deferred call goes through: go1.22 loads the code pointer through a slot holding
        &funcval, go1.27 reads the funcval's code word (a stack vvar) directly.
        """
        if not isinstance(call, Call):
            return None
        target = call.target
        if isinstance(target, Load):
            target = target.addr
            slot = target if isinstance(target, VirtualVariable) else _ref_vvar(target)
        else:
            slot = target if isinstance(target, VirtualVariable) else None
        return slot if slot is not None and slot.was_stack else None

    @staticmethod
    def _is_bits_assign(stmt) -> bool:
        return (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and stmt.dst.size == 1
            and isinstance(stmt.src, Const)
        )

    def _find_defer_setup(self, slot_varid: int, bits_offset: int):
        assert self._index is not None
        loc = self._index.defs.get(slot_varid)
        if loc is None:
            return None
        block, idx = loc
        slot_def = block.statements[idx]
        fn = slot_def.src
        funcval = _ref_vvar(fn)
        if funcval is not None:
            fn_loc = self._index.defs.get(funcval.varid)
            if fn_loc is not None:
                fn_src = fn_loc[0].statements[fn_loc[1]].src
                fn = fn_src if isinstance(fn_src, Const) else fn
        for j in range(idx + 1, len(block.statements)):
            stmt = block.statements[j]
            if self._is_bits_assign(stmt) and stmt.dst.stack_offset == bits_offset and stmt.src.value_int != 0:
                return stmt, fn
            if isinstance(stmt, (SideEffectStatement, Store, Return)):
                break
        return None

    def _defer_scaffolding(self, slot_varid: int, bits_offset: int) -> set[int]:
        """Statements to drop: the closure slot, the funcval code pointer and every other constant write of deferBits."""
        assert self._index is not None
        loc = self._index.defs.get(slot_varid)
        if loc is None:
            return set()
        slot_def = loc[0].statements[loc[1]]
        dropped: list[VirtualVariable] = [slot_def.dst]
        funcval = _ref_vvar(slot_def.src)
        if funcval is not None and self._index.total.get(funcval.varid, 0) == 1:
            fv_loc = self._index.defs.get(funcval.varid)
            if fv_loc is not None:
                dropped.append(fv_loc[0].statements[fv_loc[1]].dst)
        drop_ids = {v.varid for v in dropped}
        assigns = [
            stmt
            for block in self._graph.nodes
            for stmt in block.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
        ]
        out: set[int] = set()
        for stmt in assigns:
            dst = stmt.dst
            ref = _ref_vvar(stmt.src)
            if dst.varid in drop_ids or (self._is_bits_assign(stmt) and dst.stack_offset == bits_offset):
                out.add(stmt.idx)
            elif ref is not None and ref.varid in drop_ids and self._index.total.get(dst.varid, 0) == 0:
                out.add(stmt.idx)
                dropped.append(dst)
        # the compiler zeroes the funcval and closure slot before filling them
        for stmt in assigns:
            dst = stmt.dst
            if (
                stmt.idx not in out
                and dst.was_stack
                and isinstance(stmt.src, Const)
                and stmt.src.value_int == 0
                and self._index.total.get(dst.varid, 0) == 0
                and any(_stack_overlap(dst, v) for v in dropped)
            ):
                out.add(stmt.idx)
        return out


def _stack_overlap(a: VirtualVariable, b: VirtualVariable) -> bool:
    return a.stack_offset <= b.stack_offset < a.stack_offset + a.size or (
        b.stack_offset <= a.stack_offset < b.stack_offset + b.size
    )


class _CallReplacer(AILBlockRewriter):
    """Replace one call by a vvar and fold the byte extraction the compiler applies to its bool result."""

    def __init__(self, call: Call, replacement: VirtualVariable, owner: GoRuntimeRewriter):
        super().__init__(update_block=False)
        self._call = call
        self._replacement = replacement
        self._o = owner

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.idx == self._call.idx:
            return self._replacement
        return super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Extract(self, expr_idx, expr, stmt_idx, stmt, block):
        new_expr = super()._handle_Extract(expr_idx, expr, stmt_idx, stmt, block)
        base = new_expr.base
        if isinstance(base, BinaryOp) and base.op == "And" and isinstance(base.operands[1], Const):
            base = base.operands[0]
        if (
            isinstance(base, VirtualVariable)
            and base.varid == self._replacement.varid
            and isinstance(new_expr.offset, Const)
            and new_expr.offset.value_int == 0
        ):
            return self._o._narrow(self._replacement, new_expr.bits)
        return new_expr


class _ExprRewriter(AILBlockRewriter):
    """Loads and stores through map slot pointers, map lengths and vvars the runtime used to write through pointers."""

    def __init__(self, owner: GoRuntimeRewriter):
        super().__init__()
        self._o = owner
        self.changed = False

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        rep = self._o._replace.get(expr.varid)
        if rep is not None:
            self.changed = True
            return rep.copy()
        return expr

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        new_expr = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
        expr = new_expr if new_expr is not None else expr
        addr = expr.addr
        if isinstance(addr, Call) and self._o._kind(addr) == "mapaccess1" and len(addr.args) >= 3:
            self.changed = True
            return self._o.index_call(addr.args[1], addr.args[2], expr.bits, dict(expr.tags))
        if isinstance(addr, VirtualVariable):
            slot = self._o._slots.get(addr.varid)
            if slot is not None:
                self.changed = True
                return self._o.index_call(*slot, expr.bits, dict(expr.tags))
            if addr.varid in self._o._deref and expr.size == addr.size:
                self.changed = True
                return addr
            if addr.varid in self._o._map_vvars and expr.size == self._o.project.arch.bytes:
                self.changed = True
                return self._o._builtin("len", [addr], expr.bits, dict(expr.tags))
        return new_expr

    def _handle_Store(self, stmt_idx, stmt, block):
        new_stmt = super()._handle_Store(stmt_idx, stmt, block)
        stmt = new_stmt if new_stmt is not None else stmt
        addr = stmt.addr
        call = None
        if isinstance(addr, Call) and self._o._kind(addr) == "mapassign" and len(addr.args) >= 3:
            call = self._o.assign_call(addr.args[1], addr.args[2], stmt.data, dict(stmt.tags))
        elif isinstance(addr, VirtualVariable) and addr.varid in self._o._slots:
            call = self._o.assign_call(*self._o._slots[addr.varid], stmt.data, dict(stmt.tags))
        if call is not None:
            self.changed = True
            return self._o._stmt(call, stmt.idx)
        return new_stmt
