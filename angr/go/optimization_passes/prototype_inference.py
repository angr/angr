from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, ConditionalJump, Return, SideEffectStatement, Store
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import (
    GoSimStruct,
    GoSimType,
    GoSimTypeFunction,
    GoSimTypeInterface,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeString,
    go_type_repr,
)
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_name_at
from angr.utils.go_runtime import normalize_go_func_name
from angr.utils.ssa.vvar_uses_collector import VVarUsesCollector

from .result_widener import RET_FLOOR_TAG
from .value_fuser import _leaf_count, _load_base_and_offset

if TYPE_CHECKING:
    from angr.sim_type import SimType

l = logging.getLogger(__name__)

Words = dict[int, tuple[str, int]]  # word index -> (Go type string, words spanned)


class GoPrototypeInference(OptimizationPass):
    """
    Infer the signature of a function nobody names (no DWARF, not in the signature database, not a method) from the
    typed code around it:

    - parameters, from how they reach callees whose prototypes are known: a parameter word passed where a callee
      takes an ``int`` is an int, two consecutive words fused into ``io.Writer`` for a callee are an ``io.Writer``;
    - results, from what its return statements put in the result registers (a ``new(T)`` gives ``*T``, a constant
      string header a ``string``, an itab an interface, a known callee's result its type) and from how callers use
      the result registers of calls to it (passed to a typed callee, returned through a typed prototype, stored into
      a typed field, compared against an itab).

    Everything is recorded in ``kb.go_signatures`` as an inferred signature; it takes effect the next time the
    function is decompiled (the argument variables and return sites are built before any pass runs).
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Infer Go signatures from typed callers and callees"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._values: _Values | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary and self._arg_vvars is not None, None

    def _analyze(self, cache=None):
        sigs = self.kb.go_signatures
        self._values = _Values(self)
        params = self._infer_params() if self._func.is_prototype_guessed else None
        results_guessed = sigs.results_guessed(self._func)
        results = self._infer_results() if results_guessed else None
        if params or results:
            sigs.set_inferred(self._func.name, params, results)
            l.debug("Inferred %s(%s) -> %s from its own body", self._func.name, params, results)
        self._infer_caller_results()
        if results_guessed:
            self._trim_returns()

    #
    # Parameters
    #

    def _infer_params(self) -> list[str] | None:
        assert self._arg_vvars is not None
        words: dict[int, int] = {}  # param vvar varid -> word index
        for _, (vvar, _arg) in sorted(self._arg_vvars.items(), key=lambda kv: kv[0]):
            if isinstance(vvar, VirtualVariable) and not vvar.was_combo_reg:
                words[vvar.varid] = len(words)
        if not words:
            return None
        found: dict[int, tuple[str, int]] = {}  # word -> (type string, words spanned)
        for _stmt, call in self._values.calls:
            if not call.args:
                continue
            proto = self._callee_prototype(call)
            if proto is None:
                continue
            for arg, ty in zip(call.args, proto.args):
                if not isinstance(ty, GoSimType) or not ty.size:
                    continue
                span = ty.size // self.project.arch.bits
                if isinstance(arg, VirtualVariable) and arg.varid in words and span == 1:
                    _record(found, words[arg.varid], go_type_repr(ty), 1)
                elif isinstance(arg, Struct) and span >= 2:
                    pieces = [arg.fields[off] for off in sorted(arg.fields)]
                    if len(pieces) != span or not all(
                        isinstance(p, VirtualVariable) and p.varid in words for p in pieces
                    ):
                        continue
                    idx = [words[p.varid] for p in pieces]
                    if idx == list(range(idx[0], idx[0] + span)):
                        _record(found, idx[0], go_type_repr(ty), span)
        if not found:
            return None
        # assemble the parameter list: typed groups where known, the guessed word type elsewhere
        types: list[str] = []
        w = 0
        while w < len(words):
            hit = found.get(w)
            if hit is not None:
                types.append(hit[0])
                w += hit[1]
            else:
                types.append("uintptr")
                w += 1
        return types

    def _callee_prototype(self, call: Call) -> GoSimTypeFunction | None:
        proto = variable_map_of(self.manager).prototype(call)
        if isinstance(proto, GoSimTypeFunction):
            return proto
        target = call.target.value if hasattr(call.target, "value") else None
        if isinstance(target, int) and self.kb.functions.contains_addr(target):
            proto = self.kb.functions.get_by_addr(target, meta_only=True).prototype
            if isinstance(proto, GoSimTypeFunction):
                return proto
        return None

    #
    # Results, callee side: what the return statements carry
    #

    def _infer_results(self) -> Words | None:
        found: Words = {}
        conflicts: set[int] = set()
        for block in self._graph.nodes:
            for stmt in block.statements:
                if not isinstance(stmt, Return) or not stmt.ret_exprs:
                    continue
                leaves = self._flatten(list(stmt.ret_exprs))
                w = 0
                while w < len(leaves):
                    hit = leaves[w] if isinstance(leaves[w], tuple) else self._classify(leaves, w, depth=0)
                    if hit is None:
                        w += 1
                        continue
                    ty, span = hit
                    old = found.get(w)
                    if old is not None and old[1] == span and old[0] != ty:
                        conflicts.add(w)
                    _record(found, w, ty, span)
                    w += span
        for w in conflicts:
            # disagreeing returns keep the guess for that word
            found.pop(w, None)
        return found or None

    def _flatten(self, exprs: list) -> list:
        """
        One entry per result word: the word's expression, or an already known (type, words) for a fused value the
        value fuser rebuilt from an applied prototype (a re-inference pass).
        """
        out: list = []
        bytes_ = self.project.arch.bytes
        for expr in exprs:
            if isinstance(expr, Struct):
                out.extend(self._flatten([expr.fields[off] for off in sorted(expr.fields)]))
            elif isinstance(expr, VirtualVariable) and expr.reg_vvars:
                out.extend(expr.reg_vvars)
            elif isinstance(expr, StringLiteral):
                out.append(("string", 2))
            elif (
                isinstance(expr, Load)
                and expr.size > bytes_
                and isinstance(expr.addr, (UnaryOp, BinaryOp))
                and self._combo_piece_of(expr) is not None
            ):
                out.extend(self._combo_piece_of(expr))
            else:
                out.append(expr)
        return out

    def _combo_piece_of(self, load: Load) -> list | None:
        """The register vvars a ``Load(&combo + off, size)`` covers."""
        addr, off = _addr_base_and_offset(load.addr)
        if not (isinstance(addr, UnaryOp) and addr.op == "Reference" and isinstance(addr.operand, VirtualVariable)):
            return None
        regs = addr.operand.reg_vvars
        bytes_ = self.project.arch.bytes
        if not regs or off % bytes_ or load.size % bytes_:
            return None
        pieces = regs[off // bytes_ : (off + load.size) // bytes_]
        return pieces if len(pieces) == load.size // bytes_ else None

    def _classify(self, leaves: list, i: int, depth: int) -> tuple[str, int] | None:
        """The Go type of the value whose first word is ``leaves[i]`` and how many of the leaves it spans."""
        assert self._values is not None
        if isinstance(leaves[i], tuple):
            return leaves[i]
        expr = self._values.resolve(leaves[i])
        if isinstance(expr, BinaryOp) and expr.op == "Add":
            base = self._values.resolve(expr.operands[0])
            hit = self._values.combo_of.get(base.varid) if isinstance(base, VirtualVariable) else None
            if hit is not None:
                return self._classify_combo_word(leaves, i, hit[0], hit[1])
        if isinstance(expr, VirtualVariable):
            ty = self._values.param_types.get(expr.varid)
            if isinstance(ty, GoSimType) and ty.size == self.project.arch.bits:
                return go_type_repr(ty), 1
            hit = self._values.combo_of.get(expr.varid)
            if hit is not None:
                return self._classify_combo_word(leaves, i, hit[0], hit[1])
            src = self._values.defs.get(expr.varid)
            if isinstance(src, Call):
                return self._single_result(src, leaves, i)
            if isinstance(src, Phi):
                return self._classify_phi(leaves, i, depth)
            if isinstance(src, Convert):
                if src.from_bits == 1:
                    return "bool", 1
                return None
            if isinstance(src, (Load, Const)):
                expr = src
        if isinstance(expr, Const) and expr.is_int:
            return self._classify_const(leaves, i, expr.value_int)
        if isinstance(expr, Load):
            return self._classify_load(leaves, i, expr)
        return None

    def _combo_words(self, combo: VirtualVariable) -> list:
        """Per register word of a fused parameter or call result: (type, word within it, words), None if untyped."""
        assert self._values is not None
        ty = self._values.param_types.get(combo.varid)
        if ty is not None:
            return _value_words([ty])
        call = self._values.defs.get(combo.varid)
        proto = self._callee_prototype(call) if isinstance(call, Call) else None
        if proto is None:
            return []
        words = _result_words(proto)
        if len(words) == 3 and words[0] is not None and go_type_repr(words[0][0]) == "runtime.slice":
            # growslice returns the runtime's untyped header; the element descriptor argument types it
            elem = self._slice_elem_of(call)
            words = _value_words([elem]) if elem is not None else []
        return words

    def _classify_combo_word(self, leaves, i, combo: VirtualVariable, word: int) -> tuple[str, int] | None:
        """A register of a multi-word call result or parameter: the typed value that starts at this word."""
        assert self._values is not None
        words = self._combo_words(combo)
        if word >= len(words) or words[word] is None:
            return None
        ty, start, span = words[word]
        if start != 0:
            return None
        ids = [rv.varid for rv in combo.reg_vvars or []]
        wanted = ids[word : word + span]
        got = [self._values.resolve(x) for x in leaves[i : i + span]]
        if len(wanted) != span or len(got) != span:
            return None
        if all(isinstance(g, VirtualVariable) and g.varid == v for g, v in zip(got, wanted)):
            return go_type_repr(ty), span
        if isinstance(ty, GoSimTypeSlice) and span == 3:
            return self._classify_resliced(leaves, i, combo, word, ty)
        return None

    def _classify_resliced(self, leaves, i, combo: VirtualVariable, word: int, ty) -> tuple[str, int] | None:
        """``s[k:]`` of a typed slice: (ptr + k*w, len - k, cap - k) over the words of ``s``."""
        assert self._values is not None
        ids = [rv.varid for rv in combo.reg_vvars or []][word : word + 3]
        if len(ids) != 3 or i + 2 >= len(leaves):
            return None
        for k, op in enumerate(("Add", "Sub", "Sub")):
            leaf = self._values.resolve(leaves[i + k])
            # the pointer advances by a masked amount (no advance past an empty slice), the lengths by a constant
            if isinstance(leaf, BinaryOp) and leaf.op == op and (k == 0 or isinstance(leaf.operands[1], Const)):
                leaf = self._values.resolve(leaf.operands[0])
            if not isinstance(leaf, VirtualVariable) or leaf.varid != ids[k]:
                return None
        return go_type_repr(ty), 3

    def _slice_elem_of(self, call: Call):
        """``[]T`` for a raw ``runtime.growslice(..., &type:T)`` call."""
        name = call_target_name(self.project, call)
        if name is None or normalize_go_func_name(name) != "runtime.growslice":
            return None
        elem = self._descriptor_arg(call, 4)
        if elem is None:
            return None
        try:
            return self.kb.go_signatures.type(f"[]{elem}")
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def _single_result(self, call: Call, leaves=None, i: int = 0) -> tuple[str, int] | None:
        proto = self._callee_prototype(call)
        if proto is None:
            return None
        results = proto.results
        if len(results) != 1 or not isinstance(results[0], GoSimType) or results[0].size != self.project.arch.bits:
            return None
        name = call_target_name(self.project, call)
        name = normalize_go_func_name(name) if name is not None else ""
        if name in ("runtime.makeslice", "runtime.makeslicecopy"):
            # the pointer word of a fresh slice; the len and cap words follow
            elem = self._descriptor_arg(call, 0)
            if elem is not None and leaves is not None and i + 2 < len(leaves):
                return f"[]{elem}", 3
            return None
        repr_ = go_type_repr(results[0])
        if name.startswith("runtime.") and repr_ == "unsafe.Pointer":
            # allocation helpers return the raw word of whatever they built
            return None
        return repr_, 1

    def _descriptor_arg(self, call: Call, index: int) -> str | None:
        args = list(call.args or [])
        if index >= len(args):
            return None
        arg = args[index]
        return go_type_name_at(self.project, arg.value_int) if isinstance(arg, Const) and arg.is_int else None

    def _classify_phi(self, leaves, i, depth: int) -> tuple[str, int] | None:
        """Leaves defined by phis over the same blocks are classified per incoming block and must agree."""
        assert self._values is not None
        if depth > 2:
            return None
        phis = []
        for leaf in leaves[i:]:
            r = self._values.resolve(leaf)
            src = self._values.defs.get(r.varid) if isinstance(r, VirtualVariable) else None
            if not isinstance(src, Phi):
                break
            phis.append(dict(src.src_and_vvars))
            if len(phis) == 3:
                break
        if not phis:
            return None
        sources = [s for s in phis[0] if all(s in p for p in phis)]
        best = None
        for s in sources:
            column = [p[s] for p in phis]
            if any(v is None for v in column):
                continue
            hit = self._classify(column, 0, depth + 1)
            if hit is None:
                continue
            if best is None or best[1] < hit[1]:
                best = hit
            elif best[0] != hit[0] and best[1] == hit[1]:
                return None
        return best

    def _classify_const(self, leaves, i, value: int) -> tuple[str, int] | None:
        if value == 0:
            return None
        if i + 1 < len(leaves):
            itab = self.kb.go_types.itab_at(value)
            if itab is not None:
                return itab[0], 2
            if go_type_name_at(self.project, value) is not None:
                # a type descriptor followed by a data word: an empty interface
                return "any", 2
            nxt = self._values.resolve(leaves[i + 1]) if self._values is not None else leaves[i + 1]
            if isinstance(nxt, Const) and nxt.is_int and 0 < nxt.value_int <= 0x10000 and self._is_readonly(value):
                return "string", 2
        return None

    def _classify_load(self, leaves, i, load: Load) -> tuple[str, int] | None:
        """A load from a field of a typed pointer (a parameter, a ``new(T)`` or a typed call result)."""
        assert self._values is not None
        parsed = _load_base_and_offset(load)
        if parsed is None:
            return None
        base, off = parsed
        if base is None:
            # a package-level variable a source (DWARF) typed
            var = self.kb.go_signatures.variable_at(off)
            if var is None:
                return None
            try:
                fty = self.kb.go_signatures.type(var.type_str)
            except Exception:  # pylint:disable=broad-exception-caught
                return None
        else:
            pointee = self._pointee_type(base)
            if not isinstance(pointee, GoSimStruct):
                return None
            if off == 0 and isinstance(pointee, (GoSimTypeString, GoSimTypeSlice, GoSimTypeInterface)):
                # the words of a string/slice/interface behind a pointer (an element of a typed slice)
                fty = pointee
            else:
                fty = _field_at(pointee, off)
        if not isinstance(fty, GoSimType) or not fty.size:
            return None
        span = _leaf_count(fty)
        if span == 1:
            return (go_type_repr(fty), 1) if fty.size == load.bits else None
        # the following leaves must load the next words of the same value
        for k in range(1, span):
            if i + k >= len(leaves):
                return None
            nxt = _load_base_and_offset(self._values.resolve(leaves[i + k]))
            if nxt is None or nxt[1] != off + k * self.project.arch.bytes:
                return None
            if (base is None) != (nxt[0] is None) or (base is not None and not nxt[0].likes(base)):
                return None
        return go_type_repr(fty), span

    def _pointee_type(self, base: Expression) -> SimType | None:
        assert self._values is not None
        base = self._values.resolve(base)
        if not isinstance(base, VirtualVariable):
            return None
        ty = self._values.param_types.get(base.varid)
        if ty is None:
            hit = self._values.combo_of.get(base.varid)
            if hit is not None:
                # the pointer word of a fused value: a slice's array or a pointer result
                words = self._combo_words(hit[0])
                if hit[1] < len(words) and words[hit[1]] is not None and words[hit[1]][1] == 0:
                    ty = words[hit[1]][0]
                    if isinstance(ty, GoSimTypeSlice):
                        return ty.elem_type
            else:
                src = self._values.defs.get(base.varid)
                if isinstance(src, Call):
                    proto = self._callee_prototype(src)
                    if proto is not None and len(proto.results) == 1:
                        ty = proto.results[0]
        if isinstance(ty, GoSimTypePointer):
            return ty.pts_to
        return None

    def _is_readonly(self, addr: int) -> bool:
        section = self.project.loader.find_section_containing(addr)
        return section is not None and section.is_readable and not section.is_writable

    #
    # Results, caller side: how this function uses the results of calls to functions with guessed results
    #

    def _infer_caller_results(self) -> None:
        assert self._values is not None
        sigs = self.kb.go_signatures
        # result values of calls to callees with guessed results: varid of the (combo) vvar -> callee
        targets: dict[int, str] = {}
        for stmt, call in self._values.calls:
            target = call.target.value if hasattr(call.target, "value") else None
            if not isinstance(target, int) or not self.kb.functions.contains_addr(target):
                continue
            callee = self.kb.functions.get_by_addr(target, meta_only=True)
            if not sigs.results_guessed(callee):
                continue
            dst = None
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                dst = stmt.dst
            elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.ret_expr, VirtualVariable):
                dst = stmt.ret_expr
            if dst is not None:
                targets[dst.varid] = callee.name
        if not targets:
            return
        found: dict[str, Words] = {}

        def note_words(expr, type_str: str, span: int, exact: bool = True) -> None:
            piece = self._piece(expr)
            if piece is None:
                return
            varid, word, have = piece
            name = targets.get(varid)
            if name is None or (exact and have != span):
                return
            _record(found.setdefault(name, {}), word, type_str, span)

        def note(expr, ty) -> None:
            # an untyped pointer or word says nothing about the value
            if isinstance(ty, GoSimType) and ty.size and go_type_repr(ty) not in ("unsafe.Pointer", "uintptr"):
                note_words(expr, go_type_repr(ty), _leaf_count(ty))

        own = self._func.prototype
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Return) and stmt.ret_exprs and isinstance(own, GoSimTypeFunction):
                    self._note_return(stmt, own, note)
                elif isinstance(stmt, Store):
                    base, off = _addr_base_and_offset(stmt.addr)
                    pointee = self._pointee_type(base) if base is not None else None
                    if isinstance(pointee, GoSimStruct):
                        note(stmt.data, _field_at(pointee, off))
                elif isinstance(stmt, ConditionalJump):
                    self._note_compare(stmt.condition, note_words)
        for _stmt, call in self._values.calls:
            proto = self._callee_prototype(call)
            if proto is None or not call.args or _converts_arguments(call_target_name(self.project, call)):
                continue
            for arg, ty in zip(call.args, proto.args):
                note(arg, ty)
        for name, words in found.items():
            sigs.set_inferred(name, caller_results=words)
            l.debug("Inferred results of %s from its caller %s: %s", name, self._func.name, words)

    def _note_return(self, stmt: Return, proto: GoSimTypeFunction, note) -> None:
        results = proto.results
        exprs = list(stmt.ret_exprs)
        if len(exprs) == len(results):
            for expr, ty in zip(exprs, results):
                note(expr, ty)
            return
        # unfused: one leaf per word
        words = _result_words(proto)
        for i, expr in enumerate(exprs):
            if i < len(words) and words[i] is not None and words[i][1] == 0:
                note(expr, words[i][0])

    def _note_compare(self, cond: Expression, note_words) -> None:
        """``x == &go:itab.T,I``: the word compared is the itab of an ``I`` value, the next word its data."""
        if not isinstance(cond, BinaryOp) or cond.op not in ("CmpEQ", "CmpNE"):
            return
        a, b = cond.operands
        for x, y in ((a, b), (b, a)):
            if isinstance(y, Const) and y.is_int:
                itab = self.kb.go_types.itab_at(y.value_int)
                if itab is not None:
                    note_words(x, itab[0], 2, exact=False)

    def _piece(self, expr: Expression) -> tuple[int, int, int] | None:
        """(varid of the call result, first word, words) an expression covers of a call result value."""
        assert self._values is not None
        bytes_ = self.project.arch.bytes
        expr = self._values.resolve(expr)
        if isinstance(expr, VirtualVariable):
            hit = self._values.combo_of.get(expr.varid)
            if hit is not None:
                return hit[0].varid, hit[1], 1
            if expr.reg_vvars:
                return expr.varid, 0, len(expr.reg_vvars)
            return expr.varid, 0, 1
        if isinstance(expr, Load):
            addr = expr.addr
            off = 0
            if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
                off = addr.operands[1].value_int
                addr = addr.operands[0]
            if isinstance(addr, UnaryOp) and addr.op == "Reference" and isinstance(addr.operand, VirtualVariable):
                combo = addr.operand
                if combo.reg_vvars and off % bytes_ == 0 and expr.size % bytes_ == 0:
                    return combo.varid, off // bytes_, expr.size // bytes_
            return None
        if isinstance(expr, Struct):
            pieces = [self._piece(expr.fields[off]) for off in sorted(expr.fields)]
            if not pieces or any(p is None for p in pieces):
                return None
            varid, word, _ = pieces[0]
            expected = word
            for p in pieces:
                if p[0] != varid or p[1] != expected:
                    return None
                expected += p[2]
            return varid, word, expected - word
        return None

    #
    # Cleanup: drop the result words the widener added beyond the guessed prototype
    #

    def _trim_returns(self) -> None:
        changed = False
        for block in self._graph.nodes:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Return) and RET_FLOOR_TAG in stmt.tags:
                    tags = dict(stmt.tags)
                    floor = tags.pop(RET_FLOOR_TAG)
                    block.statements[idx] = Return(stmt.idx, list(stmt.ret_exprs)[:floor], **tags)
                    changed = True
        if not changed:
            return
        # definitions only the dropped words used are dead now
        while True:
            collector = VVarUsesCollector()
            for block in self._graph.nodes:
                collector.walk(block)
            used = collector.vvars
            removed = False
            for block in self._graph.nodes:
                keep = []
                for stmt in block.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and stmt.dst.varid not in used
                        and not isinstance(stmt.src, Call)
                        and not any(rv.varid in used for rv in stmt.dst.reg_vvars or [])
                    ):
                        removed = True
                        continue
                    keep.append(stmt)
                if len(keep) != len(block.statements):
                    block.statements = keep
            if not removed:
                break
        self.out_graph = self._graph


class _Values:
    """Definitions and register pieces of the function's virtual variables."""

    def __init__(self, pass_: GoPrototypeInference):
        self.defs: dict[int, Expression] = {}
        self.combo_of: dict[int, tuple[VirtualVariable, int]] = {}
        self.param_types: dict[int, SimType] = {}
        self.calls: list[tuple[object, Call]] = []
        bytes_ = pass_.project.arch.bytes

        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                offset = 0
                for reg_vvar in vvar.reg_vvars:
                    self.combo_of[reg_vvar.varid] = (vvar, offset // bytes_)
                    offset += reg_vvar.size

        proto = pass_._func.prototype
        if pass_._arg_vvars:
            args = list(proto.args) if isinstance(proto, GoSimTypeFunction) else []
            for i, (arg_vvar, _) in sorted(pass_._arg_vvars.items(), key=lambda kv: kv[0]):
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
                    if i < len(args):
                        self.param_types[arg_vvar.varid] = args[i]
        for block in pass_._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)
                    self.defs[stmt.dst.varid] = stmt.src
                    if isinstance(stmt.src, Call):
                        self.calls.append((stmt, stmt.src))
                elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                    self.calls.append((stmt, stmt.expr))
                    if isinstance(stmt.ret_expr, VirtualVariable):
                        note(stmt.ret_expr)
                        self.defs[stmt.ret_expr.varid] = stmt.expr

    def resolve(self, expr: Expression) -> Expression:
        """Look through virtual-variable copies."""
        seen = set()
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = self.defs.get(expr.varid)
            if not isinstance(src, VirtualVariable):
                break
            expr = src
        return expr


def _converts_arguments(name: str | None) -> bool:
    """Runtime helpers whose parameter types say nothing about the caller's value (``printint(int64(n))``)."""
    if name is None:
        return False
    name = normalize_go_func_name(name)
    return name.startswith("runtime.print") or (
        name.startswith("runtime.convT") and name not in ("runtime.convTstring", "runtime.convTslice")
    )


def _record(found: dict, word: int, type_str: str, span: int) -> None:
    # a conflicting earlier guess wins only if it is wider (an interface over its first word as an int)
    old = found.get(word)
    if old is None or old[1] < span:
        found[word] = (type_str, span)


def _value_words(types: list) -> list[tuple[SimType, int, int] | None]:
    """Per register word of the values: (type, word within that type, words of that type); None for non-Go types."""
    words: list = []
    for ty in types:
        if not isinstance(ty, GoSimType) or not ty.size:
            words.append(None)
            continue
        n = _leaf_count(ty)
        words.extend((ty, k, n) for k in range(n))
    return words


def _result_words(proto: GoSimTypeFunction) -> list[tuple[SimType, int, int] | None]:
    return _value_words(proto.results)


def _addr_base_and_offset(addr: Expression) -> tuple[Expression | None, int]:
    """``base + k`` -> (base, k); ``Const c`` -> (None, c)."""
    if isinstance(addr, Const):
        return None, addr.value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
        return addr.operands[0], addr.operands[1].value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[0], Const):
        return addr.operands[1], addr.operands[0].value_int
    return addr, 0


def _field_at(struct: GoSimStruct, off: int) -> SimType | None:
    for name, ty in struct.fields.items():
        foff = struct.offsets.get(name)
        if foff == off:
            return ty
        if foff is not None and isinstance(ty, GoSimStruct) and ty.size and foff < off < foff + ty.size // 8:
            inner = _field_at(ty, off - foff)
            if inner is not None:
                return inner
    return None
