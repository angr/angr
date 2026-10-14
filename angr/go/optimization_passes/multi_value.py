from __future__ import annotations

import logging
from typing import cast

from angr.ailment import AILBlockViewer, Block
from angr.ailment.expression import Call, ComboRegister, Const, Expression, Register, Tmp
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.decompiler.optimization_passes.combo_register_rewriter import ComboRegisterRewriter
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.optimization_passes.ret_expr_rewriter import RetExprRewriter
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.calling_conventions import SimRegArg, default_cc_for_project
from angr.enums import Flavors
from angr.go.knowledge_plugins.go_signatures import _result_registers
from angr.go.sim_type import GoSimTypeTuple
from angr.utils.go_runtime import normalize_go_func_name
from angr.utils.ssa import get_reg_offset_base_and_size

from .prototypes import GoPrototypeApplier
from .result_widener import _flatten_locs

l = logging.getLogger(__name__)


class GoRetExprRewriter(RetExprRewriter):
    """Give calls to functions with several results a combo-register return expression."""

    NAME = "Rewrite return expressions of calls to Go functions with several results"
    FLAVOR = Flavors.GO_FLAVOR

    def _check(self):
        return self.project.is_go_binary, None


class GoComboRegisterRewriter(ComboRegisterRewriter):
    """Fold register pairs that make up one combo-register parameter back into that parameter."""

    NAME = "Rewrite combo-register parameter references"

    def _check(self):
        return self.project.is_go_binary, None


# word -> the read widths (bytes) of a live result register; float result register k is word -1 - k
_Live = dict[int, frozenset[int]]


def _union(a: _Live, b: _Live) -> _Live:
    if not b:
        return a
    out = dict(a)
    for w, sizes in b.items():
        out[w] = out.get(w, frozenset()) | sizes
    return out


class _RegReads(AILBlockViewer):
    def __init__(self, word_of):
        super().__init__()
        self._word_of = word_of
        self.reads: _Live = {}

    def _handle_Register(self, expr_idx, expr, stmt_idx, stmt, block):
        self._note(expr, expr.size)

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.operand, Register) and expr.to_bits < expr.from_bits:
            # the width actually used of a register read
            self._note(expr.operand, expr.to_bits // 8)
            return
        super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)

    def _note(self, reg: Register, size: int) -> None:
        w = self._word_of(reg.reg_offset)
        if w is not None:
            self.reads[w] = self.reads.get(w, frozenset()) | {size}


class _TmpWidths(AILBlockViewer):
    """The widest use of each tmp: a tmp only ever narrowed to a byte is a byte (``test bl, bl``)."""

    def __init__(self):
        super().__init__()
        self.widths: dict[int, int] = {}

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.operand, Tmp) and expr.to_bits < expr.from_bits:
            self._note(expr.operand.tmp_idx, expr.to_bits // 8)
            return
        super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Tmp(self, expr_idx, expr, stmt_idx, stmt, block):
        self._note(expr.tmp_idx, expr.size)

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if not isinstance(stmt.dst, Tmp):
            self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _note(self, tmp: int, size: int) -> None:
        self.widths[tmp] = max(self.widths.get(tmp, 0), size)


class GoCallResultBinder(OptimizationPass):
    """
    Bind every result register a caller reads after a call to the call's result when the callee's results are only
    guessed (or the callee is unknown: interface methods, closures). ABIInternal clobbers all result registers at a
    call, so a read of rbx/x1 before any write after the call is the call's second result; the same holds for the
    float result registers (xmm0, xmm1, ...), which Go numbers independently. Direct callees learn the word count
    (and ``bool`` for words only read as a byte) through ``kb.go_signatures``; indirect calls get a combo-register
    result and a call-site prototype.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Bind the result registers callers read after Go calls"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._names: list[str] = []
        self._regs: list[int] = []
        self._fp_names: list[str] = []
        self._fp_regs: list[int] = []
        self._index: dict[int, int] = {}
        self._widths: dict = {}
        self.analyze()

    def _check(self):
        if not self.project.is_go_binary:
            return False, None
        cc_cls = default_cc_for_project(self.project)
        # ABI0 / 386 return on the stack
        return bool(cc_cls is not None and cc_cls.ARG_REGS), None

    def _analyze(self, cache=None):
        arch = self.project.arch
        cc_cls = default_cc_for_project(self.project)
        assert cc_cls is not None
        self._names = list(cc_cls.ARG_REGS)
        self._regs = [arch.registers[r][0] for r in self._names]
        self._fp_names = [r for r in cc_cls.FP_ARG_REGS or () if r in arch.registers]
        self._fp_regs = [arch.registers[r][0] for r in self._fp_names]
        self._index = {off: i for i, off in enumerate(self._regs)}
        self._index.update({off: -1 - i for i, off in enumerate(self._fp_regs)})
        sigs = self.kb.go_signatures
        own_results_known = not sigs.results_guessed(self._func)
        self._widths = {}

        # backward liveness of result registers; a call kills all of them
        live_in: dict[Block, _Live] = {b: {} for b in self._graph.nodes}
        worklist = list(self._graph.nodes)
        rounds = 0
        while worklist and rounds < 50 * len(live_in):
            rounds += 1
            block = worklist.pop()
            state = self._transfer(block, self._live_out(block, live_in), own_results_known)
            if state != live_in[block]:
                live_in[block] = state
                worklist.extend(self._graph.predecessors(block))

        applier = GoPrototypeApplier(self.project, self.kb)
        changed = False
        for block in list(self._graph.nodes):
            sites = []
            self._transfer(block, self._live_out(block, live_in), own_results_known, sites=sites)
            for idx, live in sites:
                stmt = block.statements[idx]
                new = self._bind(stmt, live, applier)
                if new is not None:
                    block.statements[idx] = new
                    changed = True
        if changed:
            self.out_graph = self._graph

    def _live_out(self, block: Block, live_in: dict[Block, _Live]) -> _Live:
        out: _Live = {}
        for succ in self._graph.successors(block):
            out = _union(out, live_in.get(succ, {}))
        return out

    def _word_of(self, reg_offset: int) -> int | None:
        base, _ = get_reg_offset_base_and_size(reg_offset, self.project.arch)
        return self._index.get(base)

    def _reads(self, expr) -> _Live:
        v = _RegReads(self._word_of)
        v.walk_expression(expr)
        return v.reads

    def _tmp_widths(self, block: Block) -> dict[int, int]:
        key = (block.addr, block.idx)
        widths = self._widths.get(key)
        if widths is None:
            v = _TmpWidths()
            v.walk(block)
            widths = self._widths[key] = v.widths
        return widths

    def _transfer(self, block: Block, live: _Live, own_results_known: bool, sites: list | None = None) -> _Live:
        for idx in range(len(block.statements) - 1, -1, -1):
            stmt = block.statements[idx]
            if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                if self._preserves_registers(stmt.expr):
                    live = _union(live, self._reads(stmt.expr))
                    continue
                if sites is not None and live:
                    sites.append((idx, live))
                live = _union(self._reads(stmt.expr), self._arg_words(stmt.expr, block))
            elif isinstance(stmt, Assignment):
                if isinstance(stmt.src, Call):
                    # an assigned call clobbers like a statement call; its result is already bound
                    live = self._reads(stmt.src)
                    continue
                if isinstance(stmt.dst, Register):
                    w = self._word_of(stmt.dst.reg_offset)
                    # a 32-bit write zero-extends; narrower writes keep the rest of the register live
                    if w is not None and stmt.dst.size >= 4:
                        live = {k: v for k, v in live.items() if k != w}
                elif isinstance(stmt.dst, Tmp) and isinstance(stmt.src, Register):
                    w = self._word_of(stmt.src.reg_offset)
                    if w is not None:
                        width = self._tmp_widths(block).get(stmt.dst.tmp_idx, stmt.src.size)
                        live = _union(live, {w: frozenset({min(width, stmt.src.size)})})
                    continue
                else:
                    live = _union(live, self._reads(stmt.dst))
                live = _union(live, self._reads(stmt.src))
            elif isinstance(stmt, Return):
                if own_results_known:
                    for e in stmt.ret_exprs or ():
                        live = _union(live, self._reads(e))
            else:
                v = _RegReads(self._word_of)
                v.walk_statement(stmt)
                live = _union(live, v.reads)
        return live

    def _arg_words(self, call: Call, block: Block) -> _Live:
        """Argument registers the call reads (call sites, and with them the arguments, are made later)."""
        target = call.target.value_int if isinstance(call.target, Const) else None
        cc = proto = None
        if isinstance(target, int) and self.kb.functions.contains_addr(target):
            callee = self.kb.functions.get_by_addr(target, meta_only=True)
            cc, proto = callee.calling_convention, callee.get_prototype(Flavors.GO_FLAVOR)
        elif self.kb.callsite_prototypes.has_prototype(block.addr):
            cc = self.kb.callsite_prototypes.get_cc(block.addr)
            proto = self.kb.callsite_prototypes.get_prototype(block.addr)
        if cc is None or proto is None:
            return {}
        try:
            locs = cc.arg_locs(proto)
        except Exception:  # pylint:disable=broad-exception-caught
            return {}
        out: _Live = {}
        for loc in locs:
            for leaf in _flatten_locs(loc):
                if isinstance(leaf, SimRegArg) and leaf.reg_name in self._names:
                    out[self._names.index(leaf.reg_name)] = frozenset({leaf.size})
                elif isinstance(leaf, SimRegArg) and leaf.reg_name in self._fp_names:
                    out[-1 - self._fp_names.index(leaf.reg_name)] = frozenset({leaf.size})
        return out

    def _preserves_registers(self, call: Call) -> bool:
        """Write barriers and the duff helpers keep the caller's registers."""
        target = call.target.value_int if isinstance(call.target, Const) else None
        if not isinstance(target, int):
            return False
        sym = self.project.loader.find_symbol(target, fuzzy=True)
        if sym is None:
            return False
        name = normalize_go_func_name(sym.name)
        return name.startswith("runtime.gcWriteBarrier") or name in ("runtime.duffzero", "runtime.duffcopy")

    def _bind(self, stmt: SideEffectStatement, live: _Live, applier: GoPrototypeApplier):
        if isinstance(stmt.ret_expr, ComboRegister):
            return None
        count = max((w for w in live if w >= 0), default=-1) + 1
        bools = {w: ("bool", 1) for w, sizes in live.items() if w >= 0 and sizes == {1}}
        # a float result only ever read as 4 bytes is a float32
        floats = {-1 - w: "float32" if sizes == {4} else "float64" for w, sizes in live.items() if w < 0}
        call = cast(Call, stmt.expr)
        target = call.target.value_int if isinstance(call.target, Const) else None
        if isinstance(target, int) and self.kb.functions.contains_addr(target):
            callee = self.kb.functions.get_by_addr(target, meta_only=True)
            sigs = self.kb.go_signatures
            if callee.calling_convention is None:
                return None
            proto = callee.get_prototype(Flavors.GO_FLAVOR)
            have_ints, have_floats = (
                _result_registers(proto.returnty, self.project.arch) if proto is not None else (0, 0)
            )
            if sigs.results_guessed(callee):
                # a guessed float result does not cover rax
                ints = count >= 2 or bool(bools) or count > have_ints
                rec = sigs.inferred_record(callee.name)
                if rec is not None and all(k in rec.fp_results for k in floats):
                    floats = {}
            elif sigs.fp_results_open(callee):
                # inferred integer results; callers may still find float ones
                ints, count, bools = False, 0, {}
                if max(floats, default=-1) < have_floats:
                    floats = {}
            else:
                return None
            if not ints and not floats:
                return None
            sigs.set_inferred(callee.name, caller_results=bools, result_words=count, fp_results=floats)
            applier.apply(callee)
            l.debug(
                "%s reads %d result words and %d float results of %s", self._func.name, count, len(floats), callee.name
            )
            # GoRetExprRewriter builds the combo from the widened prototype
            return None
        if isinstance(call.target, str) or count == 0:
            return None
        return self._bind_indirect(stmt, count, bools)

    def _bind_indirect(self, stmt: SideEffectStatement, count: int, bools: dict):
        arch = self.project.arch
        if count == 1:
            if stmt.ret_expr is not None:
                return None
            reg = Register(self.manager.next_atom(), self._regs[0], arch.bits, reg_name=self._names[0])
            return SideEffectStatement(stmt.idx, stmt.expr, reg, stmt.fp_ret_expr, **stmt.tags)
        sigs = self.kb.go_signatures
        # what an earlier decompilation of this function learned about the words read here (GoPrototypeInference)
        site = stmt.tags.get("ins_addr")
        if not isinstance(site, int):
            return None
        rec = sigs.set_callsite_inferred(site, caller_results=bools, result_words=count)
        try:
            types = [sigs.type(t) for t in rec.result_types(count)]
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        regs: list[Expression] = [
            Register(self.manager.next_atom(), self._regs[w], arch.bits, reg_name=self._names[w]) for w in range(count)
        ]
        # call sites are made after this stage; CallSiteMaker puts this result type on the site prototype
        returnty = types[0] if len(types) == 1 else GoSimTypeTuple(types)
        variable_map_of(self.manager).set_returnty(stmt.expr, returnty.with_arch(arch))
        return SideEffectStatement(
            stmt.idx, stmt.expr, ComboRegister(self.manager.next_atom(), regs), stmt.fp_ret_expr, **stmt.tags
        )
