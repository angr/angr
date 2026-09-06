from __future__ import annotations

import logging

from angr.ailment.block import Block
from angr.ailment.expression import Call, ComboRegister, Register
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.calling_conventions import SimArrayArg, SimComboArg, SimRegArg, SimStructArg
from angr.sim_type import SimTypeBottom
from angr.utils.ssa import get_reg_offset_base_and_size

l = logging.getLogger(__name__)

# the tag a widened Return carries: how many result words the guessed prototype had
RET_FLOOR_TAG = "go_ret_floor"


def _flatten_locs(loc) -> list:
    if isinstance(loc, SimStructArg):
        return [x for sub in loc.locs.values() for x in _flatten_locs(sub)]
    if isinstance(loc, SimArrayArg):
        return [x for sub in loc.locs for x in _flatten_locs(sub)]
    if isinstance(loc, SimComboArg):
        return [x for sub in loc.locations for x in _flatten_locs(sub)]
    return [loc]


class GoResultWidener(OptimizationPass):
    """
    Let the return statements of a function whose results are only guessed name every ABIInternal result register
    that holds a value at the return: registers written on all paths since the last call, or carried by that call's
    results. The calling-convention guess only ever counts the first two, so the result inference would otherwise
    never see the cap word of a slice or the error behind a pointer. The prototype keeps its guessed shape; the extra
    expressions are tagged with the guessed word count and dropped again once the inference has read them.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Widen guessed Go return statements to every result register"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        if not self.project.is_go_binary:
            return False, None
        cc = self._func.calling_convention
        if cc is None or not cc.ARG_REGS:
            # ABI0 functions return on the stack
            return False, None
        return self.kb.go_signatures.results_guessed(self._func), None

    def _analyze(self, cache=None):
        arch = self.project.arch
        cc = self._func.calling_convention
        assert cc is not None
        self._regs: list[int] = [arch.registers[r][0] for r in cc.ARG_REGS]
        self._names: list[str] = list(cc.ARG_REGS)
        self._index = {off: i for i, off in enumerate(self._regs)}
        everything = frozenset(range(len(self._regs)))

        entry = next((n for n in self._graph.nodes if (n.addr, n.idx) == self.entry_node_addr), None)
        if entry is None:
            return
        # must-analysis: result registers holding a value at the end of each block
        out: dict[Block, frozenset[int]] = dict.fromkeys(self._graph.nodes, everything)
        worklist = list(self._graph.nodes)
        rounds = 0
        while worklist and rounds < 50 * len(out):
            rounds += 1
            block = worklist.pop()
            state, _ = self._transfer(block, self._in_state(block, out, entry, everything))
            if state != out[block]:
                out[block] = state
                worklist.extend(self._graph.successors(block))

        # every return site writes the same result registers (after its last call); the ones some sites leave
        # untouched are scratch. Sites behind a call with unknown results say nothing.
        sites: list[tuple[Block, int, Return, int]] = []
        extents: list[int] = []
        for block in list(self._graph.nodes):
            for idx, stmt in enumerate(block.statements):
                if not isinstance(stmt, Return) or RET_FLOOR_TAG in stmt.tags:
                    continue
                state, unknown = self._transfer(block, self._in_state(block, out, entry, everything), stop=idx)
                extent = 0
                while extent < len(self._regs) and extent in state:
                    extent += 1
                sites.append((block, idx, stmt, extent))
                if not unknown:
                    extents.append(extent)
        if not extents:
            return
        extent = min(extents)
        changed = False
        for block, idx, stmt, _ in sites:
            floor = len(stmt.ret_exprs)
            if extent <= floor:
                continue
            exprs = list(stmt.ret_exprs)
            for i in range(floor, extent):
                exprs.append(
                    Register(
                        self.manager.next_atom(),
                        self._regs[i],
                        arch.bits,
                        reg_name=self._names[i],
                        ins_addr=stmt.tags.get("ins_addr"),
                    )
                )
            tags = dict(stmt.tags)
            tags[RET_FLOOR_TAG] = floor
            block.statements[idx] = Return(stmt.idx, exprs, **tags)
            changed = True
            l.debug("Widened return at %#x of %s to %d words", block.addr, self._func.name, extent)
        if changed:
            self.out_graph = self._graph

    def _in_state(self, block: Block, out: dict, entry: Block, everything: frozenset[int]) -> frozenset[int]:
        preds = list(self._graph.predecessors(block))
        state = everything
        for pred in preds:
            state &= out[pred]
        if block is entry:
            state = (state if preds else frozenset()) | self._param_words()
        return state

    def _param_words(self) -> frozenset[int]:
        """The result registers that carry a parameter on entry (a parameter returned as is is never rewritten)."""
        proto = self._func.prototype
        cc = self._func.calling_convention
        if proto is None or cc is None:
            return frozenset()
        try:
            locs = cc.arg_locs(proto)
        except Exception:  # pylint:disable=broad-exception-caught
            return frozenset()
        words = set()
        for loc in locs:
            for leaf in _flatten_locs(loc):
                if isinstance(leaf, SimRegArg) and leaf.reg_name in self._names:
                    words.add(self._names.index(leaf.reg_name))
        return frozenset(words)

    def _transfer(self, block: Block, state: frozenset[int], stop: int | None = None) -> tuple[frozenset[int], bool]:
        unknown = False
        for idx, stmt in enumerate(block.statements):
            if stop is not None and idx >= stop:
                break
            if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                state, unknown = self._call_words(stmt.expr, stmt.ret_expr)
            elif isinstance(stmt, Assignment):
                if isinstance(stmt.src, Call):
                    state, unknown = self._call_words(stmt.src, stmt.dst)
                elif isinstance(stmt.dst, Register):
                    word = self._word_of(stmt.dst.reg_offset)
                    if word is not None:
                        state = state | {word}
        return state, unknown

    def _word_of(self, reg_offset: int) -> int | None:
        base, _ = get_reg_offset_base_and_size(reg_offset, self.project.arch)
        return self._index.get(base)

    def _call_words(self, call: Call, ret_expr) -> tuple[frozenset[int], bool]:
        """
        A call clobbers every result register; the ones its results land in are defined afterwards. The flag says
        the callee's results are unknown (an unresolved target).
        """
        words: set[int] = set()
        regs = []
        unknown = False
        if isinstance(ret_expr, ComboRegister):
            regs = [r.reg_offset for r in ret_expr.registers if isinstance(r, Register)]
        elif isinstance(ret_expr, Register):
            regs = [ret_expr.reg_offset]
        else:
            target = call.target.value_int if hasattr(call.target, "value_int") else None
            callee = (
                self.kb.functions.get_by_addr(target, meta_only=True)
                if isinstance(target, int) and self.kb.functions.contains_addr(target)
                else None
            )
            if callee is None:
                unknown = True
            elif (
                callee.prototype is not None
                and callee.calling_convention is not None
                and callee.prototype.returnty is not None
                and not isinstance(callee.prototype.returnty, SimTypeBottom)
            ):
                try:
                    regs = [
                        self.project.arch.registers[x.reg_name][0]
                        for x in _flatten_locs(callee.calling_convention.return_val(callee.prototype.returnty))
                        if isinstance(x, SimRegArg)
                    ]
                except Exception:  # pylint:disable=broad-exception-caught
                    regs = []
        for off in regs:
            word = self._word_of(off)
            if word is not None:
                words.add(word)
        return frozenset(words), unknown
