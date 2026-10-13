from __future__ import annotations

import logging
from typing import cast

from angr.ailment.block import Block
from angr.ailment.expression import Call, ComboRegister, Const, Register, Tmp
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.calling_conventions import SimArrayArg, SimComboArg, SimRegArg, SimStructArg
from angr.enums import Flavors
from angr.go.sim_type import GoSimType
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeNum
from angr.utils.go_runtime import normalize_go_func_name
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

    A guess can also count too many: a result register a callee left behind looks returned. When a return site of
    known provenance leaves it unset and the function never writes it after its last call, it is dropped from the
    returns and from the guessed prototype.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Widen guessed Go return statements to every result register"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self._regs: list[int] = []
        self._names: list[str] = []
        self._index: dict[int, int] = {}
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
        self._regs = [arch.registers[r][0] for r in cc.ARG_REGS]
        self._names = list(cc.ARG_REGS)
        self._index = {off: i for i, off in enumerate(self._regs)}
        everything = frozenset(range(len(self._regs)))

        entry = next((n for n in self._graph.nodes if (n.addr, n.idx) == self.entry_node_addr), None)
        if entry is None:
            return
        # must-analysis: result registers holding a value at the end of each block, and whether that value may come
        # from a call whose results are unknown
        # (and the result registers whose values were copied into lower ones since the last call)
        out: dict[Block, tuple[frozenset[int], bool, frozenset[int]]] = dict.fromkeys(
            self._graph.nodes, (everything, False, frozenset())
        )
        worklist = list(self._graph.nodes)
        rounds = 0
        while worklist and rounds < 50 * len(out):
            rounds += 1
            block = worklist.pop()
            state = self._transfer(block, *self._in_state(block, out, entry, everything))
            if state != out[block]:
                out[block] = state
                worklist.extend(self._graph.successors(block))

        # every return site writes the same result registers (after its last call); the ones some sites leave
        # untouched are scratch. Sites behind a call with unknown results say nothing.
        sites: list[tuple[Block, int, Return, int]] = []
        extents: list[int] = []
        written: list[int] = []
        for block in list(self._graph.nodes):
            for idx, stmt in enumerate(block.statements):
                if not isinstance(stmt, Return) or RET_FLOOR_TAG in stmt.tags:
                    continue
                state, unknown, moved = self._transfer(block, *self._in_state(block, out, entry, everything), stop=idx)
                extent = 0
                while extent < len(self._regs) and extent in state:
                    extent += 1
                if not unknown:
                    written.append(extent)
                if moved:
                    # the function moved a call's later result words down (`return nil, err` after a call that
                    # returned (T, error)): the originals left behind are not results
                    extent = min(extent, min(moved))
                sites.append((block, idx, stmt, extent))
                if not unknown:
                    extents.append(extent)
        if not extents:
            return
        if self._narrow(sites, min(written)):
            self.out_graph = self._graph
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

    def _narrow(self, sites: list[tuple[Block, int, Return, int]], words: int) -> bool:
        """
        Cut the returns, and the guessed result type of the prototype, down to the first ``words`` result registers:
        the ones a return site of known provenance does not leave unset. Only returns that still carry exactly the
        registers the guess gave them are cut, never down to nothing, and never of a register the function itself
        writes after its last call on some path to a return.
        """
        proto = self._func.get_prototype(Flavors.GO_FLAVOR)
        if words == 0 or proto is None or isinstance(proto.returnty, GoSimType):
            # an inferred or declared result type is not the calling-convention guess
            return False
        arch = self.project.arch
        shapes = {
            tuple(
                self._word_of(e.reg_offset) if isinstance(e, Register) and e.bits == arch.bits else None
                for e in stmt.ret_exprs
            )
            for _, _, stmt, _ in sites
        }
        if len(shapes) != 1:
            return False
        (shape,) = shapes
        if len(shape) <= words or shape != tuple(range(len(shape))):
            return False
        own = self._own_writes()
        dropped = set(range(words, len(shape)))
        for block, idx, _, _ in sites:
            if dropped & self._own_transfer(block, self._own_in(block, own), stop=idx):
                return False
        for block, idx, stmt, _ in sites:
            block.statements[idx] = Return(stmt.idx, list(stmt.ret_exprs)[:words], **stmt.tags)
        new_proto = proto.copy()
        new_proto.returnty = SimTypeNum(words * arch.bits, signed=False)
        # with_arch copies, keeping the type
        self._func.set_prototype(Flavors.GO_FLAVOR, cast(SimTypeFunction, new_proto.with_arch(arch)))
        # every decompilation guesses again, and an inferred prototype would pad its results back to the guess
        self.kb.go_signatures.set_inferred(self._func.name, return_words=words)
        l.debug("Narrowed the returns of %s to %d words", self._func.name, words)
        return True

    def _own_writes(self) -> dict[Block, frozenset[int]]:
        """The result registers the function itself may have written since its last call, at the end of each block."""
        out: dict[Block, frozenset[int]] = dict.fromkeys(self._graph.nodes, frozenset())
        worklist = list(self._graph.nodes)
        while worklist:
            block = worklist.pop()
            state = self._own_transfer(block, self._own_in(block, out))
            if state != out[block]:
                out[block] = state
                worklist.extend(self._graph.successors(block))
        return out

    def _own_in(self, block: Block, out: dict[Block, frozenset[int]]) -> frozenset[int]:
        state: frozenset[int] = frozenset()
        for pred in self._graph.predecessors(block):
            state |= out[pred]
        return state

    def _own_transfer(self, block: Block, state: frozenset[int], stop: int | None = None) -> frozenset[int]:
        for idx, stmt in enumerate(block.statements):
            if stop is not None and idx >= stop:
                break
            call = stmt.expr if isinstance(stmt, SideEffectStatement) else getattr(stmt, "src", None)
            if isinstance(call, Call) and not self._preserves_registers(call):
                # the callee clobbers every result register; what it leaves there is not the function's own
                state = frozenset()
            elif isinstance(stmt, Assignment) and isinstance(stmt.dst, Register):
                word = self._word_of(stmt.dst.reg_offset)
                if word is not None:
                    state = state | {word}
        return state

    def _in_state(
        self, block: Block, out: dict, entry: Block, everything: frozenset[int]
    ) -> tuple[frozenset[int], bool, frozenset[int]]:
        preds = list(self._graph.predecessors(block))
        state = everything
        unknown = False
        moved: frozenset[int] = frozenset()
        for pred in preds:
            state &= out[pred][0]
            unknown |= out[pred][1]
            moved |= out[pred][2]
        if block is entry:
            state = (state if preds else frozenset()) | self._param_words()
        return state, unknown, moved

    def _param_words(self) -> frozenset[int]:
        """The result registers that carry a parameter on entry (a parameter returned as is is never rewritten)."""
        proto = self._func.get_prototype(Flavors.GO_FLAVOR)
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

    def _transfer(
        self, block: Block, state: frozenset[int], unknown: bool, moved: frozenset[int], stop: int | None = None
    ) -> tuple[frozenset[int], bool, frozenset[int]]:
        tmp_words: dict[int, int] = {}  # tmp -> the result register it was read from
        for idx, stmt in enumerate(block.statements):
            if stop is not None and idx >= stop:
                break
            if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                if not self._preserves_registers(stmt.expr):
                    moved = frozenset()
                state, unknown = self._call_words(stmt.expr, stmt.ret_expr, state)
            elif isinstance(stmt, Assignment):
                if isinstance(stmt.src, Call):
                    if not self._preserves_registers(stmt.src):
                        moved = frozenset()
                    state, unknown = self._call_words(stmt.src, stmt.dst, state)
                elif isinstance(stmt.dst, Register):
                    word = self._word_of(stmt.dst.reg_offset)
                    if word is not None:
                        state = state | {word}
                        moved = moved - {word}
                        src = None
                        if isinstance(stmt.src, Register):
                            src = self._word_of(stmt.src.reg_offset)
                        elif isinstance(stmt.src, Tmp):
                            src = tmp_words.get(stmt.src.tmp_idx)
                        if src is not None and src > word:
                            moved = moved | {src}
                elif isinstance(stmt.dst, Tmp) and isinstance(stmt.src, Register):
                    src = self._word_of(stmt.src.reg_offset)
                    if src is not None:
                        tmp_words[stmt.dst.tmp_idx] = src
        return state, unknown, moved

    def _preserves_registers(self, call: Call) -> bool:
        """Write barriers and the duff helpers keep the caller's registers (the compiler emits them mid-epilogue)."""
        target = call.target.value_int if isinstance(call.target, Const) else None
        if not isinstance(target, int):
            return False
        sym = self.project.loader.find_symbol(target, fuzzy=True)
        if sym is None:
            return False
        name = normalize_go_func_name(sym.name)
        return name.startswith("runtime.gcWriteBarrier") or name in ("runtime.duffzero", "runtime.duffcopy")

    def _word_of(self, reg_offset: int) -> int | None:
        base, _ = get_reg_offset_base_and_size(reg_offset, self.project.arch)
        return self._index.get(base)

    def _call_words(self, call: Call, ret_expr, state: frozenset[int]) -> tuple[frozenset[int], bool]:
        """
        A call clobbers every result register; the ones its results land in are defined afterwards. The flag says
        the callee's results are not known for sure (an unresolved target, or a callee whose results are guessed).
        """
        if self._preserves_registers(call):
            return state, False
        target = call.target.value_int if isinstance(call.target, Const) else None
        callee = (
            self.kb.functions.get_by_addr(target, meta_only=True)
            if isinstance(target, int) and self.kb.functions.contains_addr(target)
            else None
        )
        # the guess may stop short of the callee's real results: a site reading them proves nothing
        unknown = callee is None or self.kb.go_signatures.results_guessed(callee)
        regs = []
        if isinstance(ret_expr, ComboRegister):
            regs = [r.reg_offset for r in ret_expr.registers if isinstance(r, Register)]
        elif isinstance(ret_expr, Register):
            regs = [ret_expr.reg_offset]
        elif (
            callee is not None
            and callee.get_prototype(Flavors.GO_FLAVOR) is not None
            and callee.calling_convention is not None
            and callee.get_prototype(Flavors.GO_FLAVOR).returnty is not None
            and not isinstance(callee.get_prototype(Flavors.GO_FLAVOR).returnty, SimTypeBottom)
        ):
            try:
                regs = [
                    self.project.arch.registers[x.reg_name][0]
                    for x in _flatten_locs(
                        callee.calling_convention.return_val(callee.get_prototype(Flavors.GO_FLAVOR).returnty)
                    )
                    if isinstance(x, SimRegArg)
                ]
            except Exception:  # pylint:disable=broad-exception-caught
                regs = []
        words: set[int] = set()
        for off in regs:
            word = self._word_of(off)
            if word is not None:
                words.add(word)
        return frozenset(words), unknown
