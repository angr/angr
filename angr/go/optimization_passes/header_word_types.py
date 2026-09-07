from __future__ import annotations

import logging

from angr.ailment import AILBlockViewer
from angr.ailment.expression import BinaryOp, Call, Const, Extract, Insert, Load, Struct, UnaryOp, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, ConditionalJump, Return
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimStruct, GoSimType, GoSimTypeFunction, GoSimTypeInt, GoSimTypeSlice, go_type_repr
from angr.sim_type import SimType

l = logging.getLogger(__name__)

# the scratch key Clinic reads after variable recovery: vvar id -> SimType to hold as ground truth
GROUND_TRUTH_KEY = "vvar_ground_truth"
# the scratch key Clinic reads before variable recovery: stack offset -> (size in bytes, SimType, {vvar id: stack
# offset}) of a value whose words sit in that stack region (a string/slice/interface header spilled word by word),
# with the stack vvars that carry its words
STACK_REGIONS_KEY = "stack_regions"

_ORDERED = frozenset({"CmpLT", "CmpLE", "CmpGT", "CmpGE"})
_HEADER_WORDS = frozenset({"len", "cap"})


class _CallCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.calls: list[Call] = []

    def _handle_Call(self, expr_idx, expr: Call, stmt_idx, stmt, block):
        self.calls.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class GoHeaderWordTypes(OptimizationPass):
    """
    Keep the length and capacity words of string and slice headers integers. Type inference happily unifies a
    ``len`` word with the pointer word it travels next to and renders ``(*int8)(n)`` and ``unsafe.Pointer`` locals
    for what is an ``int``. A variable is proven an integer when it is the ``len``/``cap`` leaf of a fused header
    (a call argument or a return value), when it is passed where a typed callee takes an integer, or when it is
    compared in order against the ``len``/``cap`` word of a header; those variables are pinned as ground truth for
    type inference.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Pin Go header length words to int"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self._combo_pieces: set[int] = set()
        self._combo_words: dict[int, int] = {}  # combo varid -> words
        self._collect_combos()
        pins: dict[int, SimType] = {}
        int_ty = self._int_type()
        if int_ty is None:
            return
        proto = self._func.prototype
        calls = _CallCollector()
        for block in self._graph.nodes:
            calls.walk(block)
        for call in calls.calls:
            # calls anywhere in a statement: a folded append sits inside the return that yields it
            self._pin_call(call, pins, int_ty)
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Return) and stmt.ret_exprs:
                    results = proto.results if isinstance(proto, GoSimTypeFunction) else []
                    exprs = list(stmt.ret_exprs)
                    for i, expr in enumerate(exprs):
                        self._pin_value(expr, results[i] if len(results) == len(exprs) else None, pins, int_ty)
                elif isinstance(stmt, ConditionalJump):
                    self._pin_compare(stmt.condition, pins, int_ty)
        if pins:
            self._scratch.setdefault(GROUND_TRUTH_KEY, {}).update(pins)
            l.debug("Pinned %d header words to int in %s", len(pins), self._func.name)
        regions = self._stack_regions(calls.calls)
        if regions:
            self._scratch.setdefault(STACK_REGIONS_KEY, {}).update(regions)
            l.debug("Stack header regions in %s: %s", self._func.name, regions)

    #
    # Stack header regions
    #

    def _stack_regions(self, calls: list[Call]) -> dict[int, tuple[int, SimType, dict[int, int]]]:
        """
        Stack regions holding one string/slice/interface value: the leaves of a fused header (a call argument, a
        return value, a stored value) that are stack words tiling a contiguous region, and a typed call result
        assigned to a stack slot of its size. Variable recovery makes one variable of that type for the vvars
        carrying the words (and, through the phi web, every definition that reaches them).
        """
        regions: dict[int, tuple[int, SimType, dict[int, int]]] = {}
        structs: list[Struct] = []

        class _Structs(AILBlockViewer):
            def _handle_Struct(inner, expr_idx, expr, stmt_idx, stmt, block):
                structs.append(expr)
                super()._handle_Struct(expr_idx, expr, stmt_idx, stmt, block)

        walker = _Structs()
        defs: dict[int, object] = {}
        stores: list[tuple[VirtualVariable, int, object]] = []  # (stack vvar, byte offset into it, value stored)
        for block in self._graph.nodes:
            walker.walk(block)
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    defs[stmt.dst.varid] = stmt.src
                    if stmt.dst.was_stack:
                        src = stmt.src
                        if isinstance(src, Insert) and isinstance(src.offset, Const) and src.offset.is_int:
                            stores.append((stmt.dst, src.offset.value_int, src.value))
                        else:
                            stores.append((stmt.dst, 0, src))
        # words of a typed call result landing in stack slots (through spill copies): the value they are part of
        candidates: dict[tuple[int, int], dict[int, tuple[VirtualVariable, int]]] = {}
        for dst, off, value in stores:
            value = self._through_copies(value, defs)
            word = None
            src: object = value
            if isinstance(value, Extract) and isinstance(value.offset, Const) and value.offset.is_int:
                word, src = value.offset.value_int // self.project.arch.bytes, value.base
            elif isinstance(value, VirtualVariable) and value.varid in self._combo_piece_of:
                combo_id, word = self._combo_piece_of[value.varid]
                src = self._combo_defs.get(combo_id)
            if isinstance(src, VirtualVariable) and src.varid in self._combo_defs:
                src = self._combo_defs[src.varid]
            if not isinstance(src, Call):
                continue
            stack_off = dst.stack_offset + off
            if word is None:
                ty = self._call_result_word_type(src, 0, dst.bits)
                if ty is not None:
                    _note_region(regions, stack_off, dst.size, ty, {dst.varid: dst.stack_offset})
                continue
            hit = self._result_word_owner(src, word)
            if hit is None:
                continue
            ty, start, n = hit
            base = stack_off - (word - start) * self.project.arch.bytes
            candidates.setdefault((id(src), base), {})[word - start] = (dst, dst.stack_offset)
            candidates[(id(src), base)]["ty"] = (ty, n)  # type: ignore[assignment]
        for (_, base), words in candidates.items():
            ty, n = words.pop("ty")  # type: ignore[misc]
            if set(words) == set(range(n)):
                pieces = {vvar.varid: stack_off for vvar, stack_off in words.values()}
                _note_region(regions, base, n * self.project.arch.bytes, ty, pieces)
        for st in structs:
            hit = self._struct_region(st) or self._prefix_region(st)
            if hit is not None:
                off, size, ty, pieces = hit
                _note_region(regions, off, size, ty, pieces)
        return regions

    @staticmethod
    def _through_copies(expr, defs: dict):
        """The expression behind a chain of stack/register copies (spill slots)."""
        seen = set()
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = defs.get(expr.varid)
            if not isinstance(src, VirtualVariable):
                break
            expr = src
        return expr

    def _result_word_owner(self, call: Call, word: int) -> tuple[SimType, int, int] | None:
        """(struct-shaped result, its first word, its words) of the result of ``call`` that word ``word`` is in."""
        proto = self._callee_prototype(call)
        if proto is None:
            return None
        at = 0
        for ty in proto.results:
            if not isinstance(ty, GoSimType) or not ty.size:
                return None
            n = max(1, ty.size // self.project.arch.bits)
            if at <= word < at + n:
                return (ty.with_arch(self.project.arch), at, n) if isinstance(ty, GoSimStruct) and n > 1 else None
            at += n
        return None

    def _callee_prototype(self, call: Call) -> GoSimTypeFunction | None:
        proto = variable_map_of(self.manager).prototype(call)
        if proto is None:
            target = call.target.value if hasattr(call.target, "value") else None
            if isinstance(target, int) and self.kb.functions.contains_addr(target):
                proto = self.kb.functions.get_by_addr(target, meta_only=True).prototype
        return proto if isinstance(proto, GoSimTypeFunction) else None

    def _call_result_word_type(self, call: Call, word: int, bits: int) -> SimType | None:
        """The struct-shaped Go result of ``call`` that starts at result word ``word`` and is ``bits`` wide."""
        proto = variable_map_of(self.manager).prototype(call)
        if proto is None:
            target = call.target.value if hasattr(call.target, "value") else None
            if isinstance(target, int) and self.kb.functions.contains_addr(target):
                proto = self.kb.functions.get_by_addr(target, meta_only=True).prototype
        if not isinstance(proto, GoSimTypeFunction):
            return None
        at = 0
        for ty in proto.results:
            if not isinstance(ty, GoSimType) or not ty.size:
                return None
            if at == word:
                return ty.with_arch(self.project.arch) if isinstance(ty, GoSimStruct) and ty.size == bits else None
            at += max(1, ty.size // self.project.arch.bits)
        return None

    def _struct_region(self, st: Struct) -> tuple[int, int, SimType, dict[int, int]] | None:
        """
        (stack offset, size, type, {vvar id: stack offset}) when every leaf of the fused value is a stack word and
        they tile a region.
        """
        try:
            ty = self.kb.go_signatures.type(st.name).with_arch(self.project.arch)
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        if not isinstance(ty, GoSimStruct) or not ty.size or ty.size != st.bits:
            return None
        pieces = []
        for off in sorted(st.fields):
            piece = self._stack_piece(st.fields[off])
            if piece is None:
                return None
            pieces.append((off, *piece))
        if not pieces:
            return None
        base = pieces[0][1]
        for off, stack_off, size, _ in pieces:
            if stack_off != base + off or size <= 0:
                return None
        total = pieces[-1][0] + pieces[-1][2]
        if total * self.project.arch.byte_width != ty.size:
            return None
        return base, total, ty, {vvar.varid: vvar.stack_offset for _, _, _, vvar in pieces}

    def _prefix_region(self, st: Struct) -> tuple[int, int, SimType, dict[int, int]] | None:
        """
        A fused (ptr, len) of a slice (the bytes a string conversion takes) is the head of the slice header on the
        stack: the region is the whole slice.
        """
        try:
            ty = self.kb.go_signatures.type(st.name).with_arch(self.project.arch)
        except Exception:  # pylint:disable=broad-exception-caught
            return None
        if not isinstance(ty, GoSimTypeSlice) or not ty.size or st.bits >= ty.size:
            return None
        pieces = []
        for off in sorted(st.fields):
            piece = self._stack_piece(st.fields[off])
            if piece is None:
                return None
            pieces.append((off, *piece))
        if not pieces:
            return None
        base = pieces[0][1]
        if any(stack_off != base + off for off, stack_off, _, _ in pieces):
            return None
        return base, ty.size // self.project.arch.byte_width, ty, {v.varid: v.stack_offset for _, _, _, v in pieces}

    @staticmethod
    def _stack_piece(expr) -> tuple[int, int, VirtualVariable] | None:
        """(stack offset, bytes, vvar) of a leaf that is a stack word, or a word extracted from a wider stack slot."""
        if isinstance(expr, VirtualVariable) and expr.was_stack:
            return expr.stack_offset, expr.size, expr
        if isinstance(expr, Extract) and isinstance(expr.base, VirtualVariable) and expr.base.was_stack:
            off = expr.offset
            if isinstance(off, Const) and off.is_int:
                return expr.base.stack_offset + off.value_int, expr.bits // 8, expr.base
        return None

    def _collect_combos(self) -> None:
        self._combo_defs: dict[int, Call] = {}  # combo vvar -> the call defining it
        self._combo_piece_of: dict[int, tuple[int, int]] = {}  # register vvar -> (combo vvar, word)

        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                self._combo_words[vvar.varid] = len(vvar.reg_vvars)
                for i, reg_vvar in enumerate(vvar.reg_vvars):
                    self._combo_pieces.add(reg_vvar.varid)
                    self._combo_piece_of[reg_vvar.varid] = (vvar.varid, i)

        if self._arg_vvars:
            for arg_vvar, _ in self._arg_vvars.values():
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)
                    if isinstance(stmt.src, Call) and stmt.dst.varid in self._combo_words:
                        self._combo_defs[stmt.dst.varid] = stmt.src

    def _int_type(self) -> SimType | None:
        try:
            return self.kb.go_signatures.type("int").with_arch(self.project.arch)
        except Exception:  # pylint:disable=broad-exception-caught
            return None

    def _plain(self, expr) -> VirtualVariable | None:
        """A virtual variable that is a value of its own (not a register of a fused multi-word value)."""
        if (
            isinstance(expr, VirtualVariable)
            and expr.varid not in self._combo_pieces
            and expr.varid not in self._combo_words
            and expr.size == self.project.arch.bytes
        ):
            return expr
        return None

    def _pin_call(self, call: Call, pins: dict, int_ty: SimType) -> None:
        proto = variable_map_of(self.manager).prototype(call)
        if proto is None:
            target = call.target.value if hasattr(call.target, "value") else None
            if isinstance(target, int) and self.kb.functions.contains_addr(target):
                proto = self.kb.functions.get_by_addr(target, meta_only=True).prototype
        args = list(call.args or [])
        types = list(proto.args) if isinstance(proto, GoSimTypeFunction) and len(proto.args) == len(args) else []
        for i, arg in enumerate(args):
            self._pin_value(arg, types[i] if types else None, pins, int_ty)

    def _pin_value(self, expr, ty: SimType | None, pins: dict, int_ty: SimType) -> None:
        if isinstance(expr, Struct):
            names = expr.field_names
            for off, leaf in expr.fields.items():
                if names.get(off) in _HEADER_WORDS:
                    vvar = self._plain(leaf)
                    if vvar is not None:
                        pins[vvar.varid] = int_ty
            return
        vvar = self._plain(expr)
        if vvar is None or not isinstance(ty, GoSimTypeInt):
            return
        # inferred prototypes spell the words they could not type uintptr
        if ty.go_name in (None, "uintptr") or ty.size != vvar.bits:
            return
        pins[vvar.varid] = ty

    def _pin_compare(self, cond, pins: dict, int_ty: SimType) -> None:
        if not isinstance(cond, BinaryOp) or cond.op not in _ORDERED:
            return
        a, b = cond.operands
        for x, y in ((a, b), (b, a)):
            if self._is_header_word(y):
                vvar = self._plain(x)
                if vvar is not None:
                    pins[vvar.varid] = int_ty

    def _is_header_word(self, expr) -> bool:
        """``Load(&combo + 8|16)``: the len or cap word of a fused multi-word value."""
        if not isinstance(expr, Load) or expr.size != self.project.arch.bytes:
            return False
        addr = expr.addr
        if not (isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const)):
            return False
        off = addr.operands[1].value_int
        base = addr.operands[0]
        return (
            off in (self.project.arch.bytes, 2 * self.project.arch.bytes)
            and isinstance(base, UnaryOp)
            and base.op == "Reference"
            and isinstance(base.operand, VirtualVariable)
            and base.operand.varid in self._combo_words
        )


def _note_region(regions: dict, base: int, size: int, ty: SimType, pieces: dict[int, int]) -> None:
    old = regions.get(base)
    if old is None:
        regions[base] = (size, ty, dict(pieces))
    elif old[0] == size and go_type_repr(old[1]) == go_type_repr(ty):
        old[2].update(pieces)
