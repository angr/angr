from __future__ import annotations

import logging

from angr.ailment import AILBlockViewer
from angr.ailment.expression import BinaryOp, Call, Const, Load, Struct, UnaryOp, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, ConditionalJump, Return
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction, GoSimTypeInt
from angr.sim_type import SimType

l = logging.getLogger(__name__)

# the scratch key Clinic reads after variable recovery: vvar id -> SimType to hold as ground truth
GROUND_TRUTH_KEY = "vvar_ground_truth"

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

    def _collect_combos(self) -> None:
        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                self._combo_words[vvar.varid] = len(vvar.reg_vvars)
                for reg_vvar in vvar.reg_vvars:
                    self._combo_pieces.add(reg_vvar.varid)

        if self._arg_vvars:
            for arg_vvar, _ in self._arg_vvars.values():
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)

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
