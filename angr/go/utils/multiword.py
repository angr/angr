"""
Multi-word Go values that live in one virtual variable rather than in a combo register: stack-passed parameters and
stack results under the all-stack ABI0 (386). The body reads their words as ``Extract(v, k)``.
"""

from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import Call, Const, Expression, Extract, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimStruct
from angr.sim_type import SimType, SimTypeFunction


def extract_piece(expr: Expression) -> tuple[VirtualVariable, int] | None:
    """``Extract(v, k)`` -> (v, k) in bytes."""
    if isinstance(expr, Extract) and isinstance(expr.base, VirtualVariable) and isinstance(expr.offset, Const):
        return expr.base, expr.offset.value_int
    return None


def multiword_vvars(pass_) -> dict[int, SimType]:
    """
    varid -> Go struct type of every virtual variable holding a whole string/slice/interface/tuple value: parameters
    typed by the prototype, results of calls with a typed result, and copies of either.
    """
    project, manager = pass_.project, pass_.manager
    ws = project.arch.bytes
    out: dict[int, SimType] = {}

    proto = pass_._func.prototype
    if pass_._arg_vvars and isinstance(proto, SimTypeFunction):
        for vvar, var in pass_._arg_vvars.values():
            if not isinstance(vvar, VirtualVariable) or vvar.reg_vvars:
                continue  # combo-register parameters have their own piece vvars
            ident = getattr(var, "ident", "") or ""
            idx = int(ident[4:]) if ident.startswith("arg_") and ident[4:].isdigit() else None
            if idx is None or idx >= len(proto.args) or not isinstance(vvar, VirtualVariable):
                continue
            ty = proto.args[idx]
            if isinstance(ty, GoSimStruct) and ty.size == vvar.bits and vvar.size > ws:
                out[vvar.varid] = ty

    vm = variable_map_of(manager)
    copies: list[tuple[VirtualVariable, VirtualVariable]] = []
    for block in pass_._graph.nodes:
        for stmt in block.statements:
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.size > ws):
                continue
            if stmt.dst.reg_vvars:
                continue  # a combo register: its words are the constituent register vvars
            src = stmt.src
            if isinstance(src, VirtualVariable):
                copies.append((stmt.dst, src))
            elif isinstance(src, Call):
                ty = _call_result_type(pass_, vm, src)
                if isinstance(ty, GoSimStruct) and ty.size == stmt.dst.bits:
                    out[stmt.dst.varid] = ty
    changed = True
    while changed:
        changed = False
        for dst, src in copies:
            if src.varid in out and dst.varid not in out and src.size == dst.size:
                out[dst.varid] = out[src.varid]
                changed = True
    return out


def _call_result_type(pass_, vm, call: Call) -> SimType | None:
    proto = vm.prototype(call)
    if proto is None and isinstance(call.target, Const) and pass_.kb.functions.contains_addr(call.target.value_int):
        proto = pass_.kb.functions.get_by_addr(call.target.value_int, meta_only=True).prototype
    if isinstance(proto, SimTypeFunction) and proto.returnty is not None:
        ty = proto.returnty
        return ty.with_arch(pass_.project.arch) if ty._arch is None else ty
    if isinstance(call.target, str):
        # a builtin (``+``, ``append``, ``[:]``) spelled by the runtime rewriter: typed by its result tag
        name = call.tags.get("go_result_type")
        if isinstance(name, str):
            try:
                return pass_.kb.go_signatures.type(name).with_arch(pass_.project.arch)
            except Exception:  # pylint:disable=broad-exception-caught
                return None
    return None


class VVarUseCounter(AILBlockViewer):
    """Occurrences of every virtual variable (a definition counts as one)."""

    def __init__(self):
        super().__init__()
        self.counts: dict[int, int] = {}

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        self.counts[expr.varid] = self.counts.get(expr.varid, 0) + 1
        return super()._handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block)


def vvar_use_counts(graph) -> dict[int, int]:
    counter = VVarUseCounter()
    for block in graph.nodes:
        counter.walk(block)
    return counter.counts
