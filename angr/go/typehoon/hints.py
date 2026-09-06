from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.ailment import AILBlockViewer
from angr.ailment.expression import Call, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment
from angr.analyses.typehoon.typeconsts import BottomType, TopType
from angr.go.runtime_types import CONTEXT_REGISTERS
from angr.go.sim_type import GoSimTypeFunction

if TYPE_CHECKING:
    from angr.analyses.typehoon.typeconsts import TypeConstant

l = logging.getLogger(__name__)


def collect_call_result_hints(project, graph, variable_map, type_lifter) -> dict[int, TypeConstant]:
    """
    Type hints for the results of calls with a Go signature: ``v = f(...)`` types ``v`` as the result type of ``f``.

    Type inference alone loses struct-shaped results (strings, slices, interfaces, tuples) held in register pairs to
    the default integer type of the same width, so the signature's word is made binding.
    """
    hints: dict[int, TypeConstant] = {}
    functions = project.kb.functions
    for block in graph.nodes:
        for stmt in block.statements:
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)):
                continue
            call = stmt.src
            if not isinstance(call, Call) or stmt.dst.was_stack:
                continue
            proto = variable_map.prototype(call) if variable_map is not None else None
            if proto is None and not isinstance(call.target, str):
                target = call.target.value if hasattr(call.target, "value") else None
                if isinstance(target, int) and target in functions:
                    proto = functions[target].prototype
            if not isinstance(proto, GoSimTypeFunction) or proto.returnty is None:
                continue
            if proto.returnty.size != stmt.dst.bits:
                continue
            try:
                lifted = type_lifter.lift(proto.returnty)
            except Exception:  # pylint:disable=broad-exception-caught
                l.debug("Cannot lift %s", proto.returnty, exc_info=True)
                continue
            if isinstance(lifted, (BottomType, TopType)):
                continue
            hints[stmt.dst.varid] = lifted
    return hints


class _RegisterVVars(AILBlockViewer):
    """Vvars standing for one machine register: the ones defined and the ones used."""

    def __init__(self, reg_offset: int):
        super().__init__()
        self._reg = reg_offset
        self.defined: set[int] = set()
        self.used: set[int] = set()

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if isinstance(stmt.dst, VirtualVariable) and self._matches(stmt.dst):
            self.defined.add(stmt.dst.varid)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if self._matches(expr):
            self.used.add(expr.varid)

    def _matches(self, vvar: VirtualVariable) -> bool:
        return vvar.category == VVC.REGISTER and vvar.oident == self._reg


def closure_context_vvars(project, function, graph) -> list[int]:
    """The vvars that carry the closure context register into ``function`` (used, never defined)."""
    reg_name = CONTEXT_REGISTERS.get(project.arch.name)
    if reg_name is None or reg_name not in project.arch.registers:
        return []
    finder = _RegisterVVars(project.arch.registers[reg_name][0])
    for block in graph.nodes:
        finder.walk(block)
    return sorted(finder.used - finder.defined)


def collect_closure_context_hints(project, function, graph, type_lifter) -> dict[int, TypeConstant]:
    """
    Type hints for the closure context register of a closure body whose parent recorded the closure record
    (``kb.go_signatures.closure_context``): the undefined context vvars are pointers to that record.
    """
    sigs = project.kb.go_signatures
    type_str = sigs.closure_context(function.addr)
    if type_str is None:
        return {}
    vvars = closure_context_vvars(project, function, graph)
    if not vvars:
        return {}
    try:
        lifted = type_lifter.lift(sigs.type("*" + type_str).with_arch(project.arch))
    except Exception:  # pylint:disable=broad-exception-caught
        l.debug("Cannot lift the closure record %r", type_str, exc_info=True)
        return {}
    if isinstance(lifted, (BottomType, TopType)):
        return {}
    return dict.fromkeys(vvars, lifted)
