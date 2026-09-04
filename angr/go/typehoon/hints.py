from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.ailment.expression import Call, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses.typehoon.typeconsts import BottomType, TopType
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
