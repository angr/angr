"""Apply call-site information (prototypes) for known-pattern calls.

Known-pattern calls are identified by their string target, which is stable
across Clinic runs; the VariableMap holding prototypes is scoped to a single
Clinic run. This helper (re)applies the prototypes onto a graph's calls so
that variable recovery emits per-argument type constraints for Typehoon. It is
used by the KnownPatternOutliner optimization pass (which runs after the
peephole stages) and mirrors what the KnownPatternCallInfo peephole does for
graphs that already contain known-pattern calls at the start of a run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment.expression import Call
from angr.analyses.decompiler.variable_map import variable_map_of

if TYPE_CHECKING:
    import networkx

    from angr.ailment.manager import Manager
    from angr.project import Project


def prototype_for_call(project: Project, call: Call):
    """The ctx-instantiated prototype for a known-pattern call, or None. The
    return-type width and argument pointer sizes follow the target's
    PatternContext."""
    from . import TEMPLATE_BY_CALL_NAME  # pylint:disable=import-outside-toplevel
    from .context import PatternContext  # pylint:disable=import-outside-toplevel

    if not isinstance(call.target, str):
        return None
    template = TEMPLATE_BY_CALL_NAME.get(call.target)
    if template is None:
        return None
    ctx = PatternContext.from_project(project)
    pattern = template.instantiate(ctx)
    if pattern is None:
        return None
    return pattern.prototype(project.arch, const_args=pattern.const_args_of_call(call))


def apply_call_info_to_graph(graph: networkx.DiGraph, manager: Manager, project: Project) -> int:
    """Set the call-site prototype of every known-pattern call in ``graph`` in
    the VariableMap attached to ``manager``. Returns the number of calls that
    received a prototype."""
    from .finder import _iter_stmt_subexprs  # pylint:disable=import-outside-toplevel

    variable_map = variable_map_of(manager)
    count = 0
    for block in graph:
        for stmt in block.statements:
            for _, expr in _iter_stmt_subexprs(stmt):
                if not isinstance(expr, Call) or not isinstance(expr.target, str):
                    continue
                prototype = prototype_for_call(project, expr)
                if prototype is not None:
                    variable_map.set_prototype(expr, prototype)
                    count += 1
    return count
