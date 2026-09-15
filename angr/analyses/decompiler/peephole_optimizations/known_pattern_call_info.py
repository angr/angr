# pylint:disable=arguments-differ,no-self-use
from __future__ import annotations

from angr.ailment.expression import Call, VirtualVariable
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.knowledge_plugins.key_definitions import atoms

from .base import PeepholeOptimizationExprBase


class KnownPatternCallInfo(PeepholeOptimizationExprBase):
    """
    Attach call-site prototypes (and optional vvar type hints) to calls that
    were synthesized from KnownPatterns (see
    angr.analyses.decompiler.known_patterns).

    Known-pattern calls are identified by their string target, which is stable
    across Clinic runs, while the VariableMap holding prototypes is scoped to a
    single Clinic run; running as a peephole re-applies the prototype in every
    run so that variable recovery emits per-argument type constraints for
    Typehoon (e.g. ``arg <: std::string *`` for std::string::length).
    """

    __slots__ = ()

    NAME = "Attach prototypes and type hints to known-pattern calls"
    expr_classes = (Call,)

    def optimize(self, expr: Call, **kwargs):
        # import here: peephole modules load before the known_patterns package
        from angr.analyses.decompiler.known_patterns import (  # pylint:disable=import-outside-toplevel
            TEMPLATE_BY_CALL_NAME,
            PatternContext,
        )

        assert self.project is not None
        if not isinstance(expr.target, str):
            return None
        template = TEMPLATE_BY_CALL_NAME.get(expr.target)
        if template is None:
            return None
        pattern = template.instantiate(PatternContext.from_project(self.project))
        if pattern is None:
            return None

        variable_map = variable_map_of(self.manager)
        new_expr = None
        if expr.idx is None:
            # the call was synthesized outside any Clinic run and carries no
            # atom idx; re-mint one so the VariableMap can key its prototype
            new_expr = Call(
                self.manager.next_atom(),
                expr.target,
                args=expr.args,
                bits=expr.bits,
                **expr.tags,
            )
            key_expr = new_expr
        elif variable_map.prototype(expr) is None:
            key_expr = expr
        else:
            return None

        prototype = pattern.prototype(self.project.arch, const_args=pattern.const_args_of_call(expr))
        if prototype is not None:
            variable_map.set_prototype(key_expr, prototype)

        # optional direct vvar type hints for by-value captures
        if expr.args:
            for param, arg in zip(pattern.params, expr.args):
                if param.type_hint is not None and isinstance(arg, VirtualVariable):
                    self.preserve_vvar_ids.add(arg.varid)
                    atom = atoms.VirtualVariable(arg.varid, arg.size, arg.category, arg.oident)
                    self.type_hints.append((atom, param.type_hint))

        return new_expr
