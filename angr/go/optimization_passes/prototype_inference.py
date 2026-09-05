from __future__ import annotations

import logging

from angr.ailment.expression import Call, Struct, VirtualVariable
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimType, GoSimTypeFunction, go_type_repr

l = logging.getLogger(__name__)


class GoPrototypeInference(OptimizationPass):
    """
    Infer the parameter types of a function nobody names (no DWARF, not in the signature database, not a method)
    from how its parameters reach callees whose prototypes are known: a parameter word passed where a callee takes
    an ``int`` is an int, two consecutive words fused into ``io.Writer`` for a callee are an ``io.Writer``.

    The result is recorded in ``kb.go_signatures`` as an inferred signature; it takes effect the next time the
    function is decompiled (the argument variables are created before any pass runs).
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Infer Go parameter types from typed callees"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        if not self.project.is_go_binary or self._arg_vvars is None:
            return False, None
        # only functions still on a guessed prototype
        return self._func.is_prototype_guessed, None

    def _analyze(self, cache=None):
        words: dict[int, int] = {}  # param vvar varid -> word index
        for index, (vvar, _arg) in sorted(self._arg_vvars.items(), key=lambda kv: kv[0]):
            if isinstance(vvar, VirtualVariable) and not vvar.was_combo_reg:
                words[vvar.varid] = len(words)
        if not words:
            return
        found: dict[int, tuple[str, int]] = {}  # word -> (type string, words spanned)
        variable_map = variable_map_of(self.manager)
        for block in self._graph.nodes:
            for stmt in block.statements:
                call = None
                if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                    call = stmt.src
                elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                    call = stmt.expr
                if call is None or not call.args:
                    continue
                proto = self._callee_prototype(call, variable_map)
                if proto is None:
                    continue
                for arg, ty in zip(call.args, proto.args):
                    if not isinstance(ty, GoSimType) or not ty.size:
                        continue
                    span = ty.size // self.project.arch.bits
                    if isinstance(arg, VirtualVariable) and arg.varid in words and span == 1:
                        self._record(found, words[arg.varid], go_type_repr(ty), 1)
                    elif isinstance(arg, Struct) and span >= 2:
                        pieces = [arg.fields[off] for off in sorted(arg.fields)]
                        if len(pieces) != span or not all(
                            isinstance(p, VirtualVariable) and p.varid in words for p in pieces
                        ):
                            continue
                        idx = [words[p.varid] for p in pieces]
                        if idx == list(range(idx[0], idx[0] + span)):
                            self._record(found, idx[0], go_type_repr(ty), span)
        if not found:
            return
        # assemble the parameter list: typed groups where known, the guessed word type elsewhere
        types: list[str] = []
        w = 0
        while w < len(words):
            hit = found.get(w)
            if hit is not None:
                types.append(hit[0])
                w += hit[1]
            else:
                types.append("uintptr")
                w += 1
        self.kb.go_signatures.set_inferred(self._func.name, types)
        l.debug("Inferred %s(%s) from its callees", self._func.name, ", ".join(types))

    @staticmethod
    def _record(found: dict, word: int, type_str: str, span: int) -> None:
        # a conflicting earlier guess wins only if it is wider (an interface over its first word as an int)
        old = found.get(word)
        if old is None or old[1] < span:
            found[word] = (type_str, span)

    def _callee_prototype(self, call: Call, variable_map) -> GoSimTypeFunction | None:
        proto = variable_map.prototype(call)
        if isinstance(proto, GoSimTypeFunction):
            return proto
        target = call.target.value if hasattr(call.target, "value") else None
        if isinstance(target, int) and self.kb.functions.contains_addr(target):
            proto = self.kb.functions.get_by_addr(target, meta_only=True).prototype
            if isinstance(proto, GoSimTypeFunction):
                return proto
        return None
