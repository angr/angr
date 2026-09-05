from __future__ import annotations

import logging
import re

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.structured_codegen.c import type_equals
from angr.calling_conventions import GO_ABI0_CC, default_cc_for_project
from angr.go.sim_type import GoSimStruct
from angr.go.utils.names import call_target_name
from angr.knowledge_plugins.functions.function import Function, PrototypeSource
from angr.sim_type import SimTypeFunction
from angr.utils.ail import CallFinder

l = logging.getLogger(__name__)

# prototypes from signatures beat everything the decompiler infers, but never a user-supplied one
_SOURCE = PrototypeSource.SIGNATURES


_METHOD_NAME = re.compile(r"^(?P<pkg>.+?)\.(?P<ptr>\(\*)?(?P<type>[^.()/]+)\)?\.(?P<method>[^.()/]+)$")
_CLOSURE_NAME = re.compile(r"^(func|deferwrap|gowrap)\d+$")


def receiver_type_from_name(kb, arch, name: str):
    """
    ``pkg.(*T).M`` -> the SimType of ``*pkg.T``; ``pkg.T.M`` -> ``pkg.T`` when it is one word wide. ``T`` must be
    a type the binary describes. Closures (``.func1``) and plain functions give None.
    """
    m = _METHOD_NAME.match(name)
    if m is None or ("(" in name) != (m.group("ptr") is not None) or _CLOSURE_NAME.match(m.group("method")):
        return None
    tyname = f"{m.group('pkg')}.{m.group('type')}"
    if kb.go_signatures.named_type(tyname) is None:
        return None
    try:
        ty = kb.go_signatures.type(("*" if m.group("ptr") else "") + tyname)
    except Exception:  # pylint:disable=broad-exception-caught
        return None
    if ty is None or (not m.group("ptr") and (isinstance(ty, GoSimStruct) or ty.size != arch.bits)):
        # value receivers: only one-word named scalars; structs by value would send the stack-based
        # conventions through struct-location refinement they cannot always satisfy
        return None
    return ty.with_arch(arch)


class GoPrototypes(OptimizationPass):
    """
    Give the current function and its callees their Go prototypes (from DWARF, the stdlib signature database or an
    external source registered on kb.go_signatures) before return sites, argument lists and call sites are built.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_AIL_GRAPH_CREATION
    NAME = "Apply known Go prototypes"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self.kb.go_signatures.load_sources()

        self._apply(self._func)

        finder = CallFinder()
        seen: set[int] = set()
        for block in self._graph.nodes:
            for stmt in block.statements:
                finder.call = None
                finder.walk_statement(stmt, block)
                call = finder.call
                if call is None:
                    continue
                name = call_target_name(self.project, call)
                if name is None or not self.kb.functions.contains_addr(call.target.value_int):
                    continue
                callee = self.kb.functions.get_by_addr(call.target.value_int)
                if callee.addr in seen:
                    continue
                seen.add(callee.addr)
                self._apply(callee)

    def _bound_guess(self, func: Function) -> bool:
        """
        No signature source names ``func``: keep the guessed prototype but drop the parameters beyond what the
        pclntab says the function takes (its ``args`` size in bytes, results excluded), so a guess of nine integers
        for a two-word function does not become seven junk arguments at every call site.
        """
        proto = func.prototype
        if proto is None or not func.is_prototype_guessed:
            return False
        size = self.kb.go_signatures.arg_size_at(func.addr)
        words = len(proto.args) if size is None else size // self.project.arch.bytes
        args = list(proto.args[:words])
        changed = len(proto.args) > words
        recv = receiver_type_from_name(self.kb, self.project.arch, func.name)
        if recv is not None and args and not type_equals(args[0], recv):
            # the receiver of a method is spelled out in its name; the linker may have pruned it from the method table
            args[0] = recv
            changed = True
        if not changed:
            return False
        func.prototype = SimTypeFunction(
            args, proto.returnty, arg_names=list(proto.arg_names[:words]) if proto.arg_names else None
        ).with_arch(self.project.arch)
        if recv is not None:
            # a known receiver is worth keeping through variable recovery: promote the prototype out of "guessed"
            cc_cls = default_cc_for_project(self.project)
            if cc_cls is not None and not isinstance(func.calling_convention, cc_cls):
                func.calling_convention = cc_cls(self.project.arch)
            func.prototype_source = _SOURCE
        return True

    def _apply(self, func: Function) -> bool:
        if func.prototype is not None and func.prototype_source.value > _SOURCE.value:
            return False
        proto = self.kb.go_signatures.prototype(func.name)
        if proto is None:
            proto = self.kb.go_signatures.prototype_at(func.addr)
        if proto is None and func.prototype is not None:
            proto = self.kb.go_signatures.inferred_prototype(func.name, func.prototype.returnty)
        if proto is None:
            return self._bound_guess(func)
        cc_cls = (
            GO_ABI0_CC.get(self.project.arch.name)
            if func.name.endswith(".abi0")
            else default_cc_for_project(self.project)
        )
        if cc_cls is None:
            return False
        if func.calling_convention is None or not isinstance(func.calling_convention, cc_cls):
            func.calling_convention = cc_cls(self.project.arch)
        func.prototype = proto
        func.prototype_source = _SOURCE
        l.debug("Applied Go prototype to %s: %s", func.name, proto.repr(func.name))
        return True
