from ailment import Const, AILBlockWalker, Block
from ailment.statement import Call, Statement

from ..utils.library import normalize
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage


class LibFunctionIdentifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
    NAME = "Identify Rust lib functions and assign pre-defined prototypes"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _extract_target(self, stmt):
        if isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
            return self.kb.functions[stmt.target.value]
        return None

    def _analyze(self, cache=None):
        librust = self.project.kb.librust

        class CallWalker(AILBlockWalker):
            def __init__(self, pass_):
                super().__init__()
                self._pass = pass_
                self.prototype = None
                self.cc = None

            def _handle_Call_Unified(self, call: Call):
                target = self._pass._extract_target(call)
                if target is not None:
                    normalized_name = normalize(target.name, monopolize=True)
                    if librust.has_prototype(normalized_name):
                        self.prototype = librust.get_prototype(normalized_name).with_arch(self._pass.project.arch)
                        self.cc = target.calling_convention

            def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
                self._handle_Call_Unified(stmt)

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                self._handle_Call_Unified(expr)

        for block in list(self._graph.nodes()):
            walker = CallWalker(self)
            walker.walk(block)
            self.kb.callsite_prototypes.set_prototype(block.addr, walker.cc, walker.prototype, True)
