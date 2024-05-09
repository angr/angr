import ailment

from .utils import extract_callee, extract_rust_function_name
from ... import SIM_LIBRARIES
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

    def _analyze(self, cache=None):
        librust = SIM_LIBRARIES["librust"]
        for block in list(self._graph.nodes()):
            new_stmts = []
            for stmt in block.statements:
                new_stmt = stmt
                if isinstance(stmt, ailment.Stmt.Call):
                    demangled_name = extract_rust_function_name(extract_callee(stmt, self.kb))
                    if librust.has_prototype(demangled_name):
                        prototype = librust.get_prototype(demangled_name).with_arch(self.project.arch)
                        new_stmt = ailment.Stmt.Call(
                            stmt.idx,
                            stmt.target,
                            stmt.calling_convention,
                            prototype,
                            stmt.args,
                            stmt.ret_expr if prototype.returnty else None,
                            stmt.fp_ret_expr,
                            **stmt.tags,
                        )
                        extract_callee(stmt, self.kb).prototype = prototype
                        new_stmt.prototype = prototype
                new_stmts.append(new_stmt)
            block.statements = new_stmts
