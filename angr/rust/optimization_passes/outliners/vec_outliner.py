from angr.rust.sim_type import RustSimTypeFunction, RustSimTypeReference
from angr.ailment import AILBlockRewriter, Block
from angr.ailment.expression import Const, Struct, StringLiteral
from angr.ailment.statement import Assignment, Call
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass


class VecOutliner(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline Vec structs to `Vec::new`"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        def callback(stmt_idx, stmt: Assignment, block):
            if isinstance(stmt.src, Struct) and stmt.src.name.startswith("alloc::vec::Vec"):
                cap = stmt.src.get_field("buf.cap.__0") or stmt.src.get_field("buf.inner.cap.__0")
                _len = stmt.src.get_field("len")
                if (
                    isinstance(cap, Const)
                    and cap.value == 0
                    and isinstance(_len, Const)
                    and _len.value == 0
                    and "type" in stmt.src.tags
                ):
                    call = Call(
                        idx=None,
                        target=StringLiteral(None, "Vec::new", self.project.arch.bits),
                        prototype=RustSimTypeFunction(
                            args=[RustSimTypeReference(stmt.src.type)], returnty=None, is_arg0_retbuf=True
                        )
                        .with_arch(self.project.arch)
                        .normalize(),
                        args=[],
                        ret_expr=None,
                        **stmt.src.tags,
                    )
                    call.bits = 3 * self.project.arch.bits
                    new_stmt = stmt.copy()
                    new_stmt.src = call
                    block.statements[stmt_idx] = new_stmt
                    return new_stmt
            return None

        class StringStructWalker(AILBlockRewriter):

            def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Assignment | None:
                return callback(stmt_idx, stmt, block)

        walker = StringStructWalker()
        for block in self._graph.nodes:
            walker.walk(block)

        self.out_graph = self._graph
