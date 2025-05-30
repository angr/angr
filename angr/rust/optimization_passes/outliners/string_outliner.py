from angr.ailment import AILBlockWalker, Block
from angr.ailment.expression import Const, Struct
from angr.ailment.statement import Assignment, Call
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass


class StringOutliner(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline String::new()"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        def callback(stmt_idx, stmt: Assignment, block):
            if isinstance(stmt.src, Struct) and stmt.src.name == "String":
                cnt = len(list(filter(lambda ele: isinstance(ele, Const) and ele.value == 0, stmt.src.fields.values())))
                if cnt >= 2:
                    call = Call(
                        idx=None,
                        target="String::new",
                        prototype=self.kb.librust.get_prototype("String::new").with_arch(self.project.arch).normalize(),
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

        class StringStructWalker(AILBlockWalker):

            def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Assignment | None:
                return callback(stmt_idx, stmt, block)

        walker = StringStructWalker()
        for block in self._graph.nodes:
            walker.walk(block)

        self.out_graph = self._graph
