from angr.ailment.expression import VirtualVariable
from angr.ailment.statement import Label, Jump, Assignment, ConditionalJump

from angr.rust.mixins import CFAMixin, CFGTransformationMixin
from angr.rust.utils.ail import has_call
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.utils.ssa import VVarUsesCollector


class RedundantBlockRemover(OptimizationPass, CFAMixin, CFGTransformationMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_REGION_IDENTIFICATION
    NAME = "Remove redundant blocks that have no effect on functionality"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        CFAMixin.__init__(self, self._graph, self.project)
        CFGTransformationMixin.__init__(self, self._graph)

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _transform_graph_from_ssa(self, graph):
        dephication = self.project.analyses.GraphDephication(self._func, graph, rewrite=True, kb=self.kb)
        return dephication.output

    def _remove_redundant_blocks(self, dephicate=False):
        # Remove dead statements
        if dephicate:
            self._graph = self._transform_graph_from_ssa(self._graph)
            self.update_block_indexes()
        removed = True
        while removed:
            removed = False
            collector = VVarUsesCollector()
            for block in self._graph.nodes:
                collector.walk(block)
            uses = collector.vvar_and_uselocs
            blocks_to_remove = set()
            for block in self._graph.nodes:
                if block.addr == self._func.addr:
                    continue
                if all(
                    (
                        isinstance(stmt, (Label, Jump, ConditionalJump))
                        or (
                            isinstance(stmt, Assignment)
                            and isinstance(stmt.dst, VirtualVariable)
                            and all(
                                codeloc.block_addr == block.addr and codeloc.block_idx == block.idx
                                for vvar, codeloc in uses[stmt.dst.varid]
                            )
                        )
                    )
                    and not has_call(stmt, include_macro=True)
                    for stmt in block.statements
                ):
                    blocks_to_remove.add(block)
            for block in blocks_to_remove:
                removed = self.remove_block(block) or removed

    def _analyze(self, cache=None):
        self._remove_redundant_blocks()
        self._remove_redundant_blocks(dephicate=True)
        self.out_graph = self._graph
