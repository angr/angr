from ailment import Block, Assignment, Const
from ailment.expression import VirtualVariable
from ailment.statement import Label, Return, Jump, Call

from angr.rust.mixins import SRDAMixin
from angr.analyses.decompiler.optimization_passes import OptimizationPassStage
from angr.analyses.decompiler.optimization_passes.optimization_pass import SequenceOptimizationPass
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode
from angr.rust.structuring.structurer_nodes import PatternMatchNode


class ErrorPropagationWalker(SequenceWalker):
    def __init__(self, context: "ErrorPropagationSimplifier"):
        super().__init__()
        self.context = context

    def _is_safe_block(self, block: Block):
        for stmt in block.statements:
            if not (
                isinstance(stmt, Label)
                or (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg)
                or isinstance(stmt, Jump)
            ):
                return False
        return True

    def _is_early_return_block(self, block, visited=None):
        if visited and block in visited:
            return False
        if visited is None:
            visited = set()
        visited.add(block)
        for stmt in block.statements:
            if isinstance(stmt, Jump) and isinstance(stmt.target, Const):
                key = (stmt.target.value, stmt.target_idx)
                if key in self.context.block_by_addr_and_idx:
                    next_block = self.context.block_by_addr_and_idx[key]
                    return self._is_early_return_block(next_block, visited)
            if not (
                isinstance(stmt, Label)
                or (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg)
                or isinstance(stmt, Return)
            ):
                return False
        return True

    def _is_early_return(self, node):
        if isinstance(node, Block):
            return self._is_early_return_block(node)
        elif isinstance(node, SequenceNode):
            nodes = node.nodes
            if nodes and isinstance(nodes[-1], Block):
                if self._is_early_return(nodes[-1]):
                    return all(isinstance(block, Block) and self._is_safe_block(block) for block in nodes[:-1])
        return False

    def _handle_PatternMatch(self, node: PatternMatchNode, **kwargs):
        err_node = None
        ok_node = None
        new_dst_vvar = None
        for (variant, move_stmts), arm in node.arms.items():
            if variant.name == "Err":
                err_node = arm
            elif variant.name == "Ok":
                ok_node = arm
                if (
                    move_stmts
                    and isinstance(move_stmts[0], Assignment)
                    and isinstance(move_stmts[0].dst, VirtualVariable)
                ):
                    new_dst_vvar = move_stmts[0].dst
        if err_node and ok_node and new_dst_vvar and self._is_early_return(err_node):
            call = self.context.get_terminal_vvar_value(node.scrutinee)
            if isinstance(call, Call):
                call.tags["unwrapped_vvar"] = new_dst_vvar
                new_ok_node = super()._handle(ok_node)
                return new_ok_node or ok_node
        return super()._handle_PatternMatch(node, **kwargs)


class ErrorPropagationSimplifier(SequenceOptimizationPass, SRDAMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = 'Recover error propagation "?" operator'

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph")
        SRDAMixin.__init__(self, self._func, self._graph, self.project)
        self.block_by_addr_and_idx = {(block.addr, block.idx): block for block in self._graph.nodes}
        self.analyze()

    def _check(self):
        return bool(self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = ErrorPropagationWalker(self)
        walker.walk(self.seq)
        self.out_seq = self.seq
