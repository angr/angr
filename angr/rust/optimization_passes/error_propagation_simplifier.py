from ailment import Block, Assignment, Const, AILBlockWalkerBase
from ailment.expression import VirtualVariable
from ailment.statement import Label, Return, Jump, Call

from angr.rust.sim_type import RustSimTypeResult
from angr.analyses.decompiler.optimization_passes import OptimizationPassStage
from angr.analyses.decompiler.optimization_passes.optimization_pass import SequenceOptimizationPass
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import SequenceNode
from angr.rust.structuring.structurer_nodes import PatternMatchNode
from angr.utils.ssa import VVarUsesCollector


class ErrorPropagationWalker(SequenceWalker):
    def __init__(self, context: "ErrorPropagationSimplifier"):
        super().__init__()
        self.context = context
        self.dead_assignments = set()

    @staticmethod
    def _is_safe_block(block: Block):
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

    @staticmethod
    def _contains_addr(node, block_addr, block_idx):
        class Temp:
            found = False

        def callback(node, **kwargs):
            if node.addr == block_addr and node.idx == block_idx:
                Temp.found = True

        SequenceWalker(handlers={Block: callback}).walk(node)

        return Temp.found

    def _is_dead_assignment(self, new_dst_vvar, pattern_match_node, err_node):
        collector = VVarUsesCollector()
        for block in self.context._graph.nodes:
            collector.walk(block)
        uses = collector.vvar_and_uselocs[new_dst_vvar.varid]
        return all(
            self._contains_addr(err_node, use.block_addr, use.block_idx) or use.ins_addr == pattern_match_node.addr
            for vvar, use in uses
        )

    def _handle_PatternMatch(self, node: PatternMatchNode, **kwargs):
        err_node, ok_node = None, None
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

        if isinstance(node.scrutinee, VirtualVariable):
            if node.scrutinee.was_combo_reg:
                new_dst_vvar = node.scrutinee.reg_vvars[1]
            elif node.scrutinee.was_reg:
                new_dst_vvar = node.scrutinee

        if err_node and ok_node and self._is_early_return(err_node):
            if isinstance(node.scrutinee, VirtualVariable) and node.scrutinee.varid in self.context.varid_to_assignment:
                assignment = self.context.varid_to_assignment[node.scrutinee.varid]
                assignment.src.tags["propagates_error"] = True

                if new_dst_vvar and self._is_dead_assignment(new_dst_vvar, node, err_node):
                    self.dead_assignments.add(assignment)
                    new_dst_vvar = None

                if new_dst_vvar:
                    assignment.dst = new_dst_vvar
                new_ok_node = super()._handle(ok_node)
                return new_ok_node or ok_node
            elif isinstance(node.scrutinee, Call):
                node.scrutinee.tags["propagates_error"] = True
                new_ok_node = super()._handle(ok_node)
                return new_ok_node or ok_node

        return super()._handle_PatternMatch(node, **kwargs)


class ErrorPropagationSimplifier(SequenceOptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = 'Recover error propagation "?" operator'

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph")
        self.block_by_addr_and_idx = {(block.addr, block.idx): block for block in self._graph.nodes}
        self.varid_to_assignment = self._collect_varid_to_assignment_mappings()

        self.analyze()

    def _check(self):
        return bool(self.seq.nodes), None

    def _collect_varid_to_assignment_mappings(self):
        varid_to_assignment = {}

        def callback(stmt_idx, stmt: Assignment, block):
            if (
                isinstance(stmt.dst, VirtualVariable)
                and isinstance(stmt.src, Call)
                and stmt.src.prototype
                and isinstance(stmt.src.prototype.returnty, RustSimTypeResult)
            ):
                varid_to_assignment[stmt.dst.varid] = stmt

        walker = AILBlockWalkerBase(stmt_handlers={Assignment: callback})

        for block in self._graph.nodes:
            walker.walk(block)

        return varid_to_assignment

    def _remove_dead_assignments(self, stmts):
        def callback(block, **kwargs):
            changed = False
            new_stmts = []
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.src, Call) and stmt in stmts:
                    stmt = stmt.src
                    changed = True
                new_stmts.append(stmt)
            if changed:
                block.statements = new_stmts

        walker = SequenceWalker(handlers={Block: callback})
        walker.walk(self.seq)

        for block in self._graph.nodes:
            callback(block)

    def _analyze(self, cache=None):
        walker = ErrorPropagationWalker(self)
        walker.walk(self.seq)

        self._remove_dead_assignments(walker.dead_assignments)

        self.out_seq = self.seq
