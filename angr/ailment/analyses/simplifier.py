
from collections import defaultdict

from angr import Analysis, AnalysesHub
from angr.analyses.reaching_definitions.definition import Definition
from angr.analyses.reaching_definitions.constants import OP_AFTER

from ..block import Block
from ..statement import Assignment, Store, Call


class Simplifier(Analysis):
    """
    Perform function-level simplifications.
    """
    def __init__(self, func, func_graph=None, reaching_definitions=None):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions = reaching_definitions

        self.blocks = {}  # Mapping nodes to simplified blocks

        self._simplify()

    def _simplify(self):

        self._remove_dead_assignments()

    def _remove_dead_assignments(self):

        stmts_to_remove_per_block = defaultdict(set)

        # Find all statements that should be removed
        for block in self.func_graph.nodes():
            if not isinstance(block, Block):
                # Skip all blocks that are not AIL blocks
                continue
            if not block.statements:
                # Skip all empty blocks
                continue
            rd = self._reaching_definitions.get_reaching_definitions_by_node(block.addr, OP_AFTER)
            if rd is None:
                continue
            dead_defs = rd._dead_virgin_definitions

            for dead_def in dead_defs:  # type: Definition
                if dead_def.dummy:
                    continue
                stmts_to_remove_per_block[dead_def.codeloc.block_addr].add(dead_def.codeloc.stmt_idx)

        # Remove the statements
        for block in self.func_graph.nodes():
            if not isinstance(block, Block):
                continue

            if block.addr not in stmts_to_remove_per_block:
                continue

            new_statements = [ ]
            stmts_to_remove = stmts_to_remove_per_block[block.addr]

            for idx, stmt in enumerate(block.statements):
                if idx in stmts_to_remove:
                    if isinstance(stmt, (Assignment, Store)):
                        # Skip Assignment and Store statements
                        continue
                    elif isinstance(stmt, Call):
                        # the return expr is not used. it should not have return expr
                        stmt = stmt.copy()
                        stmt.ret_expr = None
                    else:
                        # Should not happen!
                        raise NotImplementedError()

                new_statements.append(stmt)

            new_block = block.copy()
            new_block.statements = new_statements

            self.blocks[block] = new_block


AnalysesHub.register_default("AILSimplifier", Simplifier)
