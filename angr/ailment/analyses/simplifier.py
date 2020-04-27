
from collections import defaultdict

from angr import Analysis, AnalysesHub
from angr.engines.light.data import SpOffset
from angr.analyses.reaching_definitions import atoms
from angr.analyses.reaching_definitions.definition import Definition
from angr.analyses.reaching_definitions.constants import OP_AFTER

from ..block import Block
from ..statement import Assignment, Store, Call


class Simplifier(Analysis):
    """
    Perform function-level simplifications.
    """
    def __init__(self, func, func_graph=None, remove_dead_memdefs=False, reaching_definitions=None):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions = reaching_definitions

        self._remove_dead_memdefs = remove_dead_memdefs

        self.blocks = {}  # Mapping nodes to simplified blocks

        self._simplify()

    def _simplify(self):

        self._remove_dead_assignments()

    def _remove_dead_assignments(self):

        stmts_to_remove_per_block = defaultdict(set)

        # Find all statements that should be removed

        for def_ in self._reaching_definitions.all_definitions:
            if def_.dummy:
                continue
            # we do not remove references to global memory regions no matter what
            if isinstance(def_.atom, atoms.MemoryLocation):
                continue
            if not self._remove_dead_memdefs and isinstance(def_.atom, (atoms.MemoryLocation, SpOffset)):
                continue
            uses = self._reaching_definitions.all_uses.get_uses(def_)

            if not uses:
                stmts_to_remove_per_block[def_.codeloc.block_addr].add(def_.codeloc.stmt_idx)

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
