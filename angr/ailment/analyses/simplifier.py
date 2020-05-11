
from typing import Set, Dict, Any
from collections import defaultdict

from angr import Analysis, AnalysesHub
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.sim_variable import SimStackVariable
from angr.analyses.propagator.propagator import Equivalence
from angr.knowledge_plugins.key_definitions import atoms
from angr.knowledge_plugins.key_definitions.definition import Definition

from ..block import Block
from ..statement import Statement, Assignment, Store, Call
from ..expression import Register, Convert, Load, StackBaseOffset


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

        self._unify_variables()
        self._remove_dead_assignments()

    def _unify_variables(self):

        # find variables that are definitely equivalent and then eliminate the unnecessary copies
        prop = self.project.analyses.Propagator(func=self.func, func_graph=self.func_graph)
        if not prop.equivalence:
            return

        addr2block: Dict[int, Block] = { }
        for block in self.func_graph.nodes():
            addr2block[block.addr] = block

        # for now, we focus on unifying registers and stack variables
        for eq in prop.equivalence:
            eq: Equivalence
            if isinstance(eq.atom0, SimStackVariable):
                if isinstance(eq.atom1, Register):
                    # stack_var == register
                    reg = eq.atom1
                elif isinstance(eq.atom1, Convert) and isinstance(eq.atom1.operand, Register):
                    # stack_var == Conv(register, M->N)
                    reg = eq.atom1.operand
                else:
                    continue

                # find the definition of this register
                the_def = None
                defs = self._reaching_definitions.all_uses.get_uses_by_location(eq.codeloc)
                for def_ in defs:
                    def_: Definition
                    if isinstance(def_.atom, atoms.Register) and def_.atom.reg_offset == reg.reg_offset:
                        # found it!
                        the_def = def_
                        break

                if the_def is None:
                    continue
                if isinstance(the_def.codeloc, ExternalCodeLocation):
                    continue

                # find all uses of this definition
                all_uses: Set[CodeLocation] = self._reaching_definitions.all_uses.get_uses(the_def)

                # TODO: We can only replace all these uses with the stack variable if the stack variable isn't
                # TODO: re-assigned of a new value. Perform this check.

                # replace all uses
                for u in all_uses:
                    if u == eq.codeloc:
                        # skip the very initial assignment location
                        continue
                    old_block = addr2block.get(u.block_addr, None)
                    if old_block is None:
                        continue

                    # if there is an update block, use that
                    the_block = self.blocks.get(old_block, old_block)

                    stmt: Statement = the_block.statements[u.stmt_idx]

                    # create the memory loading expression
                    stackvar = Load(None, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset), eq.atom0.size,
                                    endness=self.project.arch.memory_endness)

                    replaced, new_stmt = stmt.replace(eq.atom1, stackvar)
                    if replaced:
                        new_block = the_block.copy()
                        new_block.statements = the_block.statements[::]
                        new_block.statements[u.stmt_idx] = new_stmt
                        self.blocks[old_block] = new_block

    def _remove_dead_assignments(self):

        stmts_to_remove_per_block = defaultdict(set)

        # Find all statements that should be removed

        for def_ in self._reaching_definitions.all_definitions:  # type: Definition
            if def_.dummy:
                continue
            # we do not remove references to global memory regions no matter what
            if isinstance(def_.atom, atoms.MemoryLocation) and isinstance(def_.atom.addr, int):
                continue
            if not self._remove_dead_memdefs and isinstance(def_.atom, atoms.MemoryLocation):
                continue
            uses = self._reaching_definitions.all_uses.get_uses(def_)

            if not uses:
                stmts_to_remove_per_block[def_.codeloc.block_addr].add(def_.codeloc.stmt_idx)

        # Remove the statements
        for old_block in self.func_graph.nodes():

            # if there is an updated block, use it
            block = self.blocks.get(old_block, old_block)

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
            self.blocks[old_block] = new_block


AnalysesHub.register_default("AILSimplifier", Simplifier)
