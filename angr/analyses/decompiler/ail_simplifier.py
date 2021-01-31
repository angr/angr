from typing import Set, Dict, List, Tuple
from collections import defaultdict

from ailment.block import Block
from ailment.statement import Statement, Assignment, Store, Call
from ailment.expression import Register, Convert, Load, StackBaseOffset

from ...code_location import CodeLocation
from ...analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from ...sim_variable import SimStackVariable
from ...analyses.propagator.propagator import Equivalence
from ...knowledge_plugins.key_definitions import atoms
from ...knowledge_plugins.key_definitions.definition import Definition
from .. import Analysis, AnalysesHub
from .ailblock_walker import AILBlockWalker
from .block_simplifier import BlockSimplifier


class HasCallNotification(Exception):
    pass


class AILSimplifier(Analysis):
    """
    Perform function-level simplifications.
    """
    def __init__(self, func, func_graph=None, remove_dead_memdefs=False, unify_variables=False,
                 reaching_definitions=None):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions = reaching_definitions

        self._remove_dead_memdefs = remove_dead_memdefs
        self._unify_vars = unify_variables

        self._calls_to_remove: Set[CodeLocation] = set()
        self.blocks = {}  # Mapping nodes to simplified blocks

        self.simplified: bool = False
        self._simplify()

    def _simplify(self):

        folded_exprs = self._fold_exprs()
        self.simplified |= folded_exprs
        if folded_exprs:
            # reading definition analysis results are no longer reliable
            return

        if self._unify_vars:
            self.simplified |= self._unify_local_variables()
            # _fold_call_exprs() may set self._calls_to_remove, which will be honored in _remove_dead_assignments()
            self.simplified |= self._fold_call_exprs()

        self.simplified |= self._remove_dead_assignments()

    def _fold_exprs(self):
        """
        Fold expressions: Fold assigned expressions that are only used once.
        """

        # propagator
        propagator = self.project.analyses.Propagator(func=self.func, func_graph=self.func_graph)
        replacements = list(propagator._states.values())[0]._replacements

        # take replacements and rebuild the corresponding blocks
        replacements_by_block_addrs_and_idx = defaultdict(dict)
        for codeloc, reps in replacements.items():
            if reps:
                replacements_by_block_addrs_and_idx[(codeloc.block_addr, codeloc.block_idx)][codeloc] = reps

        if not replacements_by_block_addrs_and_idx:
            return False

        blocks_by_addr_and_idx = dict(((node.addr, node.idx), node) for node in self.func_graph.nodes())

        for (block_addr, block_idx), reps in replacements_by_block_addrs_and_idx.items():
            block = blocks_by_addr_and_idx[(block_addr, block_idx)]
            new_block = BlockSimplifier._replace_and_build(block, reps)
            self.blocks[block] = new_block

        return True

    def _unify_local_variables(self) -> bool:
        """
        Find variables that are definitely equivalent and then eliminate the unnecessary copies.
        """

        simplified = False

        prop = self.project.analyses.Propagator(func=self.func, func_graph=self.func_graph)
        if not prop.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int,int], Block] = { }
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        for eq in prop.equivalence:
            eq: Equivalence

            # Acceptable equivalence classes:
            #
            # stack variable == register
            # register variable == register
            # stack variable == Conv(register, M->N)
            #
            the_def = None
            if isinstance(eq.atom0, SimStackVariable):
                if isinstance(eq.atom1, Register):
                    # stack_var == register
                    reg = eq.atom1
                elif isinstance(eq.atom1, Convert) and isinstance(eq.atom1.operand, Register):
                    # stack_var == Conv(register, M->N)
                    reg = eq.atom1.operand
                else:
                    continue

            elif isinstance(eq.atom0, Register):
                if isinstance(eq.atom1, Register):
                    # register == register
                    reg = eq.atom1
                else:
                    continue

            else:
                continue

            # find the definition of this register
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
            # we make a copy of the set since we may touch the set (uses) when replacing expressions
            all_uses: Set[CodeLocation] = set(self._reaching_definitions.all_uses.get_uses(the_def))

            # TODO: We can only replace all these uses with the stack variable if the stack variable isn't
            # TODO: re-assigned of a new value. Perform this check.

            # replace all uses
            for u in all_uses:
                if u == eq.codeloc:
                    # skip the very initial assignment location
                    continue
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue

                # if there is an updated block, use it
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                if isinstance(eq.atom0, SimStackVariable):
                    # create the memory loading expression
                    dst = Load(None, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset), eq.atom0.size,
                               endness=self.project.arch.memory_endness)
                elif isinstance(eq.atom0, Register):
                    dst = eq.atom0
                else:
                    raise RuntimeError("Unsupported atom0 type %s." % type(eq.atom0))

                r, new_block = self._replace_expr_and_update_block(the_block, u.stmt_idx, stmt, the_def, u, eq.atom1,
                                                                   dst)
                if r:
                    self.blocks[old_block] = new_block
                simplified |= r

        return simplified

    def _fold_call_exprs(self) -> bool:
        """
        Fold a call expression (statement) into other statements if the return value of the call expression (statement)
        is only used once, and the use site and the call site belongs to the same supernode.

        Example::

            s0 = func();
            if (s0) ...

        after folding, it will be transformed to::

            if (func()) ...
        """

        simplified = False

        prop = self.project.analyses.Propagator(func=self.func, func_graph=self.func_graph)
        if not prop.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int,int], Block] = { }
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        for eq in prop.equivalence:
            eq: Equivalence

            # register variable == Call
            if isinstance(eq.atom0, Register):
                if isinstance(eq.atom1, Call):
                    # register variable = Call
                    call = eq.atom1
                else:
                    continue

                # find the definition of this register
                defs = [ d for d in self._reaching_definitions.all_definitions
                         if d.codeloc == eq.codeloc
                         and isinstance(d.atom, atoms.Register)
                         and d.atom.reg_offset == eq.atom0.reg_offset
                         ]
                if not defs or len(defs) > 1:
                    continue
                the_def: Definition = defs[0]

                # find all uses of this definition
                all_uses: Set[CodeLocation] = set(self._reaching_definitions.all_uses.get_uses(the_def))

                if len(all_uses) != 1:
                    continue
                u = next(iter(all_uses))

                # check if the use and the definition is within the same supernode
                super_node_blocks = self._get_super_node_blocks(
                    addr_and_idx_to_block[(the_def.codeloc.block_addr, the_def.codeloc.block_idx)]
                )
                if u.block_addr not in set(b.addr for b in super_node_blocks):
                    continue

                # replace all uses
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue

                # if there is an updated block, use that
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                if isinstance(eq.atom0, Register):
                    src = eq.atom0
                    dst = call
                else:
                    continue

                replaced, new_block = self._replace_expr_and_update_block(the_block, u.stmt_idx, stmt, the_def, u, src,
                                                                          dst)

                if replaced:
                    self.blocks[old_block] = new_block
                    # this call has been folded to the use site. we can remove this call.
                    self._calls_to_remove.add(eq.codeloc)
                    simplified = True

        return simplified

    def _get_super_node_blocks(self, start_node: Block) -> List[Block]:

        lst: List[Block] = [ start_node ]
        while True:
            b = lst[-1]
            successors = list(self.func_graph.successors(b))
            if len(successors) == 0:
                break
            if len(successors) == 1:
                succ = successors[0]
                # check its predecessors
                succ_predecessors = list(self.func_graph.predecessors(succ))
                if len(succ_predecessors) == 1:
                    lst.append(succ)
                else:
                    break
            else:
                # too many successors
                break
        return lst

    def _replace_expr_and_update_block(self, block, stmt_idx, stmt, the_def, codeloc, src_expr,
                                       dst_expr) -> Tuple[bool,Block]:
        replaced, new_stmt = stmt.replace(src_expr, dst_expr)
        if replaced:
            new_block = block.copy()
            new_block.statements = block.statements[::]
            new_block.statements[stmt_idx] = new_stmt

            # update the uses
            self._reaching_definitions.all_uses.remove_use(the_def, codeloc)
            return True, new_block

        return False, None

    def _remove_dead_assignments(self) -> bool:

        stmts_to_remove_per_block: Dict[Tuple[int,int],Set[int]] = defaultdict(set)

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
                stmts_to_remove_per_block[(def_.codeloc.block_addr, def_.codeloc.block_idx)].add(def_.codeloc.stmt_idx)

        simplified = False

        # Remove the statements
        for old_block in self.func_graph.nodes():

            # if there is an updated block, use it
            block = self.blocks.get(old_block, old_block)

            if not isinstance(block, Block):
                continue

            if (block.addr, block.idx) not in stmts_to_remove_per_block:
                continue

            new_statements = [ ]
            stmts_to_remove = stmts_to_remove_per_block[(block.addr, block.idx)]

            if not stmts_to_remove:
                continue

            for idx, stmt in enumerate(block.statements):
                if idx in stmts_to_remove:
                    if isinstance(stmt, (Assignment, Store)):
                        # Skip Assignment and Store statements
                        # if this statement triggers a call, it should not be removed
                        if not self._statement_has_call_exprs(stmt):
                            simplified = True
                            continue
                    elif isinstance(stmt, Call):
                        codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.ins_addr)
                        if codeloc in self._calls_to_remove:
                            # this call can be removed
                            simplified = True
                            continue

                        if stmt.ret_expr is not None:
                            # the return expr is not used. it should not have return expr
                            stmt = stmt.copy()
                            stmt.ret_expr = None
                            simplified = True
                    else:
                        # Should not happen!
                        raise NotImplementedError()

                new_statements.append(stmt)

            new_block = block.copy()
            new_block.statements = new_statements
            self.blocks[old_block] = new_block

        return simplified

    @staticmethod
    def _statement_has_call_exprs(stmt: Statement) -> bool:

        def _handle_callexpr(expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
            raise HasCallNotification()

        walker = AILBlockWalker()
        walker.expr_handlers[Call] = _handle_callexpr
        try:
            walker.walk_statement(stmt)
        except HasCallNotification:
            return True

        return False


AnalysesHub.register_default("AILSimplifier", AILSimplifier)
