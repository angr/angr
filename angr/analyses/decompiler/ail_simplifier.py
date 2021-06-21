from typing import Set, Dict, List, Tuple, Any, Optional
from collections import defaultdict

from ailment.block import Block
from ailment.statement import Statement, Assignment, Store, Call
from ailment.expression import Register, Convert, Load, StackBaseOffset

from ...engines.light import SpOffset
from ...knowledge_plugins.key_definitions.constants import OP_AFTER
from ...code_location import CodeLocation
from ...analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from ...sim_variable import SimStackVariable
from ...analyses.propagator.propagator import Equivalence
from ...knowledge_plugins.key_definitions import atoms
from ...knowledge_plugins.key_definitions.definition import Definition
from .. import Analysis, AnalysesHub
from .ailblock_walker import AILBlockWalker
from .ailgraph_walker import AILGraphWalker
from .block_simplifier import BlockSimplifier


class HasCallNotification(Exception):
    pass


class AILSimplifier(Analysis):
    """
    Perform function-level simplifications.
    """
    def __init__(self, func, func_graph=None, remove_dead_memdefs=False, unify_variables=False):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions = None
        self._propagator = None

        self._remove_dead_memdefs = remove_dead_memdefs
        self._unify_vars = unify_variables

        self._calls_to_remove: Set[CodeLocation] = set()
        self._assignments_to_remove: Set[CodeLocation] = set()
        self.blocks = {}  # Mapping nodes to simplified blocks

        self.simplified: bool = False
        self._simplify()

    def _simplify(self):

        folded_exprs = self._fold_exprs()
        self.simplified |= folded_exprs
        if folded_exprs:
            self._rebuild_func_graph()
            # reading definition analysis results are no longer reliable
            return

        if self._unify_vars:
            r = self._unify_local_variables()
            if r:
                self.simplified = True
                self._rebuild_func_graph()
            # _fold_call_exprs() may set self._calls_to_remove, which will be honored in _remove_dead_assignments()
            r = self._fold_call_exprs()
            if r:
                self.simplified = True
                self._rebuild_func_graph()

        r = self._remove_dead_assignments()
        if r:
            self.simplified = True
            self._rebuild_func_graph()

    def _rebuild_func_graph(self):
        def _handler(node):
            return self.blocks.get(node, None)
        AILGraphWalker(self.func_graph, _handler, replace_nodes=True).walk()
        self.blocks = {}

    def _compute_reaching_definitions(self):
        # Computing reaching definitions or return the cached one
        if self._reaching_definitions is not None:
            return self._reaching_definitions
        rd = self.project.analyses.ReachingDefinitions(subject=self.func, func_graph=self.func_graph,
                                                       observe_callback=self._simplify_function_rd_observe_callback)
        self._reaching_definitions = rd
        return rd

    @staticmethod
    def _simplify_function_rd_observe_callback(ob_type, **kwargs):
        if ob_type != 'node':
            return False
        op_type = kwargs.pop('op_type')
        return op_type == OP_AFTER

    def _compute_propagation(self):
        # Propagate expressions or return the existing result
        if self._propagator is not None:
            return self._propagator
        prop = self.project.analyses.Propagator(func=self.func, func_graph=self.func_graph)
        self._propagator = prop
        return prop

    def _clear_cache(self) -> None:
        self._propagator = None
        self._reaching_definitions = None

    def _clear_propagator_cache(self) -> None:
        self._propagator = None

    def _clear_reaching_definitions_cache(self) -> None:
        self._reaching_definitions = None

    def _fold_exprs(self):
        """
        Fold expressions: Fold assigned expressions that are only used once.
        """

        # propagator
        propagator = self._compute_propagation()
        replacements = propagator.replacements

        # take replacements and rebuild the corresponding blocks
        replacements_by_block_addrs_and_idx = defaultdict(dict)
        for codeloc, reps in replacements.items():
            if reps:
                replacements_by_block_addrs_and_idx[(codeloc.block_addr, codeloc.block_idx)][codeloc] = reps

        if not replacements_by_block_addrs_and_idx:
            return False

        blocks_by_addr_and_idx = dict(((node.addr, node.idx), node) for node in self.func_graph.nodes())

        replaced = False
        for (block_addr, block_idx), reps in replacements_by_block_addrs_and_idx.items():
            block = blocks_by_addr_and_idx[(block_addr, block_idx)]
            r, new_block = BlockSimplifier._replace_and_build(block, reps)
            replaced |= r
            self.blocks[block] = new_block

        if replaced:
            # blocks have been rebuilt - expression propagation results are no longer reliable
            self._clear_cache()
        return replaced

    def _unify_local_variables(self) -> bool:
        """
        Find variables that are definitely equivalent and then eliminate the unnecessary copies.
        """

        simplified = False

        prop = self._compute_propagation()
        if not prop.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int,int], Block] = { }
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        equivalences: Dict[Any,Set[Equivalence]] = defaultdict(set)
        for eq in prop.equivalence:
            equivalences[eq.atom1].add(eq)

        for _, eqs in equivalences.items():
            if len(eqs) > 1:
                continue

            eq = next(iter(eqs))

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
            rd = self._compute_reaching_definitions()
            defs = rd.all_uses.get_uses_by_location(eq.codeloc)
            for def_ in defs:
                def_: Definition
                if isinstance(def_.atom, atoms.Register) and def_.atom.reg_offset == reg.reg_offset:
                    # found it!
                    the_def = def_
                    break

            if the_def is None:
                continue

            if isinstance(the_def.codeloc, ExternalCodeLocation):
                # this is a function argument. we enter a slightly different logic and try to eliminate copies of this
                # argument if
                # (a) the on-stack copy of it has never been modified in this function
                # (b) the function argument register has never been updated.
                #     TODO: we may loosen requirement (b) once we have real register versioning in AIL.
                defs = [ def_ for def_ in rd.all_definitions if def_.codeloc == eq.codeloc ]
                all_uses_with_def = None
                to_replace, replace_with = None, None
                remove_initial_assignment = None

                if defs and len(defs) == 1:
                    stackvar_def = defs[0]
                    if isinstance(stackvar_def.atom, atoms.MemoryLocation) and isinstance(stackvar_def.atom.addr, SpOffset):
                        # found the stack variable
                        # Make sure there is no other write to this location
                        if any((def_ != stackvar_def and def_.atom == stackvar_def.atom) for def_ in rd.all_definitions if isinstance(def_.atom, atoms.MemoryLocation)):
                            continue

                        # Make sure the register is never updated across this function
                        if any((def_ != the_def and def_.atom == the_def.atom) for def_ in rd.all_definitions if isinstance(def_.atom, atoms.Register)):
                            continue

                        # find all its uses
                        all_stackvar_uses: Set[CodeLocation] = set(rd.all_uses.get_uses(stackvar_def))
                        all_uses_with_def = set()
                        for use in all_stackvar_uses:
                            all_uses_with_def.add((stackvar_def, use))

                        to_replace = Load(None, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset), eq.atom0.size,
                                          endness=self.project.arch.memory_endness)
                        replace_with = eq.atom1
                        remove_initial_assignment = True

                if all_uses_with_def is None:
                    continue

            else:
                # find all uses of this definition
                # we make a copy of the set since we may touch the set (uses) when replacing expressions
                all_uses: Set[CodeLocation] = set(rd.all_uses.get_uses(the_def))
                all_uses_with_def = set((the_def, use) for use in all_uses)

                remove_initial_assignment = False  # expression folding will take care of it
                if isinstance(eq.atom0, SimStackVariable):
                    # create the memory loading expression
                    to_replace = eq.atom1
                    replace_with = Load(None, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset), eq.atom0.size,
                               endness=self.project.arch.memory_endness)
                elif isinstance(eq.atom0, Register):
                    to_replace = eq.atom1
                    replace_with = eq.atom0
                else:
                    raise RuntimeError("Unsupported atom0 type %s." % type(eq.atom0))

            # TODO: We can only replace all these uses with the stack variable if the stack variable isn't
            # TODO: re-assigned of a new value. Perform this check.

            # replace all uses
            all_uses_replaced = True
            for def_, u in all_uses_with_def:
                if u == eq.codeloc:
                    # skip the very initial assignment location
                    continue
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue

                # if there is an updated block, use it
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                r, new_block = self._replace_expr_and_update_block(the_block, u.stmt_idx, stmt, def_, u, to_replace,
                                                                   replace_with)
                if r:
                    self.blocks[old_block] = new_block
                else:
                    # failed to replace a use - we need to keep the initial assignment!
                    all_uses_replaced = False
                simplified |= r

            if all_uses_replaced and remove_initial_assignment:
                # the initial statement can be removed
                self._assignments_to_remove.add(eq.codeloc)

        # no need to clear cache at the end of this function
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

        prop = self._compute_propagation()
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
                rd = self._compute_reaching_definitions()
                defs = [ d for d in rd.all_definitions
                         if d.codeloc == eq.codeloc
                         and isinstance(d.atom, atoms.Register)
                         and d.atom.reg_offset == eq.atom0.reg_offset
                         ]
                if not defs or len(defs) > 1:
                    continue
                the_def: Definition = defs[0]

                # find all uses of this definition
                all_uses: Set[CodeLocation] = set(rd.all_uses.get_uses(the_def))

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

        # no need to clear the cache at the end of this method
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
                                       dst_expr) -> Tuple[bool,Optional[Block]]:
        replaced, new_stmt = stmt.replace(src_expr, dst_expr)
        if replaced:
            new_block = block.copy()
            new_block.statements = block.statements[::]
            new_block.statements[stmt_idx] = new_stmt

            # update the uses
            rd = self._compute_reaching_definitions()
            rd.all_uses.remove_use(the_def, codeloc)
            return True, new_block

        return False, None

    def _remove_dead_assignments(self) -> bool:

        stmts_to_remove_per_block: Dict[Tuple[int,int],Set[int]] = defaultdict(set)

        # Find all statements that should be removed

        rd = self._compute_reaching_definitions()
        for def_ in rd.all_definitions:  # type: Definition
            if def_.dummy:
                continue
            # we do not remove references to global memory regions no matter what
            if isinstance(def_.atom, atoms.MemoryLocation) and isinstance(def_.atom.addr, int):
                continue
            if not self._remove_dead_memdefs and isinstance(def_.atom, atoms.MemoryLocation):
                continue
            uses = rd.all_uses.get_uses(def_)

            if not uses:
                stmts_to_remove_per_block[(def_.codeloc.block_addr, def_.codeloc.block_idx)].add(def_.codeloc.stmt_idx)

        for codeloc in self._calls_to_remove | self._assignments_to_remove:
            # this call can be removed. make sure it exists in stmts_to_remove_per_block
            stmts_to_remove_per_block[codeloc.block_addr, codeloc.block_idx].add(codeloc.stmt_idx)

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
                        # if this statement triggers a call, it should only be removed if it's in self._calls_to_remove
                        codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.ins_addr)
                        if codeloc in self._assignments_to_remove:
                            # it should be removed
                            simplified = True
                            continue

                        if self._statement_has_call_exprs(stmt):
                            if codeloc in self._calls_to_remove:
                                # it has a call and must be removed
                                simplified = True
                                continue
                        else:
                            # no calls. remove it
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
