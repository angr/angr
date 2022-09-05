from typing import Set, Dict, List, Tuple, Any, Optional, TYPE_CHECKING
from collections import defaultdict
import logging

from ailment.block import Block
from ailment.statement import Statement, Assignment, Store, Call, ConditionalJump
from ailment.expression import Register, Convert, Load, StackBaseOffset, Expression, DirtyExpression, \
    VEXCCallExpression, Tmp, Const

from ...engines.light import SpOffset
from ...knowledge_plugins.key_definitions.constants import OP_AFTER
from ...code_location import CodeLocation
from ...analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from ...sim_variable import SimStackVariable, SimMemoryVariable
from ...analyses.propagator.propagator import Equivalence
from ...knowledge_plugins.key_definitions import atoms
from ...knowledge_plugins.key_definitions.definition import Definition
from .. import Analysis, AnalysesHub
from .ailblock_walker import AILBlockWalker
from .ailgraph_walker import AILGraphWalker
from .expression_narrower import ExpressionNarrowingWalker
from .block_simplifier import BlockSimplifier
from .ccall_rewriters import CCALL_REWRITERS

if TYPE_CHECKING:
    from ailment.manager import Manager
    from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsModel


_l = logging.getLogger(__name__)


class HasCallNotification(Exception):
    """
    Notifies the existence of a call statement.
    """


class AILBlockTempCollector(AILBlockWalker):
    """
    Collects any temporaries used in a block.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.temps = set()
        self.expr_handlers[Tmp] = self._handle_Tmp

    # pylint:disable=unused-argument
    def _handle_Tmp(self, expr_idx: int, expr: Expression, stmt_idx: int,
                     stmt: Statement, block) -> None:
        if isinstance(expr, Tmp):
            self.temps.add(expr)


class AILSimplifier(Analysis):
    """
    Perform function-level simplifications.
    """
    def __init__(self, func,
                 func_graph=None,
                 remove_dead_memdefs=False,
                 stack_arg_offsets: Optional[Set[Tuple[int,int]]]=None,
                 unify_variables=False,
                 ail_manager: Optional['Manager']=None,
                 gp: Optional[int]=None,
                 narrow_expressions=False):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions = None
        self._propagator = None

        self._remove_dead_memdefs = remove_dead_memdefs
        self._stack_arg_offsets = stack_arg_offsets
        self._unify_vars = unify_variables
        self._ail_manager = ail_manager
        self._gp = gp
        self._narrow_expressions = narrow_expressions

        self._calls_to_remove: Set[CodeLocation] = set()
        self._assignments_to_remove: Set[CodeLocation] = set()
        self.blocks = {}  # Mapping nodes to simplified blocks

        self.simplified: bool = False
        self._simplify()

    def _simplify(self):

        if self._narrow_expressions:
            _l.debug("Narrowing expressions")
            narrowed_exprs = self._narrow_exprs()
            self.simplified |= narrowed_exprs
            if narrowed_exprs:
                _l.debug("... expressions narrowed")
                self._rebuild_func_graph()
                self._clear_cache()

        _l.debug("Folding expressions")
        folded_exprs = self._fold_exprs()
        self.simplified |= folded_exprs
        if folded_exprs:
            _l.debug("... expressions folded")
            self._rebuild_func_graph()
            # reaching definition analysis results are no longer reliable
            self._clear_cache()

        _l.debug("Rewriting ccalls")
        ccalls_rewritten = self._rewrite_ccalls()
        self.simplified |= ccalls_rewritten
        if ccalls_rewritten:
            _l.debug("... ccalls rewritten")
            self._rebuild_func_graph()
            self._clear_cache()

        if self._unify_vars:
            _l.debug("Unifying local variables")
            r = self._unify_local_variables()
            if r:
                _l.debug("... local variables unified")
                self.simplified = True
                self._rebuild_func_graph()
            # _fold_call_exprs() may set self._calls_to_remove, which will be honored in _remove_dead_assignments()
            _l.debug("Folding call expressions")
            r = self._fold_call_exprs()
            if r:
                _l.debug("... call expressions folded")
                self.simplified = True
                self._rebuild_func_graph()

        _l.debug("Removing dead assignments")
        r = self._remove_dead_assignments()
        if r:
            _l.debug("... dead assignments removed")
            self.simplified = True
            self._rebuild_func_graph()

    def _rebuild_func_graph(self):
        def _handler(node):
            return self.blocks.get(node, None)
        AILGraphWalker(self.func_graph, _handler, replace_nodes=True).walk()
        self.blocks = {}

    def _compute_reaching_definitions(self) -> 'ReachingDefinitionsModel':
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
        prop = self.project.analyses.Propagator(func=self.func, func_graph=self.func_graph, gp=self._gp)
        self._propagator = prop
        return prop

    def _clear_cache(self) -> None:
        self._propagator = None
        self._reaching_definitions = None

    def _clear_propagator_cache(self) -> None:
        self._propagator = None

    def _clear_reaching_definitions_cache(self) -> None:
        self._reaching_definitions = None

    #
    # Expression narrowing
    #

    def _narrow_exprs(self) -> bool:
        """
        A register may be used with full width even when only the lower bytes are really needed. This results in the
        incorrect determination of wider variables while the actual variable is narrower (e.g., int64 vs char). This
        optimization narrows a register definition if all its uses are narrower than the definition itself.
        """

        narrowed = False

        addr_and_idx_to_block: Dict[Tuple[int,int], Block] = { }
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        rd = self._compute_reaching_definitions()
        for def_ in rd.all_definitions:
            if isinstance(def_.atom, atoms.Register):
                needs_narrowing, to_size, use_exprs = self._narrowing_needed(def_, rd, addr_and_idx_to_block)
                if needs_narrowing:
                    # replace the definition
                    if not isinstance(def_.codeloc, ExternalCodeLocation):
                        old_block = addr_and_idx_to_block.get((def_.codeloc.block_addr, def_.codeloc.block_idx))
                        the_block = self.blocks.get(old_block, old_block)
                        stmt = the_block.statements[def_.codeloc.stmt_idx]
                        r, new_block = False, None
                        if isinstance(stmt, Assignment) and isinstance(stmt.dst, Register):
                            new_assignment_dst = Register(stmt.dst.idx,
                                                          None,
                                                          def_.atom.reg_offset,
                                                          to_size * self.project.arch.byte_width,
                                                          **stmt.dst.tags
                                                          )
                            new_assignment_src = Convert(stmt.src.idx,  # FIXME: This is a hack
                                                         stmt.src.bits,
                                                         to_size * self.project.arch.byte_width,
                                                         False,
                                                         stmt.src,
                                                         **stmt.src.tags
                                                         )
                            r, new_block = BlockSimplifier._replace_and_build(the_block,
                                                                              {def_.codeloc:
                                                                                   {stmt.dst: new_assignment_dst,
                                                                                    stmt.src: new_assignment_src,
                                                                                    }},
                                                                              replace_assignment_dsts=True)
                        elif isinstance(stmt, Call):
                            new_retexpr = Register(stmt.ret_expr.idx,
                                                   None,
                                                   def_.atom.reg_offset,
                                                   to_size * self.project.arch.byte_width,
                                                   **stmt.ret_expr.tags
                                                   )
                            r, new_block = BlockSimplifier._replace_and_build(
                                the_block,
                                {def_.codeloc:{stmt.ret_expr: new_retexpr}}
                            )
                        if not r:
                            # couldn't replace the definition...
                            continue
                        self.blocks[old_block] = new_block

                    # replace all uses
                    for use_loc, use_expr in use_exprs:
                        old_block = addr_and_idx_to_block.get((use_loc.block_addr, use_loc.block_idx))
                        the_block = self.blocks.get(old_block, old_block)
                        tags = use_expr.tags
                        if "reg_name" not in tags:
                            tags["reg_name"] = self.project.arch.translate_register_name(
                                def_.atom.reg_offset,
                                size=to_size * self.project.arch.byte_width
                            )
                        new_use_expr = Register(use_expr.idx,
                                                None,
                                                def_.atom.reg_offset,
                                                to_size * self.project.arch.byte_width,
                                                **use_expr.tags)
                        r, new_block = BlockSimplifier._replace_and_build(the_block, {use_loc:
                                                                                          {use_expr: new_use_expr}})
                        if not r:
                            _l.warning("Failed to replace use-expr at %s.", use_loc)
                        else:
                            self.blocks[old_block] = new_block

                    narrowed = True

        return narrowed

    def _narrowing_needed(self, def_, rd,
                          addr_and_idx_to_block) -> Tuple[bool,
                                                          Optional[int],
                                                          Optional[List[Tuple[CodeLocation,Expression]]]]:

        def_size = def_.size
        # find its uses
        use_and_exprs = rd.all_uses.get_uses_with_expr(def_)

        all_used_sizes = set()
        used_by: List[Tuple[CodeLocation,Expression]] = [ ]

        for loc, expr in use_and_exprs:
            old_block = addr_and_idx_to_block.get((loc.block_addr, loc.block_idx), None)
            if old_block is None:
                # missing a block for whatever reason
                return False, None, None

            block = self.blocks.get(old_block, old_block)
            if loc.stmt_idx >= len(block.statements):
                # missing a statement for whatever reason
                return False, None, None
            stmt = block.statements[loc.stmt_idx]

            expr_size, used_by_expr = self._extract_expression_effective_size(stmt, expr)
            if expr_size is None:
                # it's probably used in full width
                return False, None, None

            all_used_sizes.add(expr_size)
            used_by.append((loc, used_by_expr))

        if len(all_used_sizes) == 1 and next(iter(all_used_sizes)) < def_size:
            return True, next(iter(all_used_sizes)), used_by

        return False, None, None

    def _extract_expression_effective_size(self, statement, expr) -> Tuple[Optional[int],Optional[Expression]]:
        """
        Determine the effective size of an expression when it's used.
        """

        walker = ExpressionNarrowingWalker(expr)
        walker.walk_statement(statement)
        if not walker.operations:
            return None, None

        first_op = walker.operations[0]
        if isinstance(first_op, Convert):
            return first_op.to_bits // self.project.arch.byte_width, first_op

        return None, None

    #
    # Expression folding
    #

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
            r, new_block = BlockSimplifier._replace_and_build(block, reps, gp=self._gp)
            replaced |= r
            self.blocks[block] = new_block

        if replaced:
            # blocks have been rebuilt - expression propagation results are no longer reliable
            self._clear_cache()
        return replaced

    #
    # Unifying local variables
    #

    def _unify_local_variables(self) -> bool:
        """
        Find variables that are definitely equivalent and then eliminate unnecessary copies.
        """

        simplified = False

        prop = self._compute_propagation()
        if not prop.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int,int], Block] = { }
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        equivalences: Dict[Any,Set[Equivalence]] = defaultdict(set)
        atom_by_loc = set()
        for eq in prop.equivalence:
            equivalences[eq.atom1].add(eq)
            atom_by_loc.add((eq.codeloc, eq.atom1))

        # sort keys to ensure a reproducible result
        sorted_loc_and_atoms = sorted(atom_by_loc, key=lambda x: x[0])

        for _, atom in sorted_loc_and_atoms:
            eqs = equivalences[atom]
            if len(eqs) > 1:
                continue

            eq = next(iter(eqs))

            # Acceptable equivalence classes:
            #
            # stack variable == register
            # register variable == register
            # stack variable == Conv(register, M->N)
            # global variable == register
            #
            # Equivalence is generally created at assignment sites. Therefore, eq.atom0 is the definition and
            # eq.atom1 is the use.
            the_def = None
            if isinstance(eq.atom0, SimMemoryVariable):  # covers both Stack and Global variables
                if isinstance(eq.atom1, Register):
                    # stack_var == register or global_var == register
                    to_replace = eq.atom1
                    to_replace_is_def = False
                elif isinstance(eq.atom1, Convert) and isinstance(eq.atom1.operand, Register):
                    # stack_var == Conv(register, M->N)
                    to_replace = eq.atom1.operand
                    to_replace_is_def = False
                else:
                    continue

            elif isinstance(eq.atom0, Register):
                if isinstance(eq.atom1, Register):
                    # register == register
                    if self.project.arch.is_artificial_register(eq.atom0.reg_offset, eq.atom0.size):
                        to_replace = eq.atom0
                        to_replace_is_def = True
                    else:
                        to_replace = eq.atom1
                        to_replace_is_def = False
                else:
                    continue

            else:
                continue

            # find the definition of this register
            rd = self._compute_reaching_definitions()
            if to_replace_is_def:
                # find defs
                defs = [ ]
                for def_ in rd.all_definitions:
                    if def_.codeloc == eq.codeloc:
                        if isinstance(to_replace, SimStackVariable):
                            if isinstance(def_.atom, atoms.MemoryLocation) \
                                    and isinstance(def_.atom.addr, atoms.SpOffset):
                                if to_replace.offset == def_.atom.addr.offset:
                                    defs.append(def_)
                        elif isinstance(to_replace, Register):
                            if isinstance(def_.atom, atoms.Register) \
                                    and to_replace.reg_offset == def_.atom.reg_offset:
                                defs.append(def_)
                if len(defs) != 1:
                    continue
                the_def = defs[0]
            else:
                # find uses
                defs = rd.all_uses.get_uses_by_location(eq.codeloc)
                if len(defs) != 1:
                    # there are multiple defs for this register - we do not support replacing all of them
                    continue
                for def_ in defs:
                    def_: Definition
                    if isinstance(def_.atom, atoms.Register) and def_.atom.reg_offset == to_replace.reg_offset:
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
                replace_with = None
                remove_initial_assignment = None

                if defs and len(defs) == 1:
                    stackvar_def = defs[0]
                    if isinstance(stackvar_def.atom, atoms.MemoryLocation) \
                            and isinstance(stackvar_def.atom.addr, SpOffset):
                        # found the stack variable
                        # Make sure there is no other write to this location
                        if any((def_ != stackvar_def and def_.atom == stackvar_def.atom)
                               for def_ in rd.all_definitions if isinstance(def_.atom, atoms.MemoryLocation)):
                            continue

                        # Make sure the register is never updated across this function
                        if any((def_ != the_def and def_.atom == the_def.atom)
                               for def_ in rd.all_definitions if isinstance(def_.atom, atoms.Register)):
                            continue

                        # find all its uses
                        all_stackvar_uses: Set[Tuple[CodeLocation,Any]] = set(
                            rd.all_uses.get_uses_with_expr(stackvar_def))
                        all_uses_with_def = set()

                        should_abort = False
                        for use in all_stackvar_uses:
                            used_expr = use[1]
                            if used_expr is not None and used_expr.size != stackvar_def.size:
                                should_abort = True
                                break
                            all_uses_with_def.add((stackvar_def, use))
                        if should_abort:
                            continue

                        #to_replace = Load(None, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset),
                        #                  eq.atom0.size, endness=self.project.arch.memory_endness)
                        replace_with = eq.atom1
                        remove_initial_assignment = True

                if all_uses_with_def is None:
                    continue

            else:
                if isinstance(eq.atom0, SimStackVariable):
                    # create the memory loading expression
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with = Load(new_idx, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset),
                                        eq.atom0.size, endness=self.project.arch.memory_endness)
                elif isinstance(eq.atom0, SimMemoryVariable) and isinstance(eq.atom0.addr, int):
                    # create the memory loading expression
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with = Load(new_idx, Const(None, None, eq.atom0.addr, self.project.arch.bits),
                                        eq.atom0.size, endness=self.project.arch.memory_endness)
                elif isinstance(eq.atom0, Register):
                    if isinstance(eq.atom1, Register):
                        if self.project.arch.is_artificial_register(eq.atom0.reg_offset, eq.atom0.size):
                            replace_with = eq.atom1
                        else:
                            replace_with = eq.atom0
                    else:
                        raise RuntimeError("Unsupported atom1 type %s." % type(eq.atom1))
                else:
                    raise RuntimeError("Unsupported atom0 type %s." % type(eq.atom0))

                to_replace_def = the_def

                # find all uses of this definition
                # we make a copy of the set since we may touch the set (uses) when replacing expressions
                all_uses: Set[Tuple[CodeLocation,Any]] = set(rd.all_uses.get_uses_with_expr(to_replace_def))
                # make sure none of these uses are phi nodes (depends on more than one def)
                all_uses_with_unique_def = set()
                for use_and_expr in all_uses:
                    use_loc, used_expr = use_and_expr
                    defs_and_exprs = rd.all_uses.get_uses_by_location(use_loc, exprs=True)
                    filtered_defs = { def_ for def_, expr_ in defs_and_exprs if expr_ == used_expr}
                    if len(filtered_defs) == 1:
                        all_uses_with_unique_def.add(use_and_expr)
                    else:
                        # optimization: break early
                        break

                if len(all_uses) != len(all_uses_with_unique_def):
                    # only when all uses are determined by the same definition will we continue with the simplification
                    continue

                all_uses_with_def = set((to_replace_def, use_and_expr) for use_and_expr in all_uses)

                remove_initial_assignment = False  # expression folding will take care of it

            if not all_uses_with_def:
                # definitions without uses may simply be our data-flow analysis being incorrect. do not remove them.
                continue

            # TODO: We can only replace all these uses with the stack variable if the stack variable isn't
            # TODO: re-assigned of a new value. Perform this check.

            # replace all uses
            all_uses_replaced = True
            for def_, use_and_expr in all_uses_with_def:
                u, used_expr = use_and_expr
                if u == eq.codeloc:
                    # skip the very initial assignment location
                    continue
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue
                if used_expr is None:
                    all_uses_replaced = False
                    continue

                # if there is an updated block, use it
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                replace_with_copy = replace_with.copy()
                if used_expr.size != replace_with_copy.size:
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with_copy = Convert(new_idx,
                                                replace_with_copy.bits,
                                                used_expr.bits,
                                                False,
                                                replace_with_copy,
                                                )

                r, new_block = self._replace_expr_and_update_block(the_block, u.stmt_idx, stmt, def_, u, used_expr,
                                                                   replace_with_copy)
                if r:
                    self.blocks[old_block] = new_block
                else:
                    # failed to replace a use - we need to keep the initial assignment!
                    all_uses_replaced = False
                simplified |= r

            if all_uses_replaced and remove_initial_assignment:
                # the initial statement can be removed
                self._assignments_to_remove.add(eq.codeloc)

        if simplified:
            self._clear_cache()
        return simplified

    #
    # Folding call expressions
    #

    @staticmethod
    def _is_call_using_temporaries(call: Call) -> bool:
        walker = AILBlockTempCollector()
        walker.walk_statement(call)
        return len(walker.temps) > 0

    def _fold_call_exprs(self) -> bool:
        """
        Fold a call expression (statement) into other statements if the return value of the call expression (statement)
        is only used once, and the use site and the call site belongs to the same supernode.

        Example::

            s1 = func();
            s0 = s1;
            if (s0) ...

        after folding, it will be transformed to::

            s0 = func();
            if (s0) ...

        to avoid cases where func() is called more than once after simplification, another simplification pass will run
        on the structured graph to further transform it to::

            if (func()) ...
        """

        simplified = False

        prop = self._compute_propagation()
        if not prop.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int,int], Block] = { }
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        def_locations_to_remove: Set[CodeLocation] = set()
        updated_use_locations: Set[CodeLocation] = set()

        for eq in prop.equivalence:
            eq: Equivalence

            # register variable == Call
            if isinstance(eq.atom0, Register):
                if isinstance(eq.atom1, Call):
                    # register variable = Call
                    call = eq.atom1
                elif isinstance(eq.atom1, Convert) and isinstance(eq.atom1.operand, Call):
                    # register variable = Convert(Call)
                    call = eq.atom1
                else:
                    continue

                if self._is_call_using_temporaries(call):
                    continue

                if eq.codeloc in updated_use_locations:
                    # this def is now created by an updated use. the corresponding statement will be updated in the end.
                    # we must rerun Propagator to get an updated definition (and Equivalence)
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
                all_uses: Set[Tuple[CodeLocation,Any]] = set(rd.all_uses.get_uses_with_expr(the_def))

                if len(all_uses) != 1:
                    continue
                u, used_expr = next(iter(all_uses))

                if u in def_locations_to_remove:
                    # this use site has been altered by previous folding attempts. the corresponding statement will be
                    # removed in the end. in this case, this Equivalence is probably useless, and we must rerun
                    # Propagator to get an updated Equivalence.
                    continue

                # check the statement and make sure it's not a conditional jump
                the_block = addr_and_idx_to_block[(u.block_addr, u.block_idx)]
                if isinstance(the_block.statements[u.stmt_idx], ConditionalJump):
                    continue

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
                    src = used_expr
                    dst = call

                    if src.bits != dst.bits:
                        dst = Convert(None, dst.bits, src.bits, False, dst)
                else:
                    continue

                replaced, new_block = self._replace_expr_and_update_block(the_block, u.stmt_idx, stmt, the_def, u, src,
                                                                          dst)

                if replaced:
                    self.blocks[old_block] = new_block
                    # this call has been folded to the use site. we can remove this call.
                    self._calls_to_remove.add(eq.codeloc)
                    simplified = True
                    def_locations_to_remove.add(eq.codeloc)
                    updated_use_locations.add(u)

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
            rd.all_uses.remove_use(the_def, codeloc, expr=src_expr)
            return True, new_block

        return False, None

    def _remove_dead_assignments(self) -> bool:

        stmts_to_remove_per_block: Dict[Tuple[int,int],Set[int]] = defaultdict(set)

        # Find all statements that should be removed

        rd = self._compute_reaching_definitions()
        stackarg_offsets = set(tpl[1] for tpl in self._stack_arg_offsets) \
            if self._stack_arg_offsets is not None else None
        for def_ in rd.all_definitions:  # type: Definition
            if def_.dummy:
                continue
            # we do not remove references to global memory regions no matter what
            if isinstance(def_.atom, atoms.MemoryLocation) and isinstance(def_.atom.addr, int):
                continue
            if isinstance(def_.atom, atoms.MemoryLocation):
                if not self._remove_dead_memdefs:
                    # we always remove definitions for stack arguments
                    if stackarg_offsets is not None and isinstance(def_.atom.addr, atoms.SpOffset):
                        if def_.atom.addr.offset not in stackarg_offsets:
                            continue
                    else:
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

    #
    # Rewriting ccalls
    #

    def _rewrite_ccalls(self):
        rewriter_cls = CCALL_REWRITERS.get(self.project.arch.name, None)
        if rewriter_cls is None:
            return False

        walker = None

        class _any_update:
            """
            Dummy class for storing if any result has been updated.
            """
            v = False

        def _handle_expr(expr_idx: int, expr: Expression, stmt_idx: int,
                         stmt: Statement, block) -> Optional[Expression]:

            if isinstance(expr, DirtyExpression) and isinstance(expr.dirty_expr, VEXCCallExpression):
                rewriter = rewriter_cls(expr.dirty_expr)
                if rewriter.result is not None:
                    _any_update.v = True
                    return rewriter.result
                else:
                    return None

            return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        blocks_by_addr_and_idx = dict(((node.addr, node.idx), node) for node in self.func_graph.nodes())

        walker = AILBlockWalker()
        walker._handle_expr = _handle_expr

        updated = False
        for block in blocks_by_addr_and_idx.values():
            _any_update.v = False
            old_block = block.copy()
            walker.walk(block)
            if _any_update.v:
                self.blocks[old_block] = block
                updated = True

        return updated

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
