from typing import Set, Dict, List, Tuple, Any, Optional, TYPE_CHECKING
from collections import defaultdict
import logging

from ailment import AILBlockWalker
from ailment.block import Block
from ailment.statement import Statement, Assignment, Store, Call, ConditionalJump, DirtyStatement
from ailment.expression import (
    Register,
    Convert,
    Load,
    StackBaseOffset,
    Expression,
    DirtyExpression,
    VEXCCallExpression,
    Tmp,
    Const,
    BinaryOp,
)

from ...engines.light import SpOffset
from ...code_location import CodeLocation, ExternalCodeLocation
from ...sim_variable import SimStackVariable, SimMemoryVariable
from ...knowledge_plugins.propagations.states import Equivalence
from ...knowledge_plugins.key_definitions import atoms
from ...knowledge_plugins.key_definitions.atoms import Register as RegisterAtom
from ...knowledge_plugins.key_definitions.definition import Definition
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE
from .. import Analysis, AnalysesHub
from .ailgraph_walker import AILGraphWalker
from .expression_narrower import ExpressionNarrowingWalker
from .block_simplifier import BlockSimplifier
from .ccall_rewriters import CCALL_REWRITERS
from .expression_counters import SingleExpressionCounter

if TYPE_CHECKING:
    from ailment.manager import Manager
    from angr.analyses.reaching_definitions import ReachingDefinitionsModel


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
    def _handle_Tmp(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement, block) -> None:
        if isinstance(expr, Tmp):
            self.temps.add(expr)


class AILSimplifier(Analysis):
    """
    Perform function-level simplifications.
    """

    def __init__(
        self,
        func,
        func_graph=None,
        remove_dead_memdefs=False,
        stack_arg_offsets: Optional[Set[Tuple[int, int]]] = None,
        unify_variables=False,
        ail_manager: Optional["Manager"] = None,
        gp: Optional[int] = None,
        narrow_expressions=False,
        only_consts=False,
        fold_callexprs_into_conditions=False,
        use_callee_saved_regs_at_return=True,
    ):
        self.func = func
        self.func_graph = func_graph if func_graph is not None else func.graph
        self._reaching_definitions: Optional["ReachingDefinitionsModel"] = None
        self._propagator = None

        self._remove_dead_memdefs = remove_dead_memdefs
        self._stack_arg_offsets = stack_arg_offsets
        self._unify_vars = unify_variables
        self._ail_manager = ail_manager
        self._gp = gp
        self._narrow_expressions = narrow_expressions
        self._only_consts = only_consts
        self._fold_callexprs_into_conditions = fold_callexprs_into_conditions
        self._use_callee_saved_regs_at_return = use_callee_saved_regs_at_return

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

        if self._only_consts:
            return

        _l.debug("Rewriting ccalls")
        ccalls_rewritten = self._rewrite_ccalls()
        self.simplified |= ccalls_rewritten
        if ccalls_rewritten:
            _l.debug("... ccalls rewritten")
            self._rebuild_func_graph()
            self._clear_cache()

        if self._unify_vars:
            _l.debug("Removing dead assignments")
            r = self._remove_dead_assignments()
            if r:
                _l.debug("... dead assignments removed")
                self.simplified = True
                self._rebuild_func_graph()
                self._clear_cache()

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

    def _compute_reaching_definitions(self) -> "ReachingDefinitionsModel":
        # Computing reaching definitions or return the cached one
        if self._reaching_definitions is not None:
            return self._reaching_definitions
        rd = self.project.analyses.ReachingDefinitions(
            subject=self.func,
            func_graph=self.func_graph,
            # init_context=(),    <-- in case of fire break glass
            observe_all=False,
            use_callee_saved_regs_at_return=self._use_callee_saved_regs_at_return,
            track_tmps=True,
        ).model
        self._reaching_definitions = rd
        return rd

    def _compute_propagation(self, immediate_stmt_removal: bool = False):
        # Propagate expressions or return the existing result
        if self._propagator is not None:
            return self._propagator
        prop = self.project.analyses.Propagator(
            func=self.func,
            func_graph=self.func_graph,
            gp=self._gp,
            only_consts=self._only_consts,
            reaching_definitions=self._compute_reaching_definitions(),
            immediate_stmt_removal=immediate_stmt_removal,
        )
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

        addr_and_idx_to_block: Dict[Tuple[int, int], Block] = {}
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        rd = self._compute_reaching_definitions()
        sorted_defs = sorted(rd.all_definitions, key=lambda d: d.codeloc, reverse=True)
        for def_ in (d_ for d_ in sorted_defs if d_.codeloc.context is None):
            if isinstance(def_.atom, atoms.Register):
                needs_narrowing, to_size, use_exprs = self._narrowing_needed(def_, rd, addr_and_idx_to_block)
                if needs_narrowing:
                    # replace the definition
                    if not isinstance(def_.codeloc, ExternalCodeLocation):
                        old_block = addr_and_idx_to_block.get((def_.codeloc.block_addr, def_.codeloc.block_idx))
                        if old_block is None:
                            # this definition might be inside a callee function, which is why the block does not exist
                            # ignore it
                            continue

                        the_block = self.blocks.get(old_block, old_block)
                        stmt = the_block.statements[def_.codeloc.stmt_idx]
                        r, new_block = False, None
                        if isinstance(stmt, Assignment) and isinstance(stmt.dst, Register):
                            tags = dict(stmt.dst.tags)
                            tags["reg_name"] = self.project.arch.translate_register_name(
                                def_.atom.reg_offset, size=to_size
                            )
                            tags["write_size"] = stmt.dst.size
                            new_assignment_dst = Register(
                                stmt.dst.idx,
                                None,
                                def_.atom.reg_offset,
                                to_size * self.project.arch.byte_width,
                                **tags,
                            )
                            new_assignment_src = Convert(
                                stmt.src.idx,  # FIXME: This is a hack
                                stmt.src.bits,
                                to_size * self.project.arch.byte_width,
                                False,
                                stmt.src,
                                **stmt.src.tags,
                            )
                            r, new_block = BlockSimplifier._replace_and_build(
                                the_block,
                                {
                                    def_.codeloc: {
                                        stmt.dst: new_assignment_dst,
                                        stmt.src: new_assignment_src,
                                    }
                                },
                                replace_assignment_dsts=True,
                                replace_loads=True,
                            )
                        elif isinstance(stmt, Call):
                            if stmt.ret_expr is not None:
                                tags = dict(stmt.ret_expr.tags)
                                tags["reg_name"] = self.project.arch.translate_register_name(
                                    def_.atom.reg_offset, size=to_size
                                )
                                new_retexpr = Register(
                                    stmt.ret_expr.idx,
                                    None,
                                    def_.atom.reg_offset,
                                    to_size * self.project.arch.byte_width,
                                    **tags,
                                )
                                r, new_block = BlockSimplifier._replace_and_build(
                                    the_block, {def_.codeloc: {stmt.ret_expr: new_retexpr}}
                                )
                        if not r:
                            # couldn't replace the definition...
                            continue
                        self.blocks[old_block] = new_block

                    # replace all uses if necessary
                    for use_loc, (use_type, use_expr_tpl) in use_exprs:
                        if isinstance(use_expr_tpl[0], Register) and to_size == use_expr_tpl[0].size:
                            # don't replace registers to the same registers
                            continue

                        old_block = addr_and_idx_to_block.get((use_loc.block_addr, use_loc.block_idx))
                        the_block = self.blocks.get(old_block, old_block)

                        if use_type in {"expr", "mask", "convert"}:
                            # the first used expr
                            use_expr_0 = use_expr_tpl[0]
                            tags = dict(use_expr_0.tags)
                            tags["reg_name"] = self.project.arch.translate_register_name(
                                def_.atom.reg_offset, size=to_size
                            )
                            new_use_expr_0 = Register(
                                use_expr_0.idx,
                                None,
                                def_.atom.reg_offset,
                                to_size * self.project.arch.byte_width,
                                **tags,
                            )

                            # the second used expr (if it exists)
                            if len(use_expr_tpl) == 2:
                                use_expr_1 = use_expr_tpl[1]
                                assert isinstance(use_expr_1, BinaryOp)
                                con = use_expr_1.operands[1]
                                assert isinstance(con, Const)
                                new_use_expr_1 = BinaryOp(
                                    use_expr_1.idx,
                                    use_expr_1.op,
                                    [
                                        new_use_expr_0,
                                        Const(con.idx, con.variable, con.value, new_use_expr_0.bits, **con.tags),
                                    ],
                                    use_expr_1.signed,
                                    floating_point=use_expr_1.floating_point,
                                    rounding_mode=use_expr_1.rounding_mode,
                                    **use_expr_1.tags,
                                )

                                if use_expr_1.size > new_use_expr_1.size:
                                    new_use_expr_1 = Convert(
                                        None,
                                        new_use_expr_1.bits,
                                        use_expr_1.bits,
                                        False,
                                        new_use_expr_1,
                                        **new_use_expr_1.tags,
                                    )

                                r, new_block = BlockSimplifier._replace_and_build(
                                    the_block, {use_loc: {use_expr_1: new_use_expr_1}}
                                )
                            elif len(use_expr_tpl) == 1:
                                if use_expr_0.size > new_use_expr_0.size:
                                    new_use_expr_0 = Convert(
                                        None,
                                        new_use_expr_0.bits,
                                        use_expr_0.bits,
                                        False,
                                        new_use_expr_0,
                                        **new_use_expr_0.tags,
                                    )

                                r, new_block = BlockSimplifier._replace_and_build(
                                    the_block, {use_loc: {use_expr_0: new_use_expr_0}}
                                )
                            else:
                                _l.warning("Nothing to replace at %s.", use_loc)
                                r = False
                                new_block = None
                        elif use_type == "binop-convert":
                            use_expr_0 = use_expr_tpl[0]
                            tags = dict(use_expr_0.tags)
                            tags["reg_name"] = self.project.arch.translate_register_name(
                                def_.atom.reg_offset, size=to_size
                            )
                            new_use_expr_0 = Register(
                                use_expr_0.idx,
                                None,
                                def_.atom.reg_offset,
                                to_size * self.project.arch.byte_width,
                                **tags,
                            )

                            use_expr_1: BinaryOp = use_expr_tpl[1]
                            # build the new use_expr_1
                            new_use_expr_1_operands = {}
                            if use_expr_1.operands[0] is use_expr_0:
                                new_use_expr_1_operands[0] = new_use_expr_0
                                other_operand = use_expr_1.operands[1]
                            else:
                                new_use_expr_1_operands[1] = new_use_expr_0
                                other_operand = use_expr_1.operands[0]
                            use_expr_2: Convert = use_expr_tpl[2]
                            if other_operand.bits == use_expr_2.from_bits:
                                new_other_operand = Convert(
                                    None, use_expr_2.from_bits, use_expr_2.to_bits, False, other_operand
                                )
                            else:
                                # Some operations, like Sar and Shl, have operands with different sizes
                                new_other_operand = other_operand

                            if 0 in new_use_expr_1_operands:
                                new_use_expr_1_operands[1] = new_other_operand
                            else:
                                new_use_expr_1_operands[0] = new_other_operand

                            # build new use_expr_1
                            new_use_expr_1 = BinaryOp(
                                use_expr_1.idx,
                                use_expr_1.op,
                                [new_use_expr_1_operands[0], new_use_expr_1_operands[1]],
                                use_expr_1.signed,
                                bits=to_size * 8,
                                floating_point=use_expr_1.floating_point,
                                rounding_mode=use_expr_1.rounding_mode,
                                **use_expr_1.tags,
                            )

                            # first remove the old conversion
                            r, new_block = BlockSimplifier._replace_and_build(
                                the_block, {use_loc: {use_expr_2: use_expr_2.operand}}
                            )
                            # then replace use_expr_1
                            if r:
                                r, new_block = BlockSimplifier._replace_and_build(
                                    new_block, {use_loc: {use_expr_1: new_use_expr_1}}
                                )
                        else:
                            raise TypeError(f'Unsupported use_type value "{use_type}"')

                        if not r:
                            _l.warning("Failed to replace use-expr at %s.", use_loc)
                        else:
                            self.blocks[old_block] = new_block

                    narrowed = True

        return narrowed

    def _narrowing_needed(
        self, def_, rd, addr_and_idx_to_block
    ) -> Tuple[bool, Optional[int], Optional[List[Tuple[CodeLocation, Tuple[str, Tuple[Expression, ...]]]]]]:
        def_size = def_.size
        # find its uses
        use_and_exprs = rd.all_uses.get_uses_with_expr(def_)

        all_used_sizes = set()
        used_by: List[Tuple[CodeLocation, Tuple[str, Tuple[Expression, ...]]]] = []

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

            expr_size, used_by_exprs = self._extract_expression_effective_size(stmt, expr)
            if expr_size is None:
                # it's probably used in full width
                return False, None, None

            all_used_sizes.add(expr_size)
            used_by.append((loc, used_by_exprs))

        if len(all_used_sizes) == 1 and next(iter(all_used_sizes)) < def_size:
            return True, next(iter(all_used_sizes)), used_by

        return False, None, None

    def _extract_expression_effective_size(
        self, statement, expr
    ) -> Tuple[Optional[int], Optional[Tuple[str, Tuple[Expression, ...]]]]:
        """
        Determine the effective size of an expression when it's used.
        """

        walker = ExpressionNarrowingWalker(expr)
        walker.walk_statement(statement)
        if not walker.operations:
            if expr is None:
                return None, None
            return expr.size, ("expr", (expr,))

        first_op = walker.operations[0]
        if isinstance(first_op, Convert):
            return first_op.to_bits // self.project.arch.byte_width, ("convert", (first_op,))
        if isinstance(first_op, BinaryOp):
            second_op = None
            if len(walker.operations) >= 2:
                second_op = walker.operations[1]
            if (
                first_op.op == "And"
                and isinstance(first_op.operands[1], Const)
                and (second_op is None or isinstance(second_op, BinaryOp) and isinstance(second_op.operands[1], Const))
            ):
                mask = first_op.operands[1].value
                if mask == 0xFF:
                    return 1, ("mask", (first_op, second_op)) if second_op is not None else ("mask", (first_op,))
                if mask == 0xFFFF:
                    return 2, ("mask", (first_op, second_op)) if second_op is not None else ("mask", (first_op,))
                if mask == 0xFFFF_FFFF:
                    return 4, ("mask", (first_op, second_op)) if second_op is not None else ("mask", (first_op,))
            if (
                (first_op.operands[0] is expr or first_op.operands[1] is expr)
                and first_op.op not in {"Shr", "Sar"}
                and isinstance(second_op, Convert)
                and second_op.from_bits == expr.bits
            ):
                return min(expr.bits, second_op.to_bits) // self.project.arch.byte_width, (
                    "binop-convert",
                    (expr, first_op, second_op),
                )

        if expr is None:
            return None, None
        return expr.size, ("expr", (expr,))

    #
    # Expression folding
    #

    def _fold_exprs(self):
        """
        Fold expressions: Fold assigned expressions that are only used once.
        """

        # propagator
        propagator = self._compute_propagation(immediate_stmt_removal=True)
        replacements = propagator.replacements

        # take replacements and rebuild the corresponding blocks
        replacements_by_block_addrs_and_idx = defaultdict(dict)
        for codeloc, reps in replacements.items():
            if reps:
                replacements_by_block_addrs_and_idx[(codeloc.block_addr, codeloc.block_idx)][codeloc] = reps

        if not replacements_by_block_addrs_and_idx:
            return False

        blocks_by_addr_and_idx = {(node.addr, node.idx): node for node in self.func_graph.nodes()}

        if self._stack_arg_offsets:
            insn_addrs_using_stack_args = {ins_addr for ins_addr, _ in self._stack_arg_offsets}
        else:
            insn_addrs_using_stack_args = None

        replaced = False
        for (block_addr, block_idx), reps in replacements_by_block_addrs_and_idx.items():
            block = blocks_by_addr_and_idx[(block_addr, block_idx)]

            # only replace loads if there are stack arguments in this block
            replace_loads = insn_addrs_using_stack_args is not None and {
                stmt.ins_addr for stmt in block.statements
            }.intersection(insn_addrs_using_stack_args)

            r, new_block = BlockSimplifier._replace_and_build(block, reps, gp=self._gp, replace_loads=replace_loads)
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
        if not prop.model.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int, int], Block] = {}
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        equivalences: Dict[Any, Set[Equivalence]] = defaultdict(set)
        atom_by_loc = set()
        for eq in prop.model.equivalence:
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
                defs = []
                for def_ in rd.all_definitions:
                    if def_.codeloc == eq.codeloc:
                        if isinstance(to_replace, SimStackVariable):
                            if isinstance(def_.atom, atoms.MemoryLocation) and isinstance(
                                def_.atom.addr, atoms.SpOffset
                            ):
                                if to_replace.offset == def_.atom.addr.offset:
                                    defs.append(def_)
                        elif isinstance(to_replace, Register):
                            if isinstance(def_.atom, atoms.Register) and to_replace.reg_offset == def_.atom.reg_offset:
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
            if the_def.codeloc.context:
                # the definition is in a callee function
                continue

            if isinstance(the_def.codeloc, ExternalCodeLocation):
                # this is a function argument. we enter a slightly different logic and try to eliminate copies of this
                # argument if
                # (a) the on-stack or in-register copy of it has never been modified in this function
                # (b) the function argument register has never been updated.
                #     TODO: we may loosen requirement (b) once we have real register versioning in AIL.
                defs = [def_ for def_ in rd.all_definitions if def_.codeloc == eq.codeloc]
                all_uses_with_def = None
                replace_with = None
                remove_initial_assignment = None

                if defs and len(defs) == 1:
                    arg_copy_def = defs[0]
                    if (
                        isinstance(arg_copy_def.atom, atoms.MemoryLocation)
                        and isinstance(arg_copy_def.atom.addr, SpOffset)
                        or isinstance(arg_copy_def.atom, atoms.Register)
                    ):
                        # found the copied definition (either a stack variable or a register variable)

                        # Make sure there is no other write to this stack location if the copy is a stack variable
                        if isinstance(arg_copy_def.atom, atoms.MemoryLocation):
                            if any(
                                (def_ != arg_copy_def and def_.atom == arg_copy_def.atom)
                                for def_ in rd.all_definitions
                                if isinstance(def_.atom, atoms.MemoryLocation)
                            ):
                                continue

                            # Make sure the register is never updated across this function
                            if any(
                                (def_ != the_def and def_.atom == the_def.atom)
                                for def_ in rd.all_definitions
                                if isinstance(def_.atom, atoms.Register) and rd.all_uses.get_uses(def_)
                            ):
                                continue

                        # find all its uses
                        all_arg_copy_var_uses: Set[Tuple[CodeLocation, Any]] = set(
                            rd.all_uses.get_uses_with_expr(arg_copy_def)
                        )
                        all_uses_with_def = set()

                        should_abort = False
                        for use in all_arg_copy_var_uses:
                            used_expr = use[1]
                            if used_expr is not None and used_expr.size != arg_copy_def.size:
                                should_abort = True
                                break
                            all_uses_with_def.add((arg_copy_def, use))
                        if should_abort:
                            continue

                        # to_replace = Load(None, StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset),
                        #                  eq.atom0.size, endness=self.project.arch.memory_endness)
                        replace_with = eq.atom1
                        remove_initial_assignment = True

                if all_uses_with_def is None:
                    continue

            else:
                if (
                    eq.codeloc.block_addr == the_def.codeloc.block_addr
                    and eq.codeloc.block_idx == the_def.codeloc.block_idx
                ):
                    # the definition and the eq location are within the same block, and the definition is before
                    # the eq location.
                    if eq.codeloc.stmt_idx < the_def.codeloc.stmt_idx:
                        continue
                else:
                    # the definition is in the predecessor block of the eq
                    eq_block = next(
                        iter(
                            bb
                            for bb in self.func_graph
                            if bb.addr == eq.codeloc.block_addr and bb.idx == eq.codeloc.block_idx
                        )
                    )
                    eq_block_preds = set(self.func_graph.predecessors(eq_block))
                    if not any(
                        pred.addr == the_def.codeloc.block_addr and pred.idx == the_def.codeloc.block_idx
                        for pred in eq_block_preds
                    ):
                        continue

                if isinstance(eq.atom0, SimStackVariable):
                    # create the memory loading expression
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with = Load(
                        new_idx,
                        StackBaseOffset(None, self.project.arch.bits, eq.atom0.offset),
                        eq.atom0.size,
                        endness=self.project.arch.memory_endness,
                    )
                elif isinstance(eq.atom0, SimMemoryVariable) and isinstance(eq.atom0.addr, int):
                    # create the memory loading expression
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with = Load(
                        new_idx,
                        Const(None, None, eq.atom0.addr, self.project.arch.bits),
                        eq.atom0.size,
                        endness=self.project.arch.memory_endness,
                    )
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
                all_uses: Set[Tuple[CodeLocation, Any]] = set(rd.all_uses.get_uses_with_expr(to_replace_def))
                # make sure none of these uses are phi nodes (depends on more than one def)
                all_uses_with_unique_def = set()
                for use_and_expr in all_uses:
                    use_loc, used_expr = use_and_expr
                    defs_and_exprs = rd.all_uses.get_uses_by_location(use_loc, exprs=True)
                    filtered_defs = {def_ for def_, expr_ in defs_and_exprs if expr_ == used_expr}
                    if len(filtered_defs) == 1:
                        all_uses_with_unique_def.add(use_and_expr)
                    else:
                        # optimization: break early
                        break

                if len(all_uses) != len(all_uses_with_unique_def):
                    # only when all uses are determined by the same definition will we continue with the simplification
                    continue

                # one more check: there can be at most one assignment in all these use locations
                assignment_ctr = 0
                for use_loc, used_expr in all_uses:
                    block = addr_and_idx_to_block[(use_loc.block_addr, use_loc.block_idx)]
                    stmt = block.statements[use_loc.stmt_idx]
                    if isinstance(stmt, Assignment):
                        assignment_ctr += 1
                if assignment_ctr > 1:
                    continue

                all_uses_with_def = {(to_replace_def, use_and_expr) for use_and_expr in all_uses}

                remove_initial_assignment = False  # expression folding will take care of it

            # ensure the uses we consider are all after the eq location
            filtered_all_uses_with_def = []
            for def_, use_and_expr in all_uses_with_def:
                u = use_and_expr[0]
                if (
                    u.block_addr == eq.codeloc.block_addr
                    and u.block_idx == eq.codeloc.block_idx
                    and u.stmt_idx < eq.codeloc.stmt_idx
                ):
                    # this use happens before the assignment - ignore it
                    continue
                filtered_all_uses_with_def.append((def_, use_and_expr))
            all_uses_with_def = filtered_all_uses_with_def

            if not all_uses_with_def:
                # definitions without uses may simply be our data-flow analysis being incorrect. do not remove them.
                continue

            # TODO: We can only replace all these uses with the stack variable if the stack variable isn't
            # TODO: re-assigned of a new value. Perform this check.

            # replace all uses
            all_uses_replaced = True
            for def_, use_and_expr in all_uses_with_def:
                u, used_expr = use_and_expr

                use_expr_defns = []
                for d in rd.all_uses.get_uses_by_location(u):
                    if (
                        isinstance(d.atom, RegisterAtom)
                        and isinstance(def_.atom, RegisterAtom)
                        and d.atom.reg_offset == def_.atom.reg_offset
                    ):
                        use_expr_defns.append(d)
                    elif d.atom == def_.atom:
                        use_expr_defns.append(d)
                # you can never replace a use with dependencies from outside the checked defn
                if len(use_expr_defns) != 1 or list(use_expr_defns)[0] != def_:
                    if not use_expr_defns:
                        _l.warning("There was no use_expr_defns for %s, this is likely a bug", u)
                    # TODO: can you have multiple definitions which can all be eliminated?
                    all_uses_replaced = False
                    continue

                if u == eq.codeloc:
                    # skip the very initial assignment location
                    continue
                old_block = addr_and_idx_to_block.get((u.block_addr, u.block_idx), None)
                if old_block is None:
                    continue
                if used_expr is None:
                    all_uses_replaced = False
                    continue

                # ensure the expression that we want to replace with is still up-to-date
                replace_with_original_def = self._find_atom_def_at(replace_with, rd, def_.codeloc)
                if replace_with_original_def is not None and not self._check_atom_last_def(
                    replace_with, u, rd, replace_with_original_def
                ):
                    all_uses_replaced = False
                    continue

                # if there is an updated block, use it
                the_block = self.blocks.get(old_block, old_block)
                stmt: Statement = the_block.statements[u.stmt_idx]

                replace_with_copy = replace_with.copy()
                if used_expr.size != replace_with_copy.size:
                    new_idx = None if self._ail_manager is None else next(self._ail_manager.atom_ctr)
                    replace_with_copy = Convert(
                        new_idx,
                        replace_with_copy.bits,
                        used_expr.bits,
                        False,
                        replace_with_copy,
                    )

                r, new_block = self._replace_expr_and_update_block(
                    the_block, u.stmt_idx, stmt, def_, u, used_expr, replace_with_copy
                )
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

    @staticmethod
    def _find_atom_def_at(atom, rd, codeloc: CodeLocation) -> Optional[Definition]:
        if isinstance(atom, Register):
            defs = rd.get_defs(atom, codeloc, OP_BEFORE)
            return next(iter(defs)) if len(defs) == 1 else None

        return None

    @staticmethod
    def _check_atom_last_def(atom, codeloc, rd, the_def) -> bool:
        if isinstance(atom, Register):
            defs = rd.get_defs(atom, codeloc, OP_BEFORE)
            for d in defs:
                if d.codeloc != the_def.codeloc:
                    return False

        return True

    #
    # Folding call expressions
    #

    @staticmethod
    def _is_expr_using_temporaries(expr: Expression) -> bool:
        walker = AILBlockTempCollector()
        walker.walk_expression(expr)
        return len(walker.temps) > 0

    @staticmethod
    def _is_stmt_using_temporaries(stmt: Statement) -> bool:
        walker = AILBlockTempCollector()
        walker.walk_statement(stmt)
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

        s0 can be folded into the condition, which means this example can further be transformed to::

            if (func()) ...

        this behavior is controlled by fold_callexprs_into_conditions. This to avoid cases where func() is called more
        than once after simplification and graph structuring where conditions might be duplicated (e.g., in Dream).
        In such cases, the one-use expression folder in RegionSimplifier will perform this transformation.
        """

        simplified = False

        prop = self._compute_propagation()
        if not prop.model.equivalence:
            return simplified

        addr_and_idx_to_block: Dict[Tuple[int, int], Block] = {}
        for block in self.func_graph.nodes():
            addr_and_idx_to_block[(block.addr, block.idx)] = block

        def_locations_to_remove: Set[CodeLocation] = set()
        updated_use_locations: Set[CodeLocation] = set()

        eq: Equivalence
        for eq in prop.model.equivalence:
            # register variable == Call
            if isinstance(eq.atom0, Register):
                call_addr: Optional[int]
                if isinstance(eq.atom1, Call):
                    # register variable = Call
                    call: Expression = eq.atom1
                    call_addr = call.target.value if isinstance(call.target, Const) else None
                elif isinstance(eq.atom1, Convert) and isinstance(eq.atom1.operand, Call):
                    # register variable = Convert(Call)
                    call = eq.atom1
                    call_addr = call.operand.target.value if isinstance(call.operand.target, Const) else None
                else:
                    continue

                if self._is_expr_using_temporaries(call):
                    continue

                if eq.codeloc in updated_use_locations:
                    # this def is now created by an updated use. the corresponding statement will be updated in the end.
                    # we must rerun Propagator to get an updated definition (and Equivalence)
                    continue

                # find the definition of this register
                rd = self._compute_reaching_definitions()
                defs = [
                    d
                    for d in rd.all_definitions
                    if d.codeloc == eq.codeloc
                    and isinstance(d.atom, atoms.Register)
                    and d.atom.reg_offset == eq.atom0.reg_offset
                ]
                if not defs or len(defs) > 1:
                    continue
                the_def: Definition = defs[0]

                # find all uses of this definition
                all_uses: Set[Tuple[CodeLocation, Any]] = set(rd.all_uses.get_uses_with_expr(the_def))

                if len(all_uses) != 1:
                    continue
                u, used_expr = next(iter(all_uses))
                if used_expr is None:
                    continue

                if u in def_locations_to_remove:
                    # this use site has been altered by previous folding attempts. the corresponding statement will be
                    # removed in the end. in this case, this Equivalence is probably useless, and we must rerun
                    # Propagator to get an updated Equivalence.
                    continue

                if not self._fold_callexprs_into_conditions:
                    # check the statement and make sure it's not a conditional jump
                    the_block = addr_and_idx_to_block[(u.block_addr, u.block_idx)]
                    if isinstance(the_block.statements[u.stmt_idx], ConditionalJump):
                        continue

                # check if the use and the definition is within the same supernode
                super_node_blocks = self._get_super_node_blocks(
                    addr_and_idx_to_block[(the_def.codeloc.block_addr, the_def.codeloc.block_idx)]
                )
                if u.block_addr not in {b.addr for b in super_node_blocks}:
                    continue

                # check if the register has been overwritten by statements in between the def site and the use site
                usesite_atom_defs = set(rd.get_defs(the_def.atom, u, OP_BEFORE))
                if len(usesite_atom_defs) != 1:
                    continue
                usesite_atom_def = next(iter(usesite_atom_defs))
                if usesite_atom_def != the_def:
                    continue

                # check if any atoms that the call relies on has been overwritten by statements in between the def site
                # and the use site.
                defsite_all_expr_uses = set(rd.all_uses.get_uses_by_location(the_def.codeloc))
                defsite_used_atoms = set()
                for dd in defsite_all_expr_uses:
                    defsite_used_atoms.add(dd.atom)
                usesite_expr_def_outdated = False
                for defsite_expr_atom in defsite_used_atoms:
                    usesite_expr_uses = set(rd.get_defs(defsite_expr_atom, u, OP_BEFORE))
                    if not usesite_expr_uses:
                        # the atom is not defined at the use site - it's fine
                        continue
                    defsite_expr_uses = set(rd.get_defs(defsite_expr_atom, the_def.codeloc, OP_BEFORE))
                    if usesite_expr_uses != defsite_expr_uses:
                        # special case: ok if this atom is assigned to at the def site and has not been overwritten
                        if len(usesite_expr_uses) == 1:
                            usesite_expr_use = next(iter(usesite_expr_uses))
                            if usesite_expr_use.atom == defsite_expr_atom and (
                                usesite_expr_use.codeloc == the_def.codeloc
                                or usesite_expr_use.codeloc.block_addr == call_addr
                            ):
                                continue
                        usesite_expr_def_outdated = True
                        break
                if usesite_expr_def_outdated:
                    continue

                # check if there are any calls in between the def site and the use site
                if self._count_calls_in_supernodeblocks(super_node_blocks, the_def.codeloc, u) > 0:
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
                    dst: Expression = call

                    if src.bits != dst.bits:
                        dst = Convert(None, dst.bits, src.bits, False, dst)
                else:
                    continue

                # ensure what we are going to replace only appears once
                expr_ctr = SingleExpressionCounter(stmt, src)
                if expr_ctr.count > 1:
                    continue

                replaced, new_block = self._replace_expr_and_update_block(
                    the_block, u.stmt_idx, stmt, the_def, u, src, dst
                )

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
        lst: List[Block] = [start_node]
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

    def _replace_expr_and_update_block(
        self, block, stmt_idx, stmt, the_def, codeloc, src_expr, dst_expr
    ) -> Tuple[bool, Optional[Block]]:
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
        stmts_to_remove_per_block: Dict[Tuple[int, int], Set[int]] = defaultdict(set)

        # Find all statements that should be removed
        mask = (1 << self.project.arch.bits) - 1

        rd = self._compute_reaching_definitions()
        stackarg_offsets = (
            {(tpl[1] & mask) for tpl in self._stack_arg_offsets} if self._stack_arg_offsets is not None else None
        )
        def_: Definition
        for def_ in rd.all_definitions:
            if def_.dummy:
                continue
            # we do not remove references to global memory regions no matter what
            if isinstance(def_.atom, atoms.MemoryLocation) and isinstance(def_.atom.addr, int):
                continue
            if isinstance(def_.atom, atoms.MemoryLocation):
                if not self._remove_dead_memdefs:
                    # we always remove definitions for stack arguments
                    if stackarg_offsets is not None and isinstance(def_.atom.addr, atoms.SpOffset):
                        if (def_.atom.addr.offset & mask) not in stackarg_offsets:
                            continue
                    else:
                        continue

            uses = rd.all_uses.get_uses(def_)

            if not uses:
                if not isinstance(def_.codeloc, ExternalCodeLocation):
                    stmts_to_remove_per_block[(def_.codeloc.block_addr, def_.codeloc.block_idx)].add(
                        def_.codeloc.stmt_idx
                    )

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

            new_statements = []
            stmts_to_remove = stmts_to_remove_per_block[(block.addr, block.idx)]

            if not stmts_to_remove:
                continue

            for idx, stmt in enumerate(block.statements):
                if idx in stmts_to_remove and not isinstance(stmt, DirtyStatement):
                    if isinstance(stmt, (Assignment, Store)):
                        # Skip Assignment and Store statements
                        # if this statement triggers a call, it should only be removed if it's in self._calls_to_remove
                        codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.ins_addr, block_idx=block.idx)
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
                        codeloc = CodeLocation(block.addr, idx, ins_addr=stmt.ins_addr, block_idx=block.idx)
                        if codeloc in self._calls_to_remove:
                            # this call can be removed
                            simplified = True
                            continue

                        if stmt.ret_expr is not None:
                            # the return expr is not used. it should not have return expr
                            if stmt.fp_ret_expr is not None:
                                # maybe its fp_ret_expr is used?
                                stmt = stmt.copy()
                                stmt.ret_expr = stmt.fp_ret_expr
                                stmt.fp_ret_expr = None
                            else:
                                # clear ret_expr
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

        def _handle_expr(
            expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement, block
        ) -> Optional[Expression]:
            if isinstance(expr, DirtyExpression) and isinstance(expr.dirty_expr, VEXCCallExpression):
                rewriter = rewriter_cls(expr.dirty_expr, self.project.arch)
                if rewriter.result is not None:
                    _any_update.v = True
                    return rewriter.result
                else:
                    return None

            return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        blocks_by_addr_and_idx = {(node.addr, node.idx): node for node in self.func_graph.nodes()}

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

    @staticmethod
    def _expression_has_call_exprs(expr: Expression) -> bool:
        def _handle_callexpr(expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
            raise HasCallNotification()

        walker = AILBlockWalker()
        walker.expr_handlers[Call] = _handle_callexpr
        try:
            walker.walk_expression(expr)
        except HasCallNotification:
            return True

        return False

    @staticmethod
    def _count_calls_in_supernodeblocks(blocks: List[Block], start: CodeLocation, end: CodeLocation) -> int:
        """
        Count the number of call statements in a list of blocks for a single super block between two given code
        locations (exclusive).
        """
        calls = 0
        started = False
        for b in blocks:
            if b.addr == start.block_addr:
                started = True
                continue
            if b.addr == end.block_addr:
                started = False
                continue

            if started:
                if b.statements and isinstance(b.statements[-1], Call):
                    calls += 1
        return calls


AnalysesHub.register_default("AILSimplifier", AILSimplifier)
