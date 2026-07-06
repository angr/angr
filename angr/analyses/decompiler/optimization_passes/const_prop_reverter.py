from __future__ import annotations

import itertools
import logging

import claripy

from angr.ailment import Block, Const
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Call, Convert, Expression, Load, Register
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Store
from angr.analyses.decompiler.structuring import DreamStructurer, SAILRStructurer
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(__name__)


class BlockWalker(AILBlockViewer):
    def __init__(self, walked_objs: dict[type, set[SideEffectStatement | Assignment | Return | Store]]):
        super().__init__()
        self.walked_objs = walked_objs

    def _handle_SideEffectStatement(self, stmt_idx, stmt: SideEffectStatement, block):
        self.walked_objs[SideEffectStatement].add(stmt)

    def _handle_Assignment(self, stmt_idx, stmt: Assignment, block):
        src = stmt.src
        if isinstance(src, Convert):
            src = src.operand
        if isinstance(src, Call):
            self.walked_objs[Assignment].add(stmt)

    def _handle_Store(self, stmt_idx, stmt: Store, block):
        src = stmt.data
        if isinstance(src, Convert):
            src = src.operand
        if isinstance(src, Call):
            self.walked_objs[Store].add(stmt)

    def _handle_Return(self, stmt_idx, stmt: Return, block):
        self.walked_objs[Return].add(stmt)


class ConstPropOptReverter(OptimizationPass):
    """
    This optimization reverts the effects of constant propagation done by the compiler as discussed in the
    USENIX 2024 paper SAILR. This optimization's main goal is to enable later optimizations that rely on
    symbolic variables to be more effective. This optimization pass will convert two statements with a difference of
    a const and a symbolic variable into two statements with the symbolic variables.

    As an example:
    x = 75
    puts(x)
    puts(75)

    will be converted to:
    x = 75
    puts(x)
    puts(x)
    """

    ARCHES = None
    PLATFORMS = None
    # allow DREAM since it's useful for return merging
    STRUCTURING = [SAILRStructurer.NAME, DreamStructurer.NAME]
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Revert Constant Propagation Optimizations"
    DESCRIPTION = __doc__.strip()

    def __init__(self, *args, region_identifier=None, reaching_definitions=None, **kwargs):
        self.ri = region_identifier
        self.rd = reaching_definitions
        super().__init__(*args, **kwargs)

        self._call_pair_targets = []
        self.resolution = False
        self.analyze()

    def _check(self):
        return True, {}

    def _analyze(self, cache=None):
        self.resolution = False
        self.out_graph = self._graph.copy()

        if self.out_graph is None:
            return

        # find pairs of SideEffectStatements and Returns
        call_sets, return_set = self._find_candidate_pairs()

        # handle pairs of potentially similar calls
        for call_set in call_sets:
            for (call0, blk0), (call1, blk1) in itertools.combinations(call_set, 2):
                if call0 is call1:
                    continue
                self._handle_CallStatement_pair(call0, blk0, call1, blk1)

        if self._call_pair_targets:
            self._analyze_call_pair_targets()

        # handle pairs of potentially similar returns
        for ret0, blk0 in return_set:
            for ret1, blk1 in return_set:
                if ret0 is ret1:
                    continue
                self._handle_Return_pair(ret0, blk0, ret1, blk1)

        if not self.resolution:
            self.out_graph = None

    def _find_candidate_pairs(
        self,
    ) -> tuple[list[set[tuple[SideEffectStatement | Assignment | Store, Block]]], set[tuple[Return, Block]]]:
        call_sets: dict[
            str, set[tuple[SideEffectStatement | Assignment | Store, Block]]
        ] = {}  # organized by function call target
        return_set: set[tuple[Return, Block]] = set()

        # walk the graph to collect all calls and returns
        call_stmt_and_blocks = set()
        for blk in self._graph:
            walked_objs = {
                SideEffectStatement: set(),
                Assignment: set(),
                Store: set(),
                Return: set(),
            }
            walker = BlockWalker(walked_objs)
            walker.walk(blk)

            for call_stmt in walked_objs[SideEffectStatement] | walked_objs[Assignment] | walked_objs[Store]:
                call_stmt_and_blocks.add((call_stmt, blk))
            for ret_stmt in walked_objs[Return]:
                return_set.add((ret_stmt, blk))

        # now, let's group the calls
        for call_stmt, blk in call_stmt_and_blocks:
            assert isinstance(call_stmt, (SideEffectStatement, Assignment, Store))
            call_expr = self._get_callexpr_from_stmt(call_stmt)
            if call_expr is None:
                continue
            key = str(call_expr.target)
            if key not in call_sets:
                call_sets[key] = set()
            call_sets[key].add((call_stmt, blk))

        return list(call_sets.values()), return_set

    def _analyze_call_pair_targets(self):
        all_obs_points = []
        for _, observation_points in self._call_pair_targets:
            all_obs_points.extend(observation_points)
        all_obs_points = list(set(all_obs_points))

        self.rd = self.project.analyses.ReachingDefinitions(
            subject=self._func,
            func_graph=self._graph,
            observation_points=all_obs_points,
            dep_graph=None,
            track_liveness=False,
            variable_map=variable_map_of(self.manager),
        )

        for (call0, blk0, call1, blk1, arg_conflicts), _ in self._call_pair_targets:
            # attempt to do constant resolution for each argument that differs
            for i, args in arg_conflicts.items():
                a0, a1 = args[:]
                calls = {a0: call0, a1: call1}
                blks = {call0: blk0, call1: blk1}

                # we can only resolve two arguments where one is constant and one is symbolic
                const_arg = None
                sym_arg = None
                for arg in calls:
                    if isinstance(arg, Const) and const_arg is None:
                        const_arg = arg
                    elif not isinstance(arg, Const) and sym_arg is None:
                        sym_arg = arg

                if const_arg is None or sym_arg is None:
                    continue

                unwrapped_sym_arg = sym_arg.operands[0] if isinstance(sym_arg, Convert) else sym_arg
                if (
                    isinstance(unwrapped_sym_arg, Load)
                    and isinstance(unwrapped_sym_arg.addr, Const)
                    and isinstance(unwrapped_sym_arg.addr.value, int)
                ):
                    # TODO: make this support more than just Loads
                    # target must be a Load of a memory location
                    target_atom = MemoryLocation(unwrapped_sym_arg.addr.value, unwrapped_sym_arg.size, "Iend_LE")
                    const_state = self.rd.get_reaching_definitions_by_node(blks[calls[const_arg]].addr, OP_BEFORE)
                    state_load_vals = const_state.get_values(target_atom)
                else:
                    continue

                if not state_load_vals:
                    continue

                state_vals = list(state_load_vals.values())
                # the symbolic variable MUST resolve to only a single value
                if len(state_vals) != 1:
                    continue

                state_val = next(iter(state_vals[0]))
                if hasattr(state_val, "concrete") and state_val.concrete:
                    const_value = claripy.Solver().eval(state_val, 1)[0]
                else:
                    continue

                if const_value != const_arg.value:
                    continue

                _l.debug("Constant argument at position %d was resolved to symbolic arg %s", i, sym_arg)
                const_call = calls[const_arg]
                # Capture the containing block before mutating ``const_call``
                # below -- the in-place ``.args =`` assignment clears
                # ``const_call``'s cached hash and invalidates the
                # ``blks`` dict lookup that's keyed on it.
                const_call_blk = blks[const_call]
                const_arg_i = const_call.args.index(const_arg)
                const_call.args = (*const_call.args[:const_arg_i], sym_arg, *const_call.args[const_arg_i + 1 :])
                # Mutating ``const_call.args`` writes to the fresh
                # wrapper materialized by ``stmt.expr`` -- the actual stored
                # ``Call`` keeps its original args and the reverter no-ops.
                # Rebuild the containing statement's call expression
                # explicitly so the new args land in the block.
                self._rewrite_call_in_block(const_call_blk, const_call)
                self.resolution = True

    #
    # Handle Similar Returns
    #

    def _handle_Return_pair(self, obj0: Return, blk0: Block, obj1: Return, blk1: Block):
        if obj0 is obj1:
            return

        rexp0, rexp1 = obj0.ret_exprs, obj1.ret_exprs
        if rexp0 is None or rexp1 is None or len(rexp0) != len(rexp1):
            return

        conflicts = {
            i: ret_exprs
            for i, ret_exprs in enumerate(zip(rexp0, rexp1))
            if hasattr(ret_exprs[0], "likes") and not ret_exprs[0].likes(ret_exprs[1])
        }
        # only single expr return is supported
        if len(conflicts) != 1:
            return

        _, ret_exprs = next(iter(conflicts.items()))
        expr_to_blk = {ret_exprs[0]: blk0, ret_exprs[1]: blk1}
        # find the expression that is symbolic
        symb_expr, const_expr = None, None
        for expr in ret_exprs:
            unpacked_expr = expr
            if isinstance(expr, Convert):
                unpacked_expr = expr.operands[0]

            if isinstance(unpacked_expr, (Const, Call)):
                const_expr = expr
            else:
                symb_expr = expr

        if symb_expr is None or const_expr is None:
            return

        # now we do specific cases for matching
        const_ret_expr = getattr(const_expr, "ret_expr", None)
        if isinstance(symb_expr, Register) and isinstance(const_expr, Call) and isinstance(const_ret_expr, Register):
            # Handles the following case
            #   B0:
            #   return foo();   // considered constant
            #   B1:
            #   return rax;     // considered symbolic
            #
            #   =>
            #
            #   B0:
            #   rax = foo();
            #   return rax;
            #   B1:
            #   return rax;
            #
            # This is useful later for merging the return.
            #
            call_return_reg = const_ret_expr
            if symb_expr.likes(call_return_reg):
                symb_return_stmt = expr_to_blk[symb_expr].statements[-1]
                const_block = expr_to_blk[const_expr]

                # rax = foo();
                reg_assign = Assignment(self.manager.next_atom(), symb_expr, const_expr, **const_expr.tags)

                # construct new constant block
                new_const_block = const_block.copy()
                new_const_block.statements = [*new_const_block.statements[:-1], reg_assign, symb_return_stmt.copy()]
                self._update_block(const_block, new_const_block)
                self.resolution = True
        else:
            _l.debug("This case is not supported yet for Return de-propagation")

    #
    # Handle Similar Calls
    #

    def _handle_CallStatement_pair(
        self,
        stmt0: SideEffectStatement | Assignment | Store,
        blk0,
        stmt1: SideEffectStatement | Assignment | Store,
        blk1,
    ):

        obj0 = self._get_callexpr_from_stmt(stmt0)
        obj1 = self._get_callexpr_from_stmt(stmt1)

        if obj0 is None or obj1 is None or obj0 is obj1:
            return
        if not isinstance(obj0, Call) or not isinstance(obj1, Call):
            return

        # verify both calls are calls to the same function
        if isinstance(obj0.target, Expression) and isinstance(obj1.target, Expression):
            if not obj0.target.likes(obj1.target):
                return
        elif obj0.target != obj1.target:
            return

        call0, call1 = obj0, obj1
        arg_conflicts = self.find_conflicting_call_args(call0, call1)
        # if there is no conflict, then there is nothing to fix
        if not arg_conflicts:
            return

        # Only keep conflicts that _analyze_call_pair_targets can handle
        resolvable_conflicts = {i: args for i, args in arg_conflicts.items() if self._is_resolvable_conflict(args)}
        if not resolvable_conflicts:
            return

        _l.debug(
            "Found two calls at (%x, %x) that are similar. Attempting to resolve const args now...",
            blk0.addr,
            blk1.addr,
        )

        # destroy old ReachDefs, since we need a new one
        observation_points = ("node", blk0.addr, OP_BEFORE), ("node", blk1.addr, OP_BEFORE)

        # do full analysis after collecting all calls in _analyze
        self._call_pair_targets.append(((call0, blk0, call1, blk1, resolvable_conflicts), observation_points))

    @staticmethod
    def _is_resolvable_conflict(args) -> bool:
        """A conflict is resolvable by _analyze_call_pair_targets iff one argument is a constant and
        the other is (a Convert of) a Load from a constant address.
        Update this method when _analyze_call_pair_targets is more powerful!
        """
        a0, a1 = args
        const_arg = sym_arg = None
        for arg in (a0, a1):
            if isinstance(arg, Const) and const_arg is None:
                const_arg = arg
            elif not isinstance(arg, Const) and sym_arg is None:
                sym_arg = arg
        if const_arg is None or sym_arg is None:
            return False
        unwrapped = sym_arg.operands[0] if isinstance(sym_arg, Convert) else sym_arg
        return (
            isinstance(unwrapped, Load) and isinstance(unwrapped.addr, Const) and isinstance(unwrapped.addr.value, int)
        )

    @staticmethod
    def find_conflicting_call_args(call0: Call, call1: Call):
        if not call0.args or not call1.args:
            return None

        # TODO: update this to work for variable-arg functions
        if len(call0.args) != len(call1.args):
            return None

        # zip args of call 0 and 1 conflict if they are not like each other
        return {i: args for i, args in enumerate(zip(call0.args, call1.args)) if not args[0].likes(args[1])}

    def _rewrite_call_in_block(self, blk: Block, updated_call: Call) -> None:
        """Find the statement in ``blk`` whose call expression has
        the same ``idx`` as ``updated_call`` and rebuild it with the
        mutated call. Identity through ``.idx`` is necessary because
        ``stmt.expr`` materializes a fresh ``Expression`` wrapper each
        access, so we can't compare statement-side calls to
        ``updated_call`` by Python identity.
        """
        target_idx = updated_call.idx
        for i, stmt in enumerate(blk.statements):
            existing_call = self._get_callexpr_from_stmt(stmt)
            if existing_call is None or existing_call.idx != target_idx:
                continue
            if isinstance(stmt, SideEffectStatement):
                new_stmt = SideEffectStatement(
                    stmt.idx,
                    updated_call,
                    ret_expr=stmt.ret_expr,
                    fp_ret_expr=stmt.fp_ret_expr,
                    **stmt.tags,
                )
            elif isinstance(stmt, Assignment):
                src = stmt.src
                if isinstance(src, Convert):
                    new_inner = Convert(
                        src.idx,
                        src.from_bits,
                        src.to_bits,
                        src.is_signed,
                        updated_call,
                        from_type=src.from_type,
                        to_type=src.to_type,
                        rounding_mode=src.rounding_mode,
                        **src.tags,
                    )
                else:
                    new_inner = updated_call
                new_stmt = Assignment(stmt.idx, stmt.dst, new_inner, **stmt.tags)
            elif isinstance(stmt, Store):
                data = stmt.data
                if isinstance(data, Convert):
                    new_data = Convert(
                        data.idx,
                        data.from_bits,
                        data.to_bits,
                        data.is_signed,
                        updated_call,
                        from_type=data.from_type,
                        to_type=data.to_type,
                        rounding_mode=data.rounding_mode,
                        **data.tags,
                    )
                else:
                    new_data = updated_call
                new_stmt = Store(
                    stmt.idx,
                    stmt.addr,
                    new_data,
                    stmt.size,
                    stmt.endness,
                    guard=stmt.guard,
                    **stmt.tags,
                )
            else:
                continue
            blk.statements[i] = new_stmt
            return

    @staticmethod
    def _get_callexpr_from_stmt(stmt: SideEffectStatement | Assignment | Store) -> Call | None:
        if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
            return stmt.expr
        if isinstance(stmt, Assignment):
            src = stmt.src
            if isinstance(src, Convert):
                src = src.operand
            if isinstance(src, Call):
                return src
        if isinstance(stmt, Store):
            data = stmt.data
            if isinstance(data, Convert):
                data = data.operand
            if isinstance(data, Call):
                return data
        return None
