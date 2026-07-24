from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal

import networkx

from angr.ailment import Block
from angr.ailment.expression import Call, Const, Expression, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Label, SideEffectStatement, Statement
from angr.calling_conventions import SimRegArg, call_clobbered_regs, default_cc
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.utils.ail import is_phi_assignment
from angr.utils.graph import GraphUtils
from angr.utils.ssa import get_reg_offset_base, stmt_is_simple_call

from .s_rda_model import SRDAModel

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function_manager import FunctionManager

log = logging.getLogger(__name__)

_RegDef = tuple[int, int, int]
_StmtRegEffects = tuple[tuple[_RegDef, ...], frozenset[int]]
type _SRDAObservationPoint = (
    tuple[Literal["insn"], int, ObservationPointType]
    | tuple[Literal["stmt"], tuple[tuple[int, int | None], int], ObservationPointType]
    | tuple[Literal["node"], tuple[int, int | None], ObservationPointType]
)


def _copy_reg2vvarid(reg2vvarid: dict[int, dict[int, int]]) -> dict[int, dict[int, int]]:
    """Fast deep copy of a reg2vvarid map.

    ``reg2vvarid`` is always a ``dict[int, dict[int, int]]`` (register base offset -> {size -> vvar id}); all keys and
    values are immutable ints. ``copy.deepcopy`` works but its generic machinery (memo dict, ``_keep_alive``,
    per-object dispatch) dominates SReachingDefinitions runtime because ``observe`` copies this map at every graph edge
    and observation point. A two-level dict comprehension is semantically identical and far cheaper.
    """
    return {offset: sizes.copy() for offset, sizes in reg2vvarid.items()}


def get_call_clobbered_regs(
    call: Call, variable_map, functions: FunctionManager | None, arch, platform: str | None, language: str | None
) -> set[int]:
    if isinstance(call.target, str):
        # pseudo calls do not clobber any registers
        return set()
    cc = variable_map.calling_convention(call) if variable_map is not None else None
    if cc is None:
        # get the default calling convention
        cc_cls = default_cc(arch.name, platform=platform, language=language)
        if cc_cls is not None:
            cc = cc_cls(arch)
    if cc is not None:
        # try to get the function
        func = None
        if functions is not None and isinstance(call.target, Const) and functions.contains_addr(call.target.value_int):
            func = functions.get_by_addr(call.target.value_int, meta_only=True)
        reg_list = call_clobbered_regs(cc, func, arch)
        if isinstance(cc.RETURN_VAL, SimRegArg):
            # do not update reg_list directly, otherwise you may update cc.CALLER_SAVED_REGS!
            reg_list = [*reg_list, cc.RETURN_VAL.reg_name]
        return {arch.registers[reg_name][0] for reg_name in reg_list}
    log.warning("Cannot determine registers that are clobbered by call expression %r.", call)
    return set()


class RegVVarPredicate:
    """
    Implements a predicate that is used in get_reg_vvar_by_stmt_idx and get_reg_vvar_by_insn.
    """

    def __init__(
        self,
        reg_offset: int,
        min_size: int,
        vvars: list[VirtualVariable],
        arch,
        platform: str | None = None,
        language: str | None = None,
        variable_map=None,
        functions: FunctionManager | None = None,
    ):
        self.reg_offset = reg_offset
        self.min_size = min_size
        self.vvars = vvars
        self.arch = arch
        self.platform = platform
        self.language = language
        self.variable_map = variable_map
        self.functions = functions

    def predicate(self, stmt: Statement) -> bool:
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_reg
            and stmt.dst.reg_offset == self.reg_offset
            and stmt.dst.size >= self.min_size
        ):
            if stmt.dst not in self.vvars:
                self.vvars.append(stmt.dst)
            return True
        if isinstance(stmt, SideEffectStatement):
            for return_expr in (stmt.ret_expr, stmt.fp_ret_expr):
                if (
                    isinstance(return_expr, VirtualVariable)
                    and return_expr.was_reg
                    and return_expr.reg_offset == self.reg_offset
                    and return_expr.size >= self.min_size
                ):
                    if return_expr not in self.vvars:
                        self.vvars.append(return_expr)
                    return True
        if (call := stmt_is_simple_call(stmt)) is not None:
            # A matching explicit result definition above takes precedence because call clobbers happen before result
            # definitions. Otherwise the call is a barrier for earlier definitions of caller-saved registers,
            # including when simplification has folded it into an Assignment wrapper.
            clobbered_regs = get_call_clobbered_regs(
                call, self.variable_map, self.functions, self.arch, self.platform, self.language
            )
            if self.reg_offset in clobbered_regs:
                return True
        return False


class StackVVarPredicate:
    """
    Implements a predicate that is used in get_stack_vvar_by_stmt_idx and get_stack_vvar_by_insn.
    """

    def __init__(self, stack_offset: int, size: int, vvars: list[VirtualVariable]):
        self.stack_offset = stack_offset
        self.size = size
        self.vvars = vvars

    def predicate(self, stmt: Statement) -> bool:
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and stmt.dst.stack_offset <= self.stack_offset < stmt.dst.stack_offset + stmt.dst.size
            and stmt.dst.stack_offset <= self.stack_offset + self.size <= stmt.dst.stack_offset + stmt.dst.size
        ):
            if stmt.dst not in self.vvars:
                self.vvars.append(stmt.dst)
            return True
        return False


class SRDAView:
    """
    A view of SRDA model that provides various functionalities for querying the model.
    """

    def __init__(self, model: SRDAModel):
        self.model = model
        self._traversal_order: list[Block] | None = None
        # caches for the dominance-based observe() fast path (func_graph is immutable for this view's lifetime)
        self._idoms: dict[Block, Block] | None = None
        self._block_reg_effects: dict[tuple[int, int | None], tuple[_StmtRegEffects, ...]] = {}
        self._blocks_by_key: dict[tuple[int, int | None], Block] | None = None

    def _get_vvar_by_stmt(
        self,
        block_addr: int,
        block_idx: int | None,
        stmt_idx: int,
        op_type: ObservationPointType,
        predicate: Callable,
        consecutive: bool = False,
    ):
        # find the starting block
        for block in self.model.func_graph:
            if block.addr == block_addr and block.idx == block_idx:
                the_block = block
                break
        else:
            return

        traversed = set()
        if stmt_idx == -1:
            # start from the end of the block
            stmt_idx = len(the_block.statements) - 1
        queue: list[tuple[Block, int | None]] = [
            (the_block, stmt_idx if op_type == ObservationPointType.OP_BEFORE else stmt_idx + 1)
        ]
        predicate_returned_true = False
        while queue:
            block, start_stmt_idx = queue.pop(0)
            traversed.add(block)

            stmts = block.statements[:start_stmt_idx] if start_stmt_idx is not None else block.statements

            for stmt in reversed(stmts):
                r = predicate(stmt)
                predicate_returned_true |= r
                should_break = (predicate_returned_true and r is False) if consecutive else r
                if should_break:
                    break
            else:
                # not found
                for pred in self.model.func_graph.predecessors(block):
                    if pred not in traversed:
                        traversed.add(pred)
                        queue.append((pred, None))

    @staticmethod
    def _pick_unique_reg_vvar(vvars: list[VirtualVariable], reg_offset: int, addr: int) -> VirtualVariable | None:
        """
        Return the unique virtual variable holding a register's value at a program point, or None if there is none.

        Multiple vvars mean multiple definitions of the register reach the program point without a phi node merging
        them. This legitimately happens when Ssailification deliberately passes up phi creation at a merge point
        (e.g., when the reaching definitions have inconsistent sizes, such as a def of sil vs. defs of rsi) on the
        assumption that the register is dead there, but a use is discovered only later (e.g., a variadic call
        argument identified by CallSiteMaker after SSA construction). In that case the register's value is
        path-dependent and cannot be represented by any single vvar, so we return None and let callers fall back to
        their register-expression path.
        """
        unique_varids = {vvar.varid for vvar in vvars}
        if len(unique_varids) > 1:
            log.debug(
                "Multiple virtual variables (%s) for register offset %d reach %#x without a phi node; there is no "
                "unique reaching definition.",
                sorted(unique_varids),
                reg_offset,
                addr,
            )
            return None
        return vvars[0] if vvars else None

    def get_reg_vvar_by_stmt(
        self,
        reg_offset: int,
        min_size: int,
        block_addr: int,
        block_idx: int | None,
        stmt_idx: int,
        op_type: ObservationPointType,
    ) -> VirtualVariable | None:
        reg_offset = get_reg_offset_base(reg_offset, self.model.arch)
        vvars = []
        predicater = RegVVarPredicate(
            reg_offset,
            min_size,
            vvars,
            self.model.arch,
            platform=self.model.platform,
            language=self.model.language,
            variable_map=self.model.variable_map,
            functions=self.model.functions,
        )
        self._get_vvar_by_stmt(block_addr, block_idx, stmt_idx, op_type, predicater.predicate)

        if not vvars:
            # not found - check function arguments
            for func_arg in self.model.func_args:
                if isinstance(func_arg, VirtualVariable):
                    func_arg_category = func_arg.parameter_category
                    if func_arg_category == VirtualVariableCategory.REGISTER:
                        func_arg_regoff = func_arg.parameter_reg_offset
                        if func_arg_regoff == reg_offset and func_arg.size >= min_size:
                            vvars.append(func_arg)

        return self._pick_unique_reg_vvar(vvars, reg_offset, block_addr)

    def get_stack_vvar_by_stmt(  # pylint: disable=too-many-positional-arguments
        self,
        stack_offset: int,
        size: int,
        block_addr: int,
        block_idx: int | None,
        stmt_idx: int,
        op_type: ObservationPointType,
    ) -> VirtualVariable | None:
        vvars = []
        predicater = StackVVarPredicate(stack_offset, size, vvars)
        self._get_vvar_by_stmt(block_addr, block_idx, stmt_idx, op_type, predicater.predicate, consecutive=True)

        if not vvars:
            # not found - check function arguments
            for func_arg in self.model.func_args:
                if isinstance(func_arg, VirtualVariable):
                    func_arg_category = func_arg.parameter_category
                    if func_arg_category == VirtualVariableCategory.STACK:
                        func_arg_stackoff = func_arg.oident[1]  # type: ignore
                        if func_arg_stackoff == stack_offset and func_arg.size == size:
                            vvars.append(func_arg)
        # there might be multiple vvars; we prioritize the one whose size fits the best
        for v in vvars:
            if (
                (v.was_stack and v.stack_offset == stack_offset)
                or (v.was_parameter and v.parameter_stack_offset == stack_offset)
            ) and v.size == size:
                return v
        return vvars[0] if vvars else None

    def _get_vvar_by_insn(self, addr: int, op_type: ObservationPointType, predicate, block_idx: int | None = None):
        # find the starting block
        for block in self.model.func_graph:
            if block.idx == block_idx and block.addr <= addr < block.addr + block.original_size:
                the_block = block
                break
        else:
            return

        # determine the starting stmt_idx
        starting_stmt_idx = len(the_block.statements) if op_type == ObservationPointType.OP_AFTER else 0
        for stmt_idx, stmt in enumerate(the_block.statements):
            # skip all labels and phi assignments
            if isinstance(stmt, Label) or is_phi_assignment(stmt):
                if op_type == ObservationPointType.OP_BEFORE:
                    # ensure that we tick starting_stmt_idx forward
                    starting_stmt_idx = stmt_idx
                continue

            if (op_type == ObservationPointType.OP_BEFORE and stmt.tags["ins_addr"] == addr) or (
                op_type == ObservationPointType.OP_AFTER and stmt.tags["ins_addr"] > addr
            ):
                starting_stmt_idx = stmt_idx
                break

        self._get_vvar_by_stmt(the_block.addr, the_block.idx, starting_stmt_idx, op_type, predicate)

    def get_reg_vvar_by_insn(
        self, reg_offset: int, min_size: int, addr: int, op_type: ObservationPointType, block_idx: int | None = None
    ) -> VirtualVariable | None:
        reg_offset = get_reg_offset_base(reg_offset, self.model.arch)
        vvars = []
        predicater = RegVVarPredicate(
            reg_offset,
            min_size,
            vvars,
            self.model.arch,
            platform=self.model.platform,
            language=self.model.language,
            variable_map=self.model.variable_map,
            functions=self.model.functions,
        )

        self._get_vvar_by_insn(addr, op_type, predicater.predicate, block_idx=block_idx)

        return self._pick_unique_reg_vvar(vvars, reg_offset, addr)

    def get_stack_vvar_by_insn(  # pylint: disable=too-many-positional-arguments
        self, stack_offset: int, size: int, addr: int, op_type: ObservationPointType, block_idx: int | None = None
    ) -> VirtualVariable | None:
        vvars = []
        predicater = StackVVarPredicate(stack_offset, size, vvars)
        self._get_vvar_by_insn(addr, op_type, predicater.predicate, block_idx=block_idx)

        assert len(vvars) <= 1
        return vvars[0] if vvars else None

    def get_vvar_value(self, vvar: VirtualVariable) -> Expression | None:
        if vvar.varid not in self.model.all_vvar_definitions:
            return None
        codeloc = self.model.all_vvar_definitions[vvar.varid]

        for block in self.model.func_graph:
            if block.addr == codeloc.block_addr and block.idx == codeloc.block_idx:
                if codeloc.stmt_idx is not None and codeloc.stmt_idx < len(block.statements):
                    stmt = block.statements[codeloc.stmt_idx]
                    if isinstance(stmt, Assignment) and stmt.dst.likes(vvar):
                        return stmt.src
                break
        return None

    def observe(self, observation_points: list[_SRDAObservationPoint], entry: Block | None = None):
        insn_ops: dict[int, ObservationPointType] = {op[1]: op[2] for op in observation_points if op[0] == "insn"}
        stmt_ops: dict[tuple[tuple[int, int | None], int], ObservationPointType] = {
            op[1]: op[2] for op in observation_points if op[0] == "stmt"
        }
        node_ops: dict[tuple[int, int | None], ObservationPointType] = {
            op[1]: op[2] for op in observation_points if op[0] == "node"
        }
        # TODO: Other types

        # Fast path: dominance-based and demand-driven. Only the observed blocks are processed; the reg2vvarid reaching
        # a block's entry is the closest dominating definition per register (which in SSA is exactly the reaching
        # definition), so no whole-graph quasi-topological sort or per-edge map copy is needed. Requires an entry
        # block (to build the dominator tree); insn observation points fall back to the legacy forward path (resolving
        # an instruction address to its block(s) is only needed there -- SRDA's callers use only stmt/node points).
        if entry is None or insn_ops:
            return self._observe_forward(insn_ops, stmt_ops, node_ops)
        return self._observe_dominance(entry, stmt_ops, node_ops)

    def _observe_block(self, block, reg2vvarid, insn_ops, stmt_ops, node_ops, observations) -> None:
        """
        Walk one block forward from the given entry ``reg2vvarid`` (mutated in place), writing snapshots into
        ``observations`` at this block's node/insn/stmt observation points. Shared by both observe() paths so their
        per-block snapshot semantics are byte-for-byte identical; the paths differ only in how the entry map is seeded.
        """
        block_key = block.addr, block.idx

        if block_key in node_ops and node_ops[block_key] == ObservationPointType.OP_BEFORE:
            observations[("node", block_key, ObservationPointType.OP_BEFORE)] = _copy_reg2vvarid(reg2vvarid)

        block_reg_effects = self._get_block_reg_effects(block)
        last_insn_addr = None
        for stmt_idx, stmt in enumerate(block.statements):
            if last_insn_addr != stmt.tags["ins_addr"]:
                if last_insn_addr in insn_ops and insn_ops[last_insn_addr] == ObservationPointType.OP_AFTER:
                    observations[("insn", last_insn_addr, ObservationPointType.OP_AFTER)] = _copy_reg2vvarid(reg2vvarid)
                if (
                    stmt.tags["ins_addr"] in insn_ops
                    and insn_ops[stmt.tags["ins_addr"]] == ObservationPointType.OP_BEFORE
                ):
                    observations[("insn", last_insn_addr, ObservationPointType.OP_BEFORE)] = _copy_reg2vvarid(
                        reg2vvarid
                    )
                last_insn_addr = stmt.tags["ins_addr"]

            stmt_key = block_key, stmt_idx
            if stmt_key in stmt_ops and stmt_ops[stmt_key] == ObservationPointType.OP_BEFORE:
                observations[("stmt", stmt_key, ObservationPointType.OP_BEFORE)] = _copy_reg2vvarid(reg2vvarid)

            reg_defs, clobbered_regs = block_reg_effects[stmt_idx]
            for base_offset in clobbered_regs:
                reg2vvarid.pop(base_offset, None)
            for base_offset, size, varid in reg_defs:
                if base_offset not in reg2vvarid:
                    reg2vvarid[base_offset] = {}
                reg2vvarid[base_offset][size] = varid

            if stmt_key in stmt_ops and stmt_ops[stmt_key] == ObservationPointType.OP_AFTER:
                observations[("stmt", stmt_key, ObservationPointType.OP_AFTER)] = _copy_reg2vvarid(reg2vvarid)

        if block_key in node_ops and node_ops[block_key] == ObservationPointType.OP_AFTER:
            observations[("node", block_key, ObservationPointType.OP_AFTER)] = _copy_reg2vvarid(reg2vvarid)

    def _observe_forward(self, insn_ops, stmt_ops, node_ops):
        # The traversal order depends only on func_graph, which is immutable for the lifetime of this view. observe()
        # is frequently called more than once per analysis (e.g. call-site uses and callee-saved-register uses), and
        # the quasi-topological sort dominates observe(), so cache it across calls.
        if self._traversal_order is None:
            self._traversal_order = GraphUtils.quasi_topological_sort_nodes(self.model.func_graph)
        all_reg2vvarid: defaultdict[tuple[int, int | None], dict[int, dict[int, int]]] = defaultdict(dict)

        observations = {}
        for block in self._traversal_order:
            reg2vvarid = all_reg2vvarid[block.addr, block.idx]
            self._observe_block(block, reg2vvarid, insn_ops, stmt_ops, node_ops, observations)
            for succ in self.model.func_graph.successors(block):
                if succ is block:
                    continue
                all_reg2vvarid[succ.addr, succ.idx] = _copy_reg2vvarid(reg2vvarid)

        return observations

    def _get_block_reg_effects(self, block: Block) -> tuple[_StmtRegEffects, ...]:
        """
        Return cached register effects for each statement in ``block``.

        Definitions are stored in forward execution order. A call's clobbered base-register offsets are stored
        separately because forward observation applies the clobber before the statement's explicit return definition,
        while reverse dominator seeding must consider those definitions before treating the call as a barrier.
        """
        arch = self.model.arch
        block_key = block.addr, block.idx
        effects = self._block_reg_effects.get(block_key)
        if effects is not None:
            return effects

        stmt_effects = []
        for stmt in block.statements:
            reg_defs = []
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg:
                reg_defs.append((get_reg_offset_base(stmt.dst.reg_offset, arch), stmt.dst.size, stmt.dst.varid))
            elif isinstance(stmt, SideEffectStatement):
                for return_expr in (stmt.ret_expr, stmt.fp_ret_expr):
                    if isinstance(return_expr, VirtualVariable) and return_expr.was_reg:
                        reg_defs.append(
                            (
                                get_reg_offset_base(return_expr.reg_offset, arch),
                                return_expr.size,
                                return_expr.varid,
                            )
                        )

            call = stmt_is_simple_call(stmt)
            clobbered_regs = (
                frozenset(
                    get_reg_offset_base(reg_offset, arch)
                    for reg_offset in get_call_clobbered_regs(
                        call,
                        self.model.variable_map,
                        self.model.functions,
                        arch,
                        self.model.platform,
                        self.model.language,
                    )
                )
                if call is not None
                else frozenset()
            )
            stmt_effects.append((tuple(reg_defs), clobbered_regs))

        effects = tuple(stmt_effects)
        self._block_reg_effects[block_key] = effects
        return effects

    def _seed_from_dominators(self, block, idoms) -> dict[int, dict[int, int]]:
        """
        The register map reaching ``block``'s entry: for each ``(base register, size)``, the definition in the closest
        strict dominator that defines it. In SSA this is exactly the reaching definition at the block entry (phis are
        defs in the merge block and so are picked up by the in-block walk, not here). Calls form barriers for all
        earlier definitions of each clobbered base register; definitions at or after a call remain visible.
        """
        reg2vvarid: dict[int, dict[int, int]] = {}
        d = idoms.get(block)
        if d is None or d is block:
            # entry block (its immediate dominator is itself) or unreachable node: no strict dominators
            return reg2vvarid
        found: set[tuple[int, int]] = set()
        blocked_bases: set[int] = set()
        while True:
            for reg_defs, clobbered_regs in reversed(self._get_block_reg_effects(d)):
                # These definitions occur after the call's clobber in forward execution, so inspect them first while
                # scanning backward. Do not remove already-found post-call definitions when installing the barrier.
                for base, size, vid in reversed(reg_defs):
                    key = base, size
                    if base not in blocked_bases and key not in found:
                        found.add(key)
                        if base not in reg2vvarid:
                            reg2vvarid[base] = {}
                        reg2vvarid[base][size] = vid
                blocked_bases.update(clobbered_regs)

            nd = idoms.get(d)
            if nd is None or nd is d:
                break
            d = nd
        return reg2vvarid

    def _observe_dominance(self, entry, stmt_ops, node_ops):
        if self._idoms is None:
            self._idoms = networkx.immediate_dominators(self.model.func_graph, entry)
        idoms = self._idoms
        if self._blocks_by_key is None:
            self._blocks_by_key = {(b.addr, b.idx): b for b in self.model.func_graph}
        blocks_by_key = self._blocks_by_key

        observed_blocks: set[tuple[int, int | None]] = set(node_ops.keys())
        for block_key, _stmt_idx in stmt_ops:
            observed_blocks.add(block_key)

        observations = {}
        no_insn_ops: dict[int, ObservationPointType] = {}
        for block_key in observed_blocks:
            block = blocks_by_key.get(block_key)
            if block is None:
                continue
            reg2vvarid = self._seed_from_dominators(block, idoms)
            self._observe_block(block, reg2vvarid, no_insn_ops, stmt_ops, node_ops, observations)
        return observations
