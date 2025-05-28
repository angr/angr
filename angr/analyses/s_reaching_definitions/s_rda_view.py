from __future__ import annotations

import logging
from collections.abc import Callable
from collections import defaultdict

from angr.ailment import Block
from angr.ailment.statement import Statement, Assignment, Call, Label
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory, Expression

from angr.utils.ail import is_phi_assignment
from angr.utils.graph import GraphUtils
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType, ObservationPoint
from angr.utils.ssa import get_reg_offset_base
from angr.calling_conventions import SimRegArg, default_cc

from .s_rda_model import SRDAModel

log = logging.getLogger(__name__)


class RegVVarPredicate:
    """
    Implements a predicate that is used in get_reg_vvar_by_stmt_idx and get_reg_vvar_by_insn.
    """

    def __init__(self, reg_offset: int, vvars: list[VirtualVariable], arch):
        self.reg_offset = reg_offset
        self.vvars = vvars
        self.arch = arch

    def _get_call_clobbered_regs(self, stmt: Call) -> set[int]:
        cc = stmt.calling_convention
        if cc is None:
            # get the default calling convention
            cc = default_cc(self.arch.name)  # TODO: platform and language
        if cc is not None:
            reg_list = cc.CALLER_SAVED_REGS
            if isinstance(cc.RETURN_VAL, SimRegArg):
                reg_list.append(cc.RETURN_VAL.reg_name)
            return {self.arch.registers[reg_name][0] for reg_name in reg_list}
        log.warning("Cannot determine registers that are clobbered by call statement %r.", stmt)
        return set()

    def predicate(self, stmt: Statement) -> bool:
        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_reg
            and stmt.dst.reg_offset == self.reg_offset
        ):
            if stmt.dst not in self.vvars:
                self.vvars.append(stmt.dst)
            return True
        if isinstance(stmt, Call):
            if (
                isinstance(stmt.ret_expr, VirtualVariable)
                and stmt.ret_expr.was_reg
                and stmt.ret_expr.reg_offset == self.reg_offset
            ):
                if stmt.ret_expr not in self.vvars:
                    self.vvars.append(stmt.ret_expr)
                return True
            # is it clobbered maybe?
            clobbered_regs = self._get_call_clobbered_regs(stmt)
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

    def get_reg_vvar_by_stmt(
        self, reg_offset: int, block_addr: int, block_idx: int | None, stmt_idx: int, op_type: ObservationPointType
    ) -> VirtualVariable | None:
        reg_offset = get_reg_offset_base(reg_offset, self.model.arch)
        vvars = []
        predicater = RegVVarPredicate(reg_offset, vvars, self.model.arch)
        self._get_vvar_by_stmt(block_addr, block_idx, stmt_idx, op_type, predicater.predicate)

        if not vvars:
            # not found - check function arguments
            for func_arg in self.model.func_args:
                if isinstance(func_arg, VirtualVariable):
                    func_arg_category = func_arg.parameter_category
                    if func_arg_category == VirtualVariableCategory.REGISTER:
                        func_arg_regoff = func_arg.parameter_reg_offset
                        if func_arg_regoff == reg_offset:
                            vvars.append(func_arg)

        assert len(vvars) <= 1
        return vvars[0] if vvars else None

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

            if (op_type == ObservationPointType.OP_BEFORE and stmt.ins_addr == addr) or (
                op_type == ObservationPointType.OP_AFTER and stmt.ins_addr > addr
            ):
                starting_stmt_idx = stmt_idx
                break

        self._get_vvar_by_stmt(the_block.addr, the_block.idx, starting_stmt_idx, op_type, predicate)

    def get_reg_vvar_by_insn(
        self, reg_offset: int, addr: int, op_type: ObservationPointType, block_idx: int | None = None
    ) -> VirtualVariable | None:
        reg_offset = get_reg_offset_base(reg_offset, self.model.arch)
        vvars = []
        predicater = RegVVarPredicate(reg_offset, vvars, self.model.arch)

        self._get_vvar_by_insn(addr, op_type, predicater.predicate, block_idx=block_idx)

        assert len(vvars) <= 1
        return vvars[0] if vvars else None

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

    def observe(self, observation_points: list[ObservationPoint]):
        insn_ops: dict[int, ObservationPointType] = {op[1]: op[2] for op in observation_points if op[0] == "insn"}
        stmt_ops: dict[tuple[tuple[int, int | None], int], ObservationPointType] = {
            op[1]: op[2] for op in observation_points if op[0] == "stmt"
        }
        node_ops: dict[tuple[int, int | None], ObservationPointType] = {
            op[1]: op[2] for op in observation_points if op[0] == "node"
        }
        # TODO: Other types

        traversal_order = GraphUtils.quasi_topological_sort_nodes(self.model.func_graph)
        all_reg2vvarid: defaultdict[tuple[int, int | None], dict[int, int]] = defaultdict(dict)

        observations = {}
        for block in traversal_order:
            reg2vvarid = all_reg2vvarid[block.addr, block.idx]

            if (block.addr, block.idx) in node_ops and node_ops[
                (block.addr, block.idx)
            ] == ObservationPointType.OP_BEFORE:
                observations[("block", (block.addr, block.idx), ObservationPointType.OP_BEFORE)] = reg2vvarid.copy()

            last_insn_addr = None
            for stmt_idx, stmt in enumerate(block.statements):
                if last_insn_addr != stmt.ins_addr:
                    # observe
                    if last_insn_addr in insn_ops and insn_ops[last_insn_addr] == ObservationPointType.OP_AFTER:
                        observations[("insn", last_insn_addr, ObservationPointType.OP_AFTER)] = reg2vvarid.copy()
                    if stmt.ins_addr in insn_ops and insn_ops[stmt.ins_addr] == ObservationPointType.OP_BEFORE:
                        observations[("insn", last_insn_addr, ObservationPointType.OP_BEFORE)] = reg2vvarid.copy()
                    last_insn_addr = stmt.ins_addr

                stmt_key = (block.addr, block.idx), stmt_idx
                if stmt_key in stmt_ops and stmt_ops[stmt_key] == ObservationPointType.OP_BEFORE:
                    observations[("stmt", stmt_key, ObservationPointType.OP_BEFORE)] = reg2vvarid.copy()

                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg:
                    base_offset = get_reg_offset_base(stmt.dst.reg_offset, self.model.arch)
                    reg2vvarid[base_offset] = stmt.dst.varid
                elif isinstance(stmt, Call) and isinstance(stmt.ret_expr, VirtualVariable) and stmt.ret_expr.was_reg:
                    base_offset = get_reg_offset_base(stmt.ret_expr.reg_offset, self.model.arch)
                    reg2vvarid[base_offset] = stmt.ret_expr.varid

                if stmt_key in stmt_ops and stmt_ops[stmt_key] == ObservationPointType.OP_AFTER:
                    observations[("stmt", stmt_key, ObservationPointType.OP_AFTER)] = reg2vvarid.copy()

            if (block.addr, block.idx) in node_ops and node_ops[
                (block.addr, block.idx)
            ] == ObservationPointType.OP_AFTER:
                observations[("block", (block.addr, block.idx), ObservationPointType.OP_AFTER)] = reg2vvarid.copy()

            for succ in self.model.func_graph.successors(block):
                if succ is block:
                    continue
                all_reg2vvarid[succ.addr, succ.idx] = reg2vvarid.copy()

        return observations
