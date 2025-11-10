from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional, Tuple

from angr.ailment import Assignment, Expression, Statement, Block, UnaryOp
from angr.ailment.expression import VirtualVariable, Load, BasePointerOffset, StackBaseOffset, BinaryOp, Const
from angr.ailment.statement import Store, Call, ConditionalJump

from angr.rust.utils.ail import unwrap_stack_vvar_reference, CallFinder


@dataclass
class StackDefinition:
    data: Expression
    stmt: Statement
    stmt_idx: int
    block: Block


class DFAMixin:
    """
    Data Flow Analysis Helper
    """

    def __init__(self, graph=None):
        self.graph = graph

    def _extract_operands(self, expr):
        if isinstance(expr, BinaryOp) and expr.op == "Add" and isinstance(expr.operands[1], Const):
            return expr.operands[0], expr.operands[1].value
        return expr, 0

    def _get_simple_path(self, last_block):
        assert self.graph
        preds = list(self.graph.predecessors(last_block))
        path = [last_block]
        if len(preds) == 1:
            pred = next(iter(preds))
            if len(list(self.graph.successors(pred))) == 1:
                path = self._get_simple_path(pred) + path
        return path

    def collect_stack_defs_at(self, block):
        """
        Collect stack definitions at specific block
        """
        stack_defs = OrderedDict()
        for idx, stmt in enumerate(block.statements):
            dst_vvar, data = self.extract_write_to_stack_vvar(stmt)
            if dst_vvar and data and dst_vvar.stack_offset not in stack_defs:
                stack_defs[dst_vvar.stack_offset] = StackDefinition(data, stmt, idx, block)
        return stack_defs

    @staticmethod
    def _has_call(stmt):
        finder = CallFinder()
        finder.walk_statement(stmt)
        return finder.call is not None

    def _collect_callsite_stmts(self, callsite_block):
        assert self.graph
        found_call = False
        stmts = []
        cur_block = callsite_block
        while not (found_call and cur_block.statements and self._has_call(cur_block.statements[-1])):
            for idx, stmt in enumerate(reversed(cur_block.statements)):
                idx = len(cur_block.statements) - idx - 1
                if not found_call:
                    if self._has_call(stmt):
                        found_call = True
                else:
                    stmts.append((stmt, idx, cur_block))
            preds = list(self.graph.predecessors(cur_block))
            if len(preds) == 1:
                pred = next(iter(preds))
                if len(list(self.graph.successors(pred))) == 1:
                    cur_block = pred
                    continue
            break
        return stmts

    def collect_callsite_stack_defs(self, callsite_block, max_blocks=1):
        """
        Collect stack variable definitions at a given callsite
        """
        stack_defs = OrderedDict()
        visited_blocks = set()
        for stmt, idx, block in self._collect_callsite_stmts(callsite_block):
            if stack_defs:
                visited_blocks.add(block)
                if len(visited_blocks) > max_blocks:
                    break
            dst_vvar, data = self.extract_write_to_stack_vvar(stmt)
            if dst_vvar and data and dst_vvar.stack_offset not in stack_defs:
                stack_defs[dst_vvar.stack_offset] = StackDefinition(data, stmt, idx, block)
        return stack_defs

    def extract_write_to_stack_vvar(self, stmt) -> Tuple[Optional[VirtualVariable], Optional[Expression]]:
        if isinstance(stmt, Assignment):
            if isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                return stmt.dst, stmt.src
            # Workaround for this weird case:
            # Load(addr=(Reference vvar_1485{stack -4456}), size=8, endness=Iend_LE) = (Reference vvar_142{reg 72})
            if isinstance(stmt.dst, Load) and isinstance(stmt.dst.addr, UnaryOp) and stmt.dst.addr.op == "Reference":
                real_dst = stmt.dst.addr.operand
                if isinstance(real_dst, VirtualVariable) and real_dst.was_stack:
                    return real_dst, stmt.src
        elif isinstance(stmt, Store):
            if dst := unwrap_stack_vvar_reference(stmt.addr):
                return dst, stmt.data
        return None, None

    def extract_stack_data_flow(self, stmt):
        dst_offset = None
        src_offset = None
        size = None
        dst, src = None, None
        if isinstance(stmt, Assignment):
            dst = stmt.dst
            src = stmt.src
            size = stmt.src.size
        elif isinstance(stmt, Store):
            dst = stmt.addr
            src = stmt.data
            size = stmt.data.size
        if dst and src:
            if isinstance(dst, VirtualVariable) and dst.was_stack:
                dst_offset = dst.stack_offset
            elif isinstance(dst, StackBaseOffset):
                dst_offset = dst.offset
            if isinstance(src, VirtualVariable) and src.was_stack:
                src_offset = src.stack_offset
            elif isinstance(src, Load) and isinstance(src.addr, BasePointerOffset):
                src_offset = src.addr.offset
        if dst_offset is not None and src_offset is not None and size is not None:
            return dst_offset, src_offset, size
        return None, None, None

    def find_reg_ptr_to_reg_data_flow(self, block, reg_vvar):
        for stmt in block.statements:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_reg
                and isinstance(stmt.src, Load)
            ):
                vvar, offset = self._extract_operands(stmt.src.addr)
                if isinstance(vvar, VirtualVariable) and vvar.likes(reg_vvar):
                    return stmt.dst, vvar, offset, stmt
        return None, None, None, None

    def find_stack_data_flow(self, block, src_offset, size):
        cur_size = 0
        flows = []
        stmts = []
        distance = set()
        for stmt in block.statements:
            stmt_dst_offset, stmt_src_offset, stmt_size = self.extract_stack_data_flow(stmt)
            if stmt_dst_offset is not None and stmt_src_offset is not None and stmt_size is not None:
                if src_offset + size > stmt_src_offset >= src_offset:
                    cur_size += stmt_size
                    flows.append((stmt_dst_offset, stmt_src_offset, stmt_size))
                    stmts.append(stmt)
                    distance.add(stmt_dst_offset - stmt_src_offset)
                    if cur_size >= size:
                        break
            else:
                cur_size = 0
                flows = []
                stmts = []
                distance = set()
        if cur_size == size and len(distance) == 1:
            dst_offset = src_offset + next(iter(distance))
            return stmts, dst_offset
        return None, None

    def extract_stack_to_reg_data_flow(self, stmt):
        src_offset = None
        size = None
        dst, src = None, None
        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_reg:
            dst = stmt.dst
            src = stmt.src
            size = stmt.src.size
        if dst and src:
            if isinstance(src, VirtualVariable) and src.was_stack:
                src_offset = src.stack_offset
            elif isinstance(src, Load) and isinstance(src.addr, BasePointerOffset):
                src_offset = src.addr.offset
        if dst is not None and src_offset is not None and size is not None:
            return dst, src_offset, size
        return None, None, None

    def find_stack_to_reg_data_flow(self, block, src_offset, size):
        for stmt in block.statements:
            dst, stmt_src_offset, stmt_size = self.extract_stack_to_reg_data_flow(stmt)
            if dst and stmt_src_offset == src_offset and stmt_size == size:
                return stmt, dst
        return None, None

    def get_def_block_and_stmt(self, data):
        for block in self.graph.nodes:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and stmt.src is data:
                    return block, stmt
        return None, None
