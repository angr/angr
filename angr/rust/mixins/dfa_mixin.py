from ailment import Assignment
from ailment.expression import VirtualVariable, Load, BasePointerOffset, StackBaseOffset, BinaryOp, Const
from ailment.statement import Store


class DFAMixin:
    """
    Data Flow Analysis Helper
    """

    def __init__(self):
        pass

    def _extract_operands(self, expr):
        if isinstance(expr, BinaryOp) and expr.op == "Add" and isinstance(expr.operands[1], Const):
            return expr.operands[0], expr.operands[1].value
        return expr, 0

    def extract_stack_dest_data_flow(self, stmt):
        dst_offset = None
        dst, src = None, None
        if isinstance(stmt, Assignment):
            dst = stmt.dst
            src = stmt.src
        elif isinstance(stmt, Store):
            dst = stmt.addr
            src = stmt.data
        if dst and src:
            if isinstance(dst, VirtualVariable) and dst.was_stack:
                dst_offset = dst.stack_offset
            elif isinstance(dst, StackBaseOffset):
                dst_offset = dst.offset
        if dst_offset is not None and src is not None:
            return dst_offset, src
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
