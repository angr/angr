from ailment import Assignment
from ailment.expression import VirtualVariable, Load, BasePointerOffset


class DFAHelper:
    """
    Data Flow Analysis Helper
    """

    def __init__(self):
        pass

    def extract_stack_data_flow(self, stmt):
        dst_offset = None
        src_offset = None
        size = None
        if isinstance(stmt, Assignment):
            if isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                dst_offset = stmt.dst.stack_offset
            if isinstance(stmt.src, VirtualVariable) and stmt.src.was_stack:
                src_offset = stmt.src.stack_offset
            elif isinstance(stmt.src, Load) and isinstance(stmt.src.addr, BasePointerOffset):
                src_offset = stmt.src.addr.offset
            size = stmt.src.size
        return dst_offset, src_offset, size

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
