# pylint:disable=no-self-use
from __future__ import annotations
from typing import TYPE_CHECKING
from collections import deque

from angr.ailment.expression import Call, Const, StackBaseOffset, VirtualVariable, Load, UnaryOp
from angr.ailment.statement import Assignment, Store, SideEffectStatement, NoOp
from angr import SIM_LIBRARIES
from .optimization_pass import OptimizationPass, OptimizationPassStage
from .inlined_strcpy_simplifier import collect_constant_stores, stride_to_int

if TYPE_CHECKING:
    from angr.ailment.block import Block


class InlinedMemcpySimplifier(OptimizationPass):
    """
    Simplifies inlined data copying logic into calls to memcpy.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined memcpy"
    DESCRIPTION = "Simplify inlined memcpy patterns into memcpy calls"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return not self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        for block in list(self._graph):
            new_statements = []
            changed = False
            for stmt in block.statements:
                replacement = self._optimize_stmt_16b_store(stmt)
                if replacement is not None:
                    new_statements.append(replacement)
                    changed = True
                else:
                    new_statements.append(stmt)
            if changed:
                new_block = block.copy(statements=new_statements)
                self._update_block(block, new_block)

    def _optimize_stmt_16b_store(self, stmt):
        should_replace = False
        dst_offset, src_offset, store_size = None, None, None

        if (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and stmt.dst.size == 16
            and isinstance(stmt.src, Load)
        ):
            dst_offset = stmt.dst.stack_offset
            store_size = stmt.dst.size
            if (
                isinstance(stmt.src.addr, UnaryOp)
                and stmt.src.addr.op == "Reference"
                and isinstance(stmt.src.addr.operand, VirtualVariable)
                and stmt.src.addr.operand.was_stack
            ):
                should_replace = True
                src_offset = stmt.src.addr.operand.stack_offset
            elif isinstance(stmt.src.addr, StackBaseOffset):
                should_replace = True
                src_offset = stmt.src.addr.offset

        if (
            isinstance(stmt, Store)
            and isinstance(stmt.addr, StackBaseOffset)
            and stmt.size == 16
            and isinstance(stmt.data, Load)
        ):
            dst_offset = stmt.addr.offset
            store_size = stmt.size
            if (
                isinstance(stmt.data.addr, UnaryOp)
                and stmt.data.addr.op == "Reference"
                and isinstance(stmt.data.addr.operand, VirtualVariable)
            ):
                should_replace = True
                src_offset = stmt.data.addr.operand.stack_offset
            elif isinstance(stmt.data.addr, StackBaseOffset):
                should_replace = True
                src_offset = stmt.data.addr.offset

        if should_replace:
            assert dst_offset is not None and src_offset is not None and store_size is not None
            return SideEffectStatement(
                stmt.idx,
                Call(
                    stmt.idx,
                    "memcpy",
                    calling_convention=None,
                    args=[
                        StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, dst_offset),
                        StackBaseOffset(self.manager.next_atom(), self.project.arch.bits, src_offset),
                        Const(self.manager.next_atom(), None, store_size, self.project.arch.bits),
                    ],
                    prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("memcpy", arch=self.project.arch),
                    bits=None,
                    **stmt.tags,
                ),
                ret_expr=None,
                fp_ret_expr=None,
                **stmt.tags,
            )

        return None


class InlinedMemcpySimplifierLate(InlinedMemcpySimplifier):
    """
    Same as InlinedMemcpySimplifier but runs after SSA level 1 transformation.
    """

    STAGE = OptimizationPassStage.AFTER_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify inlined memcpy (late)"

    def _analyze(self, cache=None):
        super()._analyze(cache=cache)

        # find consecutive assignments across blocks and merge them into a single memcpy call
        # we do it after SSA level 1 to avoid having to deal with stack variable aliasing

        # find consecutive regions
        regions: list[list[Block]] = self._get_sese_blocks()

        for region in regions:
            # TODO: during the store statement scan, stop at critical statements that may affect aliasing
            # TODO: Provide knobs to control how aggressively we create memcpy calls

            all_constant_stores = {}
            for block in region:
                for offset, (stmt_idx, data) in collect_constant_stores(
                    block.statements, 0, self.project.arch.memory_endness
                ).items():
                    all_constant_stores[offset] = block.addr, stmt_idx, data

            if not all_constant_stores:
                continue

            offsets = sorted(all_constant_stores.keys())
            next_offset = min(offsets)
            strides = []
            stride = []
            for offset in offsets:
                if next_offset is not None and offset != next_offset:
                    next_offset = None
                    if len(stride):
                        strides.append(stride)
                    stride = []
                baddr, sidx, v = all_constant_stores[offset]
                if v is not None:
                    stride.append((offset, (baddr, sidx), v))
                    next_offset = offset + v.size
                else:
                    next_offset = None
                    if len(stride):
                        strides.append(stride)
                    stride = []
            if len(stride):
                strides.append(stride)

            if not strides:
                return None

            # construct a memcpy call for each stride over 16 bytes, and remove the corresponding statements
            for stride in strides:
                integer, size = stride_to_int(stride)
                if size >= 16:
                    min_stack_off = min(off for off, _loc, _value in stride)
                    data = integer.to_bytes(size, "big")
                    memcpy_dst = StackBaseOffset(None, self.project.arch.bits, min_stack_off)
                    data_id = self.kb.custom_strings.allocate(data)
                    memcpy_stmt = SideEffectStatement(
                        self.manager.next_atom(),
                        Call(
                            self.manager.next_atom(),
                            "memcpy",
                            calling_convention=None,
                            args=[
                                memcpy_dst,
                                Const(None, None, data_id, self.project.arch.bits, custom_string=True),
                                Const(self.manager.next_atom(), None, size, self.project.arch.bits),
                            ],
                            prototype=SIM_LIBRARIES["libc.so"][0].get_prototype("memcpy", arch=self.project.arch),
                            bits=None,
                            ins_addr=stride[0][1][0],
                        ),
                        ret_expr=None,
                        fp_ret_expr=None,
                        ins_addr=stride[0][1][0],
                    )

                    for _, (block_addr, stmt_idx), _ in stride:
                        block = self._get_block(block_addr)
                        stmt = block.statements[stmt_idx]
                        block.statements[stmt_idx] = NoOp(None, **stmt.tags)

                    last_block_addr, last_stmt_idx = stride[-1][1]
                    block = self._get_block(last_block_addr)
                    block.statements[last_stmt_idx] = memcpy_stmt

    def _get_sese_blocks(self) -> list[list[Block]]:
        """
        Get single-entry-single-exit block regions in the function.
        """
        visited = set()
        regions = []

        entry = self._get_block(self.entry_node_addr[0], idx=self.entry_node_addr[1])

        queue = deque([(entry, [entry])])
        while queue:
            block, region = queue.popleft()
            if (block.addr, block.idx) in visited:
                if region:
                    regions.append(region)
                continue
            visited.add((block.addr, block.idx))

            succs = list(self._graph.successors(block))
            if len(succs) == 1 and succs[0] != block:
                queue.append((succs[0], [*region, succs[0]]))
            elif len(succs) == 0:
                if region:
                    regions.append(region)
            else:
                if region:
                    regions.append(region)
                for succ in succs:
                    if (succ.addr, succ.idx) in visited:
                        continue
                    visited.add((block.addr, block.idx))
                    queue.append((succ, [succ]))

        return regions
