from typing import Dict, Optional

from ailment import Const
from ailment.expression import BinaryOp, VirtualVariable, VirtualVariableCategory
from ailment.statement import Store, Assignment, Call, ConditionalJump, Label, Jump

from .base import TransformationPass, SRDAHelper
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from ..ailment.expression import String


class SimplificationState:
    def __init__(self, context: "AllocSimplifier", alloc_block, alloc_call):
        self.context = context
        self.alloc_block = alloc_block
        self.alloc_call = alloc_call

        self.alloc_size = None
        self.alloc_align = None
        args = self.alloc_call.args
        if len(args) >= 1:
            self.alloc_size = args[0]
        if len(args) >= 2:
            self.alloc_align = args[1]
        # Statements that initiate the allocated heap memory
        self.init_stmts = []
        # Statements that construct the final object
        self.construct_stmts = []

    def _try_outline_string(self):
        if self.alloc_align is None or (isinstance(self.alloc_align, Const) and self.alloc_align.value == 1):
            if isinstance(self.alloc_size, Const):
                alloc_size = self.alloc_size.value
                init_bytes = bytearray(b"\x00" * alloc_size)
                for stmt in self.init_stmts:
                    if isinstance(stmt, Store) and isinstance(stmt.data, Const):
                        vvar, offset = self.context.extract_vvar_and_offset(stmt.addr)
                        data = stmt.data.value.to_bytes(stmt.data.size, self.context.endian)
                        init_bytes[offset : offset + stmt.data.size] = data
                try:
                    decoded_str = init_bytes.decode()
                    data = String(None, None, 0, self.context.project.arch.bits, decoded_str)
                    call = Call(
                        idx=None,
                        target="String::from",
                        prototype=self.context.librust.get_prototype("String::from").with_arch(
                            self.context.project.arch
                        ),
                        args=[data],
                        ret_expr=None,
                        **self.construct_stmts[0].tags,
                    )
                    call.bits = 3 * self.context.project.arch.bits
                    return call
                except UnicodeDecodeError:
                    pass
        return None

    def _try_outline_vec(self):
        return None

    def outline(self):
        if len(self.construct_stmts) != 3:
            return None, (None, None)

        dst = None
        category = None
        if all(isinstance(stmt, Store) for stmt in self.construct_stmts):
            dst = self.construct_stmts[0].addr
            category = "Store"
        elif all(isinstance(stmt, Assignment) for stmt in self.construct_stmts):
            dst = self.construct_stmts[0].dst
            category = "Assignment"

        outline_result = self._try_outline_string()

        replacement = None
        if outline_result:
            if category == "Store":
                replacement = Store(
                    None,
                    dst,
                    outline_result,
                    size=3 * self.context.project.arch.bits,
                    endness=self.context.endian,
                    **self.construct_stmts[0].tags,
                )
            elif category == "Assignment":
                vvar_id = self.context.vvar_id_start
                self.context.vvar_id_start += 1
                vvar_bits = self.context.project.arch.bits * 3
                dst_vvar = VirtualVariable(
                    None,
                    vvar_id,
                    vvar_bits,
                    VirtualVariableCategory.STACK,
                    oident=dst.stack_offset,
                    **self.construct_stmts[0].tags,
                )
                replacement = Assignment(idx=None, dst=dst_vvar, src=outline_result, **dst_vvar.tags)

        if replacement:
            stmts_to_remove = set(self.init_stmts).union(self.construct_stmts[1:])
            stmts_to_remove.add(self.alloc_block.statements[-1])
            stmt_to_replace = (self.construct_stmts[0], replacement)
            return stmts_to_remove, stmt_to_replace

        return None, (None, None)


RUST_ALLOC_FUNCTIONS = ["__rust_alloc"]
RUST_ALLOC_ERROR_HANDLING_FUNCTIONS = ["alloc::raw_vec::handle_error", "alloc::alloc::handle_alloc_error"]


class AllocSimplifier(TransformationPass, SRDAHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory Allocation Simplifier"

    def __init__(self, func, **kwargs):
        TransformationPass.__init__(self, func, **kwargs)
        SRDAHelper.__init__(self, self)

        self.states: Dict[Call, SimplificationState] = {}
        self.librust = SIM_LIBRARIES["librust"]

        self._used_construct_stmts = set()
        self._stmt_to_block = {}

        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _match_alloc_region(self, block) -> SimplificationState | None:
        if block.statements:
            terminal = block.statements[-1]
            if (
                isinstance(terminal, Assignment)
                and isinstance(terminal.dst, VirtualVariable)
                and isinstance(terminal.src, Call)
                and self.match_call(terminal, RUST_ALLOC_FUNCTIONS)
                and self.num_successors(block) == 1
            ):
                alloc_call = terminal.src
                return SimplificationState(self, block, alloc_call)
        return None

    def extract_vvar_and_offset(self, expr) -> [Optional[VirtualVariable], Optional[int]]:
        if (
            isinstance(expr, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operands[0], VirtualVariable)
            and isinstance(expr.operands[1], Const)
        ):
            return expr.operands[0], expr.operands[1].value
        elif isinstance(expr, VirtualVariable):
            return expr, 0
        return None, None

    def _find_init_stmts(self, block):
        for stmt in block.statements:
            if isinstance(stmt, Store):
                vvar, offset = self.extract_vvar_and_offset(stmt.addr)
                value = self.get_real_vvar_value(vvar)
                if value in self.states:
                    state = self.states[value]
                    state.init_stmts.append(stmt)

    def _check_construct_stmts(self, stmts, store_alloc_ptr_idx):
        if any(stmt in self._used_construct_stmts for stmt in stmts):
            return False
        if all(isinstance(stmt, Store) for stmt in stmts):
            vvars_and_offsets = [self.extract_vvar_and_offset(stmt.addr) for stmt in stmts]
            vvars = set(vvar for vvar, offset in vvars_and_offsets)
            offsets = [offset for vvar, offset in vvars_and_offsets]
            data = [stmt.data for stmt in stmts]
            data.pop(store_alloc_ptr_idx)
            if (
                len(vvars) == 1
                and None not in offsets
                and offsets[2] - offsets[0] == self.project.arch.bytes * 2
                and offsets[2] - offsets[1] == self.project.arch.bytes
                and len(data) == 2
            ):
                return data[0].likes(data[1])
        elif all(isinstance(stmt, Assignment) for stmt in stmts):
            vvars = [stmt.dst for stmt in stmts]
            if all(isinstance(vvar, VirtualVariable) and vvar.was_stack for vvar in vvars):
                offsets = [vvar.stack_offset for vvar in vvars]
                data = [stmt.src for stmt in stmts]
                data.pop(store_alloc_ptr_idx)
                if (
                    len(vvars) == 3
                    and offsets[2] - offsets[0] == self.project.arch.bytes * 2
                    and offsets[2] - offsets[1] == self.project.arch.bytes
                    and data[0].likes(data[1])
                ):
                    return True
        return False

    def _find_construct_stmts(self, block):
        for idx, stmt in enumerate(block.statements):
            stmt_ahead, stmt_ahead_ahead, stmt_back, stmt_back_back = None, None, None, None
            if idx - 1 >= 0:
                stmt_ahead = block.statements[idx - 1]
            if idx - 2 >= 0:
                stmt_ahead_ahead = block.statements[idx - 2]
            if idx + 1 < len(block.statements):
                stmt_back = block.statements[idx + 1]
            if idx + 2 < len(block.statements):
                stmt_back_back = block.statements[idx + 2]
            if isinstance(stmt, Store) or isinstance(stmt, Assignment):
                vvar = stmt.data if isinstance(stmt, Store) else stmt.src
                value = self.get_real_vvar_value(vvar)
                if value in self.states:
                    state = self.states[value]
                    store_alloc_ptr = stmt
                    construct_stmts = None
                    if self._check_construct_stmts([stmt_ahead_ahead, stmt_ahead, store_alloc_ptr], 2):
                        construct_stmts = [stmt_ahead_ahead, stmt_ahead, store_alloc_ptr]
                    elif self._check_construct_stmts([stmt_ahead, store_alloc_ptr, stmt_back], 1):
                        construct_stmts = [stmt_ahead, store_alloc_ptr, stmt_back]
                    elif self._check_construct_stmts([store_alloc_ptr, stmt_back, stmt_back_back], 0):
                        construct_stmts = [store_alloc_ptr, stmt_back, stmt_back_back]
                    if construct_stmts:
                        state.construct_stmts = construct_stmts
                        self._used_construct_stmts = self._used_construct_stmts.union(construct_stmts)

    def _get_real_jump_target(self, target, target_idx):
        if isinstance(target, Const):
            block_addr = target.value
            block_idx = target_idx
            visited = set()
            visited_blocks = []
            while (block_addr, block_idx) not in visited:
                visited.add((block_addr, block_idx))
                block = self.blocks_by_addr_and_idx[(block_addr, block_idx)]
                visited_blocks.append(block)
                if (
                    all(isinstance(stmt, Label) or isinstance(stmt, Jump) for stmt in block.statements)
                    and self.num_successors(block) == 1
                ):
                    succ = self.get_one_successor(block)
                    block_addr = succ.addr
                    block_idx = succ.idx
                else:
                    return visited_blocks, block
        return None, None

    def _remove_alloc_error_handling_blocks(self):
        error_handling_blocks = set()
        for block in self._graph.nodes:
            if self.match_call(block, RUST_ALLOC_ERROR_HANDLING_FUNCTIONS):
                error_handling_blocks.add(block)

        blocks_to_remove = set(error_handling_blocks)

        for block in self._graph.nodes:
            if block.statements and isinstance(jump := block.statements[-1], ConditionalJump):
                true_visited_blocks, true_block = self._get_real_jump_target(jump.true_target, jump.true_target_idx)
                false_visited_blocks, false_block = self._get_real_jump_target(jump.false_target, jump.false_target_idx)
                if true_block in error_handling_blocks and false_block not in error_handling_blocks:
                    self.replace_jump_target(block, true_visited_blocks[0], false_block)
                    blocks_to_remove |= set(true_visited_blocks)
                elif false_block in error_handling_blocks and true_block not in error_handling_blocks:
                    self.replace_jump_target(block, false_visited_blocks[0], true_block)
                    blocks_to_remove |= set(false_visited_blocks)

        for block in blocks_to_remove:
            self._remove_block(block)

    def _analyze(self, cache=None):
        self._remove_alloc_error_handling_blocks()

        for block in self._graph.nodes:
            for stmt in block.statements:
                self._stmt_to_block[stmt] = block

        for block in self._graph.nodes:
            state = self._match_alloc_region(block)
            if state:
                self.states[state.alloc_call] = state

        for block in self._graph.nodes:
            self._find_init_stmts(block)
            self._find_construct_stmts(block)

        for state in self.states.values():
            stmts_to_remove, (old_stmt, replacement) = state.outline()
            if stmts_to_remove is not None:
                for stmt in stmts_to_remove:
                    if stmt in self._stmt_to_block:
                        block = self._stmt_to_block[stmt]
                        block.statements.remove(stmt)
                        self._stmt_to_block.pop(stmt)
                if old_stmt in self._stmt_to_block:
                    block = self._stmt_to_block[old_stmt]
                    idx = block.statements.index(old_stmt)
                    block.statements[idx] = replacement

        self.out_graph = self._graph
