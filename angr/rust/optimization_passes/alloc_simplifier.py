from typing import Dict, Optional

import archinfo
from ailment import Const, AILBlockWalker, Block
from ailment.expression import BinaryOp, VirtualVariable, VirtualVariableCategory, StackBaseOffset, UnaryOp
from ailment.statement import Store, Assignment, Call, ConditionalJump, Label, Jump, Statement

from .base import TransformationPass, SSAVariableHelper
from ..mixins.srda_mixin import SRDAMixin
from ..ailment.statement import FunctionLikeMacro
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from ..ailment.expression import String


class VecIndexingWalker(AILBlockWalker):
    def __init__(self, raw_ptr_vvar, vec_vvar, element_size):
        super().__init__()
        self.raw_ptr_vvar = raw_ptr_vvar
        self.vec_vvar = vec_vvar
        self.element_size = element_size

    def _fix_idx_size(self, idx_expr):
        if isinstance(idx_expr, BinaryOp) and idx_expr.op == "Mul":
            op0 = idx_expr.operands[0]
            op1 = idx_expr.operands[1]
            if isinstance(op0, Const) and op0.value == self.element_size:
                return op1
            elif isinstance(op1, Const) and op1.value == self.element_size:
                return op0
        return None

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        new_expr = super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
        expr = expr if new_expr is None else new_expr
        if expr.op == "Add" and any(self.raw_ptr_vvar.likes(operand) for operand in expr.operands):
            idx_expr = expr.operands[0] if self.raw_ptr_vvar.likes(expr.operands[1]) else expr.operands[1]
            idx_expr = self._fix_idx_size(idx_expr)
            if idx_expr:
                new_expr = UnaryOp(
                    expr.idx,
                    "Reference",
                    BinaryOp(expr.idx, "Index", [self.vec_vvar, idx_expr], signed=False, bits=self.raw_ptr_vvar.bits),
                )
        return new_expr


class SimplificationState:
    def __init__(self, context: "AllocSimplifier", alloc_block, alloc_call):
        self.context = context
        self.alloc_block = alloc_block
        self.alloc_call = alloc_call

        self.alloc_size = None
        self.alloc_align = None
        self.vec_length = None
        args = self.alloc_call.args
        if len(args) >= 1:
            self.alloc_size = args[0]
        if len(args) >= 2:
            self.alloc_align = args[1]
        # Statements that initiate the allocated heap memory
        self.init_stmts = []
        # Statements that construct the final object
        self.construct_stmts = []
        self.raw_ptr_vvar = None
        self.vec_element_size = None

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
                    if decoded_str.isprintable():
                        data = String(None, None, 0, self.context.project.arch.bits, decoded_str)
                        call = Call(
                            idx=None,
                            target="String::from",
                            prototype=self.context.librust.get_prototype("String::from")
                            .with_arch(self.context.project.arch)
                            .normalize(),
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
        if isinstance(self.alloc_size, Const) and isinstance(self.vec_length, Const):
            vec_length = self.vec_length.value
            alloc_size = self.alloc_size.value
            if alloc_size % vec_length != 0:
                return None
            ele_size = alloc_size // vec_length
            self.vec_element_size = ele_size
            if all(isinstance(stmt, Store) and isinstance(stmt.data, Const) for stmt in self.init_stmts):
                init_bytes = bytearray(b"\x00" * alloc_size)
                for stmt in self.init_stmts:
                    if isinstance(stmt, Store):
                        vvar, offset = self.context.extract_vvar_and_offset(stmt.addr)
                        data = stmt.data.value.to_bytes(stmt.data.size, self.context.endian)
                        init_bytes[offset : offset + stmt.data.size] = data
                elements = []
                for i in range(vec_length):
                    endian = "big" if (self.context.project.arch.memory_endness == archinfo.Endness.BE) else "little"
                    element = int.from_bytes(init_bytes[i * ele_size : (i + 1) * ele_size], byteorder=endian)
                    element = Const(None, None, element, ele_size * self.context.project.arch.byte_width)
                    elements.append(element)
                macro = FunctionLikeMacro(
                    None,
                    "vec",
                    elements,
                    bits=alloc_size * self.context.project.arch.byte_width,
                    delimiter="[]",
                    **self.construct_stmts[-1].tags,
                )
                return macro
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
        if not outline_result:
            outline_result = self._try_outline_vec()

        replacement = None
        if isinstance(outline_result, Call) or isinstance(outline_result, FunctionLikeMacro):
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
                dst_vvar = self.context.new_stack_vvar(
                    dst.stack_offset, self.context.project.arch.bits * 3, self.construct_stmts[0].tags
                )
                if isinstance(outline_result, FunctionLikeMacro) and isinstance(self.raw_ptr_vvar, VirtualVariable):
                    self.context.raw_ptr_vvar_to_vec_vvar[self.raw_ptr_vvar] = dst_vvar
                replacement = Assignment(idx=None, dst=dst_vvar, src=outline_result, **dst_vvar.tags)

        if replacement:
            stmts_to_remove = set(self.init_stmts).union(self.construct_stmts[1:])
            stmts_to_remove.add(self.alloc_block.statements[-1])
            stmt_to_replace = (self.construct_stmts[0], replacement)
            return stmts_to_remove, stmt_to_replace

        return None, (None, None)


RUST_ALLOC_FUNCTIONS = ["__rust_alloc"]
RUST_ALLOC_ERROR_HANDLING_FUNCTIONS = ["alloc::raw_vec::handle_error", "alloc::alloc::handle_alloc_error"]


class AllocSimplifier(TransformationPass, SRDAMixin, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory Allocation Simplifier"

    def __init__(self, func, **kwargs):
        TransformationPass.__init__(self, func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        SSAVariableHelper.__init__(self, self)

        self.states: Dict[Call, SimplificationState] = {}
        self.librust = SIM_LIBRARIES["librust"]

        self._used_construct_stmts = set()
        self._stmt_to_block = {}
        self.raw_ptr_vvar_to_vec_vvar = {}

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
                value = self.get_terminal_vvar_value(vvar)
                if value in self.states:
                    state = self.states[value]
                    state.init_stmts.append(stmt)

    def _check_construct_stmts(self, stmts, store_alloc_ptr_idx):
        if any(stmt in self._used_construct_stmts for stmt in stmts):
            return None
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
                and data[0].likes(data[1])
            ):
                return data[0]
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
                    return data[0]
        return None

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
                value = self.get_terminal_vvar_value(vvar)
                if value in self.states:
                    state = self.states[value]
                    store_alloc_ptr = stmt
                    construct_stmts = None
                    if vec_length := self._check_construct_stmts([stmt_ahead_ahead, stmt_ahead, store_alloc_ptr], 2):
                        construct_stmts = [stmt_ahead_ahead, stmt_ahead, store_alloc_ptr]
                    elif vec_length := self._check_construct_stmts([stmt_ahead, store_alloc_ptr, stmt_back], 1):
                        construct_stmts = [stmt_ahead, store_alloc_ptr, stmt_back]
                    elif vec_length := self._check_construct_stmts([store_alloc_ptr, stmt_back, stmt_back_back], 0):
                        construct_stmts = [store_alloc_ptr, stmt_back, stmt_back_back]
                    if construct_stmts:
                        state.construct_stmts = construct_stmts
                        state.vec_length = vec_length
                        state.raw_ptr_vvar = stmt.dst if isinstance(stmt, Assignment) else None
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

    def _replace_raw_ptr_with_vec(self, raw_ptr_vvar, vec_vvar, element_size):
        walker = VecIndexingWalker(raw_ptr_vvar, vec_vvar, element_size)
        for block in self._graph.nodes:
            walker.walk(block)

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
                if state.raw_ptr_vvar in self.raw_ptr_vvar_to_vec_vvar and state.vec_element_size:
                    raw_ptr_vvar = state.raw_ptr_vvar
                    vec_vvar = self.raw_ptr_vvar_to_vec_vvar[raw_ptr_vvar]
                    self._replace_raw_ptr_with_vec(raw_ptr_vvar, vec_vvar, state.vec_element_size)

        self.out_graph = self._graph
