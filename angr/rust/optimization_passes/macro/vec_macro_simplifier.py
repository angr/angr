from typing import Dict, Optional, List

import archinfo
from ailment import Const
from ailment.expression import BinaryOp, VirtualVariable, Load, StackBaseOffset
from ailment.statement import Store, Assignment, Call, FunctionLikeMacro

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from ..base import SSAVariableHelper
from ...mixins.cfg_transformation_mixin import CFGTransformationMixin
from ...mixins.srda_mixin import SRDAMixin
from ...mixins.cfa_mixin import CFAMixin
from ...sim_type import RustSimTypeVec, RustSimTypeInt
from .... import SIM_LIBRARIES
from ....analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage


class SimplificationState:
    def __init__(self, context: "VecMacroSimplifier", alloc_block, alloc_call):
        self.context = context
        self.alloc_block = alloc_block
        self.alloc_call = alloc_call

        self.alloc_size = None
        self.alloc_align = None
        self.vec_length = None
        args = self.alloc_call.args
        if len(args) >= 2:
            self.alloc_size = args[1]
        # Statements that initiate the allocated heap memory
        self.init_stmts = []
        # Statements that construct the final object
        self.construct_stmt = None

    def _extract_stack_offset_and_size(self, vvars: List[VirtualVariable]):
        sorted_vvars = sorted(vvars, key=lambda v: v.stack_offset)
        cur_offset = sorted_vvars[0].stack_offset
        size = 0
        for vvar in sorted_vvars:
            if vvar.stack_offset == cur_offset:
                size += vvar.size
                cur_offset += vvar.size
            else:
                return None, None
        return sorted_vvars[0].stack_offset, size

    def _try_outline_vec(self):
        if isinstance(self.alloc_size, Const) and isinstance(self.vec_length, Const):
            vec_length = self.vec_length.value
            alloc_size = self.alloc_size.value
            if alloc_size % vec_length != 0:
                return None
            ele_size = alloc_size // vec_length
            if all(isinstance(stmt, Store) and isinstance(stmt.data, Const) for stmt in self.init_stmts):
                endian = "big" if (self.context.project.arch.memory_endness == archinfo.Endness.BE) else "little"
                init_bytes = bytearray(b"\x00" * alloc_size)
                for stmt in self.init_stmts:
                    if isinstance(stmt, Store):
                        vvar, offset = self.context.extract_vvar_and_offset(stmt.addr)
                        data = stmt.data.value.to_bytes(stmt.data.size, endian)
                        init_bytes[offset : offset + stmt.data.size] = data
                elements = []
                for i in range(vec_length):
                    element = int.from_bytes(init_bytes[i * ele_size : (i + 1) * ele_size], byteorder=endian)
                    element = Const(None, None, element, ele_size * self.context.project.arch.byte_width)
                    elements.append(element)
                ele_ty = RustSimTypeInt(ele_size * self.context.project.arch.byte_width, signed=False)
                returnty = RustSimTypeVec(ele_ty).with_arch(self.context.project.arch)
                macro = FunctionLikeMacro(
                    None,
                    "vec",
                    elements,
                    bits=alloc_size * self.context.project.arch.byte_width,
                    delimiter="[]",
                    returnty=returnty,
                    **self.construct_stmt.tags,
                )
                return macro
            if all(
                isinstance(stmt, Store) and isinstance(stmt.data, VirtualVariable) and stmt.data.was_stack
                for stmt in self.init_stmts
            ):
                offset, size = self._extract_stack_offset_and_size([stmt.data for stmt in self.init_stmts])
                if size == alloc_size:
                    elements = []
                    for i in range(vec_length):
                        element = Load(
                            None,
                            StackBaseOffset(None, self.context.project.arch.bits, offset + i * ele_size),
                            ele_size,
                            endness=self.context.project.arch.memory_endness,
                        )
                        elements.append(element)
                    ele_ty = RustSimTypeInt(ele_size * self.context.project.arch.byte_width, signed=False)
                    returnty = RustSimTypeVec(ele_ty).with_arch(self.context.project.arch)
                    macro = FunctionLikeMacro(
                        None,
                        "vec",
                        elements,
                        bits=alloc_size * self.context.project.arch.byte_width,
                        delimiter="[]",
                        returnty=returnty,
                        **self.construct_stmt.tags,
                    )
                    return macro
        return None

    def outline(self):
        if not self.construct_stmt:
            return None, (None, None)

        dst = self.construct_stmt.dst
        outline_result = self._try_outline_vec()

        replacement = None
        if isinstance(outline_result, FunctionLikeMacro):
            dst_vvar = dst
            replacement = Assignment(idx=None, dst=dst_vvar, src=outline_result, **dst_vvar.tags)

        if replacement:
            stmts_to_remove = set(self.init_stmts)
            stmts_to_remove.add(self.alloc_block.statements[-1])
            stmt_to_replace = (self.construct_stmt, replacement)
            return stmts_to_remove, stmt_to_replace

        return None, (None, None)


RUST_ALLOC_FUNCTIONS = ["alloc::alloc::Global::alloc_impl"]
RUST_ALLOC_ERROR_HANDLING_FUNCTIONS = ["alloc::raw_vec::handle_error", "alloc::alloc::handle_alloc_error"]
RUST_CONVERT_TO_VEC_FUNCTIONS = ["alloc::slice::hack::into_vec"]


class VecMacroSimplifier(OptimizationPass, SRDAMixin, SSAVariableHelper, CFAMixin, CFGTransformationMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rust Memory Allocation Simplifier"

    def __init__(self, func, **kwargs):
        OptimizationPass.__init__(self, func, **kwargs)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        SSAVariableHelper.__init__(self, self)
        CFAMixin.__init__(self, self._graph, self.project)
        CFGTransformationMixin.__init__(self, self._graph)

        self.states: Dict[Call, SimplificationState] = {}
        self.librust = SIM_LIBRARIES["librust"]

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
                and self.match_call(block, RUST_ALLOC_FUNCTIONS)
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

    def _bind_init_stmts(self, block):
        for stmt in block.statements:
            if isinstance(stmt, Store):
                vvar, offset = self.extract_vvar_and_offset(stmt.addr)
                value = self.get_terminal_vvar_value(vvar)
                if value in self.states:
                    state = self.states[value]
                    state.init_stmts.append(stmt)

    def _bind_construct_stmt(self, block):
        if self.match_call(block, RUST_CONVERT_TO_VEC_FUNCTIONS):
            call = self.terminal_call(block)
            if call and len(call.args) >= 2:
                arg0 = call.args[0]
                if isinstance(arg0, VirtualVariable):
                    value = self.get_terminal_vvar_value(arg0)
                    if value in self.states:
                        state = self.states[value]
                        state.construct_stmt = self.last_stmt(block)
                        state.vec_length = call.args[1]

    def _remove_alloc_error_handling_blocks(self):
        error_handling_blocks = set()
        for block in self._graph.nodes:
            if self.match_call(block, RUST_ALLOC_ERROR_HANDLING_FUNCTIONS):
                error_handling_blocks.add(block)

        for block in set(error_handling_blocks):
            self.remove_block(block)

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
            self._bind_init_stmts(block)
            self._bind_construct_stmt(block)

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
