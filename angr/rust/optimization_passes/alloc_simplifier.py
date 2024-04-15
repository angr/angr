from typing import Optional, Tuple, List

import ailment
import archinfo
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...utils.library import get_rust_function_name
from ..ailment.expression import VecInitialization, String


class AllocSimplifierState:
    def __init__(self):
        self.alloc_block = None
        self.if_block = None
        self.error_block = None
        self.init_block = None
        self.alloc_call = None
        self.alloc_size = None
        self.alloc_align = None
        self.new_alloc_statements = None
        self.new_init_statements = None
        self.new_if_statements = None
        self.init_bytes = None


class AllocSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory Allocation Simplifier"

    RUST_ALLOC_FUNCTIONS = ["__rust_alloc"]
    RUST_ERROR_HANDLING_FUNCTIONS = ["alloc::alloc::handle_alloc_error"]

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = AllocSimplifierState()
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    # -- Utils -- #

    def _try_extract_value(self, expr):
        if isinstance(expr, ailment.expression.Const):
            return expr.value
        return None

    def _get_tail_call(self, block) -> Optional[ailment.statement.Call]:
        if len(block.statements) >= 1 and isinstance(block.statements[-1], ailment.statement.Call):
            return block.statements[-1]
        return None

    def _try_get_specific_call(self, block: ailment.Block, func_list):
        call = self._get_tail_call(block)
        if call is not None and isinstance(call.target, ailment.expression.Const):
            addr = call.target.value
            if addr in self.project.kb.functions:
                func = self.project.kb.functions[addr]
                if get_rust_function_name(func.demangled_name) in func_list:
                    return call
        return None

    # -- Utils -- #

    def _try_get_alloc_call(self, block: ailment.Block):
        self.state.alloc_call = self._try_get_specific_call(block, AllocSimplifier.RUST_ALLOC_FUNCTIONS)

    def _try_get_error_handling_call(self, block: ailment.Block):
        return self._try_get_specific_call(block, AllocSimplifier.RUST_ERROR_HANDLING_FUNCTIONS)

    def _try_identify_region(self, block):
        successors = set(self._graph.successors(block))
        if len(successors) == 1:
            if_block = next(iter(successors))
            if len(if_block.statements) >= 1 and isinstance(if_block.statements[-1], ailment.statement.ConditionalJump):
                successors = set(self._graph.successors(if_block))
                if len(successors) == 2:
                    block1, block2 = successors
                    error_block, init_block = None, None
                    if self._try_get_error_handling_call(block1):
                        error_block, init_block = block1, block2
                    elif self._try_get_error_handling_call(block2):
                        error_block, init_block = block2, block1
                    self.state.alloc_block = block
                    self.state.if_block = if_block
                    self.state.error_block = error_block
                    self.state.init_block = init_block

    def _try_simplify_alloc_block(self):
        if len(self.state.alloc_call.args) >= 1:
            alloc_size = self._try_extract_value(self.state.alloc_call.args[0])
            alloc_align = None
            if len(self.state.alloc_call.args) >= 2:
                alloc_align = self._try_extract_value(self.state.alloc_call.args[1])
            self.state.alloc_size = alloc_size
            self.state.alloc_align = alloc_align
            self.state.new_alloc_statements = self.state.alloc_block.statements[:-1]

    def _simplify_if_block(self):
        br: ailment.statement.ConditionalJump = self.state.if_block.statements[-1]
        target = ailment.expression.Const(0, None, self.state.init_block.addr, self.project.arch.bits)
        self.state.new_if_statements = self.state.if_block.statements[:-1] + [
            ailment.statement.Jump(br.idx, target, ins_addr=br.ins_addr)
        ]

    def _try_simplify_init_block(self):
        offset_to_bytes = {}
        new_statements = []
        for stmt in self.state.init_block.statements:
            if isinstance(stmt, ailment.statement.Store):
                addr = stmt.addr
                base = None
                offset = 0
                if isinstance(addr, ailment.expression.Register):
                    base = addr
                elif (
                    isinstance(addr, ailment.expression.BinaryOp)
                    and addr.op == "Add"
                    and isinstance(addr.operands[1], ailment.expression.Const)
                ):
                    base = addr.operands[0]
                    offset = addr.operands[1].value
                if (
                    base
                    and base.reg_offset == self.state.alloc_call.ret_expr.reg_offset
                    and isinstance(stmt.data, ailment.expression.Const)
                ):
                    value = stmt.data.value
                    endian = "big" if (self.project.arch.memory_endness == archinfo.Endness.BE) else "little"
                    value_bytes = value.to_bytes(stmt.data.size, endian)
                    offset_to_bytes[offset] = value_bytes
                    continue
            new_statements.append(stmt)
        init_bytes = bytearray(b"\x00" * self.state.alloc_size)
        for offset, value_bytes in offset_to_bytes.items():
            if offset + len(value_bytes) > self.state.alloc_size:
                self.state.init_bytes = None
                return
            init_bytes[offset : offset + len(value_bytes)] = value_bytes
        init_bytes = bytes(init_bytes)
        self.state.init_bytes = init_bytes
        self.state.new_init_statements = new_statements

    def _try_simplify_vec(self):
        ret_expr = self.state.alloc_call.ret_expr
        vec_var, vec_var_base, vec_var_offset = None, None, 0
        vec_length, vec_capacity = None, None
        tmp_new_init_statements = []
        for stmt in self.state.new_init_statements:
            discard = False
            if isinstance(stmt, ailment.statement.Store):
                # Identify variable (with base and offset)
                # Variable can be a stack base offset or register
                if vec_var is None:
                    if stmt.data.likes(ret_expr):
                        if isinstance(stmt.addr, ailment.expression.StackBaseOffset):
                            vec_var = stmt.addr
                            vec_var_base = stmt.addr.base
                            vec_var_offset = stmt.addr.offset
                            discard = True
                        elif isinstance(stmt.addr, ailment.expression.Register):
                            vec_var = stmt.addr
                            vec_var_base = stmt.addr.reg_offset
                            vec_var_offset = 0
                            discard = True
                # After the variable is identified, search for other fields (length and capacity)
                else:
                    addr = stmt.addr
                    data = stmt.data
                    if isinstance(data, ailment.expression.Const) and data.value == len(self.state.init_bytes):
                        data = data.value
                        base, offset = None, None
                        if isinstance(addr, ailment.expression.StackBaseOffset):
                            base = addr.base
                            offset = addr.offset
                        elif (
                            isinstance(addr, ailment.expression.BinaryOp)
                            and addr.op == "Add"
                            and isinstance(addr.operands[0], ailment.expression.Register)
                            and isinstance(addr.operands[1], ailment.expression.Const)
                        ):
                            base = addr.operands[0].reg_offset
                            offset = addr.operands[1].value
                        if base == vec_var_base:
                            if vec_length is None and offset == vec_var_offset + self.project.arch.bytes:
                                vec_length = data
                                discard = True
                            elif vec_capacity is None and offset == vec_var_offset + self.project.arch.bytes * 2:
                                vec_capacity = data
                                discard = True
            if not discard:
                tmp_new_init_statements.append(stmt)
        if not vec_length or not vec_capacity:
            return
        if self.state.alloc_align == 1:
            try:
                decoded_str = self.state.init_bytes.decode("utf-8")
                addr = vec_var
                data = String(addr.idx, addr.variable, 0, self.project.arch.bits * 3, decoded_str, is_heap_str=True)
                new_stmt = ailment.Stmt.Store(
                    addr.idx,
                    addr,
                    data,
                    self.project.arch.bytes * 3,
                    self.project.arch.memory_endness,
                    ins_addr=self.state.alloc_call.ins_addr,
                )
                self.state.new_init_statements = tmp_new_init_statements
                self._do_simplify(new_stmt)
            except UnicodeDecodeError:
                pass
        # It's not a string, try vector

    def _try_simplify(self):
        funcs = [self._try_simplify_vec]
        for func in funcs:
            func()

    def _do_simplify(self, new_stmt):
        self.state.alloc_block.statements = self.state.new_alloc_statements
        self.state.if_block.statements = self.state.new_if_statements
        self.state.init_block.statements = self.state.new_init_statements
        self.state.alloc_block.statements.append(new_stmt)
        self._remove_block(self.state.error_block)

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            self.state = AllocSimplifierState()
            self._try_get_alloc_call(block)
            # Is this block trying to allocate new heap memory?
            if self.state.alloc_call is None:
                continue
            # Can we identify the region that contains all the blocks of the initialization process?
            self._try_identify_region(block)
            if any(
                block is None
                for block in (
                    self.state.alloc_block,
                    self.state.if_block,
                    self.state.init_block,
                    self.state.error_block,
                )
            ):
                continue
            self._try_simplify_alloc_block()
            # Can we extract the number of bytes allocated from alloc_block?
            if self.state.alloc_size is None:
                continue
            # Can we extract the initial bytes from init_block?
            self._try_simplify_init_block()
            if self.state.init_bytes is None:
                continue
            # Simplify if block
            self._simplify_if_block()
            # Sanity check passed! Let's try to match a specific type
            self._try_simplify()
