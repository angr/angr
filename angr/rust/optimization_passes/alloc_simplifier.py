from typing import Optional, Tuple, List

import ailment
import archinfo
from ...analyses.decompiler.optimization_passes.engine_base import SimplifierAILState
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ...utils.library import get_rust_function_name
from ..ailment.expression import VecInitialization, String


class AllocSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory Allocation Simplifier"

    RUST_ALLOC_FUNCTIONS = ["__rust_alloc"]
    RUST_ERROR_HANDLING_FUNCTIONS = ["alloc::alloc::handle_alloc_error"]

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _split_const(self, const: ailment.expression.Const, to_bytes):
        if const.size == to_bytes:
            return [const.value]
        elif const.size % to_bytes == 0:
            endness = "big" if (self.project.arch.memory_endness == archinfo.Endness.BE) else "little"
            value_bytes = const.value.to_bytes(const.size, endness)
            result = []
            for i in range(0, const.size, to_bytes):
                result.append(int.from_bytes(value_bytes[i : i + to_bytes], endness, signed=False))
            return result
        return []

    def _try_simplify_vec_(self, alloc_block, alloc_call, if_block, error_block, init_block):
        align = alloc_call.args[1].value
        br: ailment.statement.ConditionalJump = if_block.statements[-1]
        target = None
        if isinstance(br.true_target, ailment.expression.Const) and br.true_target.value == init_block.addr:
            target = br.true_target
        elif isinstance(br.false_target, ailment.expression.Const) and br.false_target.value == init_block.addr:
            target = br.false_target
        if target:
            if_block.statements[-1] = ailment.statement.Jump(br.idx, target, ins_addr=br.ins_addr)
            init_values = []
            new_statements = []
            init_finished = False
            for stmt in init_block.statements:
                if isinstance(stmt, ailment.statement.Store) and not init_finished:
                    addr = stmt.addr
                    base = None
                    offset = 0
                    if isinstance(addr, ailment.expression.Register):
                        base = addr
                    elif isinstance(addr, ailment.expression.BinaryOp) and addr.op == "Add":
                        base = addr.operands[0]
                        offset = addr.operands[1]
                    if (
                        base
                        and base.reg_offset == alloc_call.ret_expr.reg_offset
                        and isinstance(stmt.data, ailment.expression.Const)
                    ):
                        init_values += self._split_const(stmt.data, align)
                    else:
                        init_finished = True
                        new_statements.append(stmt)
                elif isinstance(stmt, ailment.statement.Label):
                    new_statements.append(stmt)
                else:
                    init_finished = True
                    new_statements.append(stmt)

            init_block.statements = new_statements
            alloc_block.statements = alloc_block.statements[:-1]
            self._remove_block(error_block)
            init_block.statements.insert(
                0, VecInitialization(0, alloc_call.ret_expr, init_values, ins_addr=alloc_call.ins_addr)
            )
            return True
        return False

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

    def _try_get_alloc_call(self, block: ailment.Block):
        return self._try_get_specific_call(block, AllocSimplifier.RUST_ALLOC_FUNCTIONS)

    def _try_get_error_handling_call(self, block: ailment.Block):
        return self._try_get_specific_call(block, AllocSimplifier.RUST_ERROR_HANDLING_FUNCTIONS)

    def _try_identify_blocks(self, block: ailment):
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
                    return block, if_block, error_block, init_block
        return None, None, None, None

    def _try_simplify_alloc_block(
        self, alloc_block, alloc_call: ailment.statement.Call
    ) -> Tuple[Optional[int], Optional[List[ailment.Stmt]]]:
        if len(alloc_call.args) >= 1:
            arg = alloc_call.args[0]
            if isinstance(arg, ailment.expression.Const):
                return arg.value, alloc_block.statements[:-1]
        return None, None

    def _simplify_if_block(self, init_block, if_block) -> Optional[List[ailment.Stmt]]:
        br: ailment.statement.ConditionalJump = if_block.statements[-1]
        target = ailment.expression.Const(0, None, init_block.addr, self.project.arch.bits)
        new_statements = if_block.statements[:-1] + [ailment.statement.Jump(br.idx, target, ins_addr=br.ins_addr)]
        return new_statements

    def _try_simplify_init_block(
        self, alloc_size, alloc_call, init_block
    ) -> Tuple[Optional[bytes], Optional[List[ailment.Stmt]]]:
        offset_to_bytes = {}
        new_statements = []
        for stmt in init_block.statements:
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
                    and base.reg_offset == alloc_call.ret_expr.reg_offset
                    and isinstance(stmt.data, ailment.expression.Const)
                ):
                    value = stmt.data.value
                    endian = "big" if (self.project.arch.memory_endness == archinfo.Endness.BE) else "little"
                    value_bytes = value.to_bytes(stmt.data.size, endian)
                    offset_to_bytes[offset] = value_bytes
                    continue
            new_statements.append(stmt)
        init_bytes = bytearray(b"\x00" * alloc_size)
        for offset, value_bytes in offset_to_bytes.items():
            if offset + len(value_bytes) > alloc_size:
                return None, None
            init_bytes[offset : offset + len(value_bytes)] = value_bytes
        init_bytes = bytes(init_bytes)
        return init_bytes, new_statements

    def _try_simplify_string(self, init_bytes, alloc_call, new_init_statements):
        ret_expr = alloc_call.ret_expr
        str_expr = None
        str_expr_base = None
        str_expr_offset = 0
        str_length = None
        str_capacity = None
        tmp_new_init_statements = []
        for stmt in new_init_statements:
            discard = False
            if isinstance(stmt, ailment.statement.Store):
                if str_expr is None:
                    if stmt.data.likes(ret_expr):
                        if isinstance(stmt.addr, ailment.expression.StackBaseOffset):
                            str_expr = stmt.addr
                            str_expr_base = stmt.addr.base
                            str_expr_offset = stmt.addr.offset
                            discard = True
                        elif isinstance(stmt.addr, ailment.expression.Register):
                            str_expr = stmt.addr
                            str_expr_base = stmt.addr.reg_offset
                            str_expr_offset = 0
                            discard = True
                else:
                    addr = stmt.addr
                    data = stmt.data
                    if isinstance(data, ailment.expression.Const) and data.value == len(init_bytes):
                        data = data.value
                    else:
                        tmp_new_init_statements.append(stmt)
                        continue
                    if isinstance(addr, ailment.expression.StackBaseOffset):
                        if addr.base == str_expr_base:
                            if str_length is None and addr.offset == str_expr_offset + self.project.arch.bytes:
                                str_length = data
                                discard = True
                            elif str_capacity is None and addr.offset == str_expr_offset + self.project.arch.bytes * 2:
                                str_capacity = data
                                discard = True
                    elif (
                        isinstance(addr, ailment.expression.BinaryOp)
                        and addr.op == "Add"
                        and isinstance(addr.operands[0], ailment.expression.Register)
                        and addr.operands[0].reg_offset == str_expr_base
                        and isinstance(addr.operands[1], ailment.expression.Const)
                    ):
                        offset = addr.operands[1].value
                        if str_length is None and offset == str_expr_offset + self.project.arch.bytes:
                            str_length = data
                            discard = True
                        elif str_capacity is None and offset == str_expr_offset + self.project.arch.bytes * 2:
                            str_capacity = data
                            discard = True
            if not discard:
                tmp_new_init_statements.append(stmt)
        if not str_length or not str_capacity:
            return None, new_init_statements
        try:
            decoded_str = init_bytes.decode("utf-8")
            data = str_expr
            expr = String(data.idx, data.variable, 0, self.project.arch.bits * 3, decoded_str, is_heap_str=True)
            return (
                ailment.Stmt.Store(
                    data.idx,
                    data,
                    expr,
                    self.project.arch.bytes * 3,
                    self.project.arch.memory_endness,
                    ins_addr=alloc_call.ins_addr,
                ),
                tmp_new_init_statements,
            )
        except UnicodeDecodeError:
            return None, new_init_statements

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            alloc_call = self._try_get_alloc_call(block)
            # Is this block trying to allocate new heap memory?
            if alloc_call is None:
                continue
            # Can we identify all the blocks of the initialization process?
            alloc_block, if_block, error_block, init_block = self._try_identify_blocks(block)
            if any(block is None for block in (alloc_block, if_block, error_block, init_block)):
                continue
            alloc_size, new_alloc_statements = self._try_simplify_alloc_block(alloc_block, alloc_call)
            # Can we extract the number of bytes allocated from alloc_block?
            if alloc_size is None:
                continue
            # Can we extract the initial bytes from init_block?
            init_bytes, new_init_statements = self._try_simplify_init_block(alloc_size, alloc_call, init_block)
            if init_bytes is None:
                continue
            # Sanity check passed! Let's try to match a specific type
            new_stmt, new_init_statements = self._try_simplify_string(init_bytes, alloc_call, new_init_statements)
            if new_stmt is not None:
                alloc_block.statements = new_alloc_statements
                new_if_statements = self._simplify_if_block(init_block, if_block)
                if_block.statements = new_if_statements
                init_block.statements = new_init_statements
                alloc_block.statements.append(new_stmt)
                self._remove_block(error_block)
