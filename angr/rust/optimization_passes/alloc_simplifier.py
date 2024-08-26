from enum import IntEnum

import ailment
from ailment import Const
from ailment.expression import StackBaseOffset, BinaryOp, Register, Tmp, VirtualVariable, VirtualVariableCategory
from ailment.statement import Store

from .base import TransformationPass
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from ..ailment.expression import String


class InitialData:
    def __init__(self):
        pass


class AllocSimplifierState:
    def __init__(self):
        self.alloc_block = None
        self.init_block = None
        self.init_block2 = None
        self.removed_stmts = []
        self.alloc_call = None
        self.alloc_size = None
        self.alloc_align = None
        self.init_bytes = None


RUST_ALLOC_FUNCTIONS = ["__rust_alloc"]


class AllocSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory Allocation Simplifier"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = AllocSimplifierState()
        self.librust = SIM_LIBRARIES["librust"]
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _try_identify_region(self, block):
        if self.num_successors(block) == 1:
            succ = self.get_one_successor(block)
            if succ.statements and isinstance(succ.statements[-1], ailment.statement.Jump):
                if self.num_successors(succ) == 1:
                    succ = self.get_one_successor(succ)
                    self.state.alloc_block = block
                    self.state.init_block = succ
                    # If the init block ends with a memset call, we consider its successor as init block too
                    if self.match_call(succ, ["memset"]) and self.num_successors(succ) == 1:
                        self.state.init_block2 = self.get_one_successor(succ)
                    return True
        return False

    def _try_simplify_alloc_block(self):
        if len(self.state.alloc_call.args) >= 1:
            alloc_size = self.state.alloc_call.args[0]
            alloc_align = 1
            if len(self.state.alloc_call.args) >= 2 and isinstance(self.state.alloc_call.args[1], Const):
                alloc_align = self.state.alloc_call.args[1].value
            self.state.alloc_size = alloc_size
            self.state.alloc_align = alloc_align
            self.state.removed_stmts.append(self.state.alloc_call)
            return True

    def _try_simplify_init_block_const(self):
        # Called when alloc_size is constant
        # Special handle for memset
        if self.match_call(self.state.init_block, ["memset"]):
            call = self.state.init_block.statements[-1]
            if (
                len(call.args) == 3
                and self.state.alloc_call.ret_expr.likes(call.args[0])
                and isinstance(call.args[1], Const)
            ):
                self.state.init_bytes = call.args[1].value.to_bytes(1, "little") * self.state.alloc_size
                self.state.removed_stmts.append(call)
                return True
            return False
        if self.match_call(self.state.init_block, ["String::from"]):
            import ipdb

            ipdb.set_trace()
        offset_to_bytes = {}
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
                    value_bytes = value.to_bytes(stmt.data.size, self.endian)
                    offset_to_bytes[offset] = value_bytes
                    self.state.removed_stmts.append(stmt)
        init_bytes = bytearray(b"\x00" * self.state.alloc_size)
        for offset, value_bytes in offset_to_bytes.items():
            if offset + len(value_bytes) > self.state.alloc_size:
                return False
            init_bytes[offset : offset + len(value_bytes)] = value_bytes
        init_bytes = bytes(init_bytes)
        self.state.init_bytes = init_bytes
        return True

    def _try_simplify_init_block(self):
        if isinstance(self.state.alloc_size, Const):
            self.state.alloc_size = self.state.alloc_size.value
            return self._try_simplify_init_block_const()
        return False

    def _try_simplify_string(self, alloc_var):
        if self.state.alloc_align == 1:
            # It could be a string
            try:
                decoded_str = self.state.init_bytes.decode("utf-8")
                if not decoded_str.isprintable():
                    return None
                addr = alloc_var
                if isinstance(addr, ailment.expression.StackBaseOffset):
                    addr = ailment.expression.StackBaseOffset(
                        addr.idx, self.project.arch.bits * 3, addr.offset, **addr.tags
                    )
                data = String(addr.idx, addr.variable, 0, self.project.arch.bits, decoded_str)
                new_stmt = ailment.Stmt.Call(
                    idx=addr.idx,
                    target="String::from",
                    prototype=self.librust.get_prototype("String::from").with_arch(self.project.arch),
                    args=[addr, data],
                    ret_expr=None,
                    **self.state.alloc_call.tags,
                )
                return new_stmt
            except UnicodeDecodeError:
                pass
        return None

    def _try_simplify_vec(self, alloc_var):
        unique_chars = set(self.state.init_bytes)
        if len(unique_chars) == 1:
            char = next(iter(unique_chars))
            length = len(self.state.init_bytes)
            # We will generate something like vec![0; 500]
            if char == 0:
                addr = alloc_var
                if isinstance(addr, ailment.expression.StackBaseOffset):
                    addr = ailment.expression.StackBaseOffset(
                        addr.idx, self.project.arch.bits * 3, addr.offset, **addr.tags
                    )
                data = Const(addr.idx, addr.variable, length, self.project.arch.bits)
                new_stmt = ailment.Stmt.Call(
                    idx=addr.idx,
                    target="Vec::with_capacity",
                    prototype=self.librust.get_prototype("Vec::with_capacity").with_arch(self.project.arch),
                    args=[data],
                    ret_expr=addr,
                    **self.state.alloc_call.tags,
                )
                return new_stmt
        return None

    def _try_simplify_vec_like(self):
        ret_expr = self.state.alloc_call.ret_expr
        # A vector-like object consists of three fields: ptr, len, cap
        # ptr should be StackBaseOffset or Register
        alloc_var, alloc_base, alloc_offset = None, None, 0
        alloc_length, alloc_capacity = None, None
        stmts = list(self.state.init_block.statements)
        if self.state.init_block2:
            stmts += self.state.init_block2.statements
        for stmt in stmts:
            if isinstance(stmt, Store):
                addr = stmt.addr
                data = stmt.data
                # Identify variable (with base and offset)
                # Variable can be a stack base offset or register
                if data.likes(ret_expr):
                    if isinstance(addr, BinaryOp) and addr.op == "Add":
                        addr = addr.operands[0]
                    if isinstance(addr, StackBaseOffset):
                        alloc_var = addr
                        alloc_base = addr.base
                        alloc_offset = addr.offset
                        self.state.removed_stmts.append(stmt)
                        break
                    elif isinstance(addr, Register):
                        alloc_var = addr
                        alloc_base = addr.reg_offset
                        alloc_offset = 0
                        self.state.removed_stmts.append(stmt)
                        break
        if alloc_var:
            new_alloc_var = alloc_var
            new_alloc_offset = alloc_offset
            # Search for other fields (length and capacity)
            # We considered the possibility that fields order maybe changed
            for stmt in stmts:
                if alloc_length and alloc_capacity:
                    break
                if isinstance(stmt, Store) and not (alloc_var and alloc_length and alloc_capacity):
                    addr = stmt.addr
                    data = stmt.data
                    base = None
                    offset = 0
                    if isinstance(addr, StackBaseOffset):
                        base = addr.base
                        offset = addr.offset
                    elif isinstance(addr, Register):
                        base = addr.reg_offset
                        offset = 0
                    elif (
                        isinstance(addr, BinaryOp)
                        and addr.op == "Add"
                        and isinstance(addr.operands[0], Register)
                        and isinstance(addr.operands[1], Const)
                    ):
                        base = addr.operands[0].reg_offset
                        offset = addr.operands[1].value
                    if base == alloc_base and isinstance(data, Const):
                        if abs(offset - alloc_offset) <= 2 * self.project.arch.bytes:
                            if data.size == self.project.arch.bytes and data.value * self.state.alloc_align == len(
                                self.state.init_bytes
                            ):
                                if alloc_length is None:
                                    alloc_length = data.value
                                else:
                                    alloc_capacity = data.value
                                if offset < new_alloc_offset:
                                    new_alloc_offset = offset
                                    new_alloc_var = addr
                                self.state.removed_stmts.append(stmt)
                            elif data.size == 2 * self.project.arch.bytes:
                                length = data.value & ((2 << self.project.arch.bits) - 1)
                                capacity = data.value >> self.project.arch.bits
                                if length == capacity and length * self.state.alloc_align == len(self.state.init_bytes):
                                    alloc_length = length
                                    alloc_capacity = capacity
                                    if offset < new_alloc_offset:
                                        new_alloc_offset = offset
                                        new_alloc_var = addr
                                    self.state.removed_stmts.append(stmt)
            alloc_var = new_alloc_var

        if not alloc_var or not alloc_length or not alloc_capacity:
            return False

        # Finalize simplification
        # Try to match potential high-level API calls (String::from, vec!)
        finalizers = [self._try_simplify_string, self._try_simplify_vec]
        for func in finalizers:
            new_stmt = func(alloc_var)
            if new_stmt:
                self._do_simplify(new_stmt)
                return True
        return False

    def _try_simplify(self):
        funcs = [self._try_simplify_vec_like]
        for func in funcs:
            if func():
                return True
        return False

    def _do_simplify(self, new_stmt):
        blocks = [self.state.alloc_block, self.state.init_block]
        if self.state.init_block2:
            blocks.append(self.state.init_block2)
        for stmt in self.state.removed_stmts:
            for block in blocks:
                if stmt in block.statements:
                    block.statements.remove(stmt)
        self.state.alloc_block.statements.append(new_stmt)

    def simplify_alloc(self, block):
        # Is this block trying to allocate new heap memory?
        if self.match_call(block, RUST_ALLOC_FUNCTIONS):
            self.state = AllocSimplifierState()
            self.state.alloc_call = block.statements[-1]
        else:
            return False
        # Can we identify the region that contains all the blocks of the initialization process?
        if not self._try_identify_region(block):
            return False

        if not self._try_simplify_alloc_block():
            return False

        # Can we extract the initial bytes from init_block?
        # This step may change the AIL graph, so we save the original AIL graph
        if not self._try_simplify_init_block():
            return False

        # Sanity check passed! Let's try to match a specific type
        return self._try_simplify()

    def _analyze(self, cache=None):
        return
        blocks = []
        pending_blocks = []
        for block in self._graph.nodes:
            if self.match_call(block, RUST_ALLOC_FUNCTIONS):
                pending_blocks.append(block)
        while len(blocks) != len(pending_blocks):
            blocks = pending_blocks
            pending_blocks = []
            for block in blocks:
                if not self.simplify_alloc(block):
                    pending_blocks.append(block)
