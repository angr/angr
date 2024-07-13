import ailment
import archinfo
from ailment.statement import Call

from ..sim_type import RustSimTypeFunction
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from ..ailment.expression import Vec, String
from .utils import extract_callee, extract_rust_function_name, extract_value


class AllocSimplifierState:
    def __init__(self):
        self.alloc_block = None
        self.init_block = None
        self.alloc_call = None
        self.alloc_size = None
        self.alloc_align = None
        self.new_alloc_statements = None
        self.new_init_statements = None
        self.init_bytes = None


class AllocSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Rust Memory Allocation Simplifier"

    RUST_ALLOC_FUNCTIONS = ["__rust_alloc"]

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = AllocSimplifierState()
        self.librust = SIM_LIBRARIES["librust"]
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _try_identify_region(self, block):
        successors = set(self._graph.successors(block))
        if len(successors) == 1:
            succ = next(iter(successors))
            if succ.statements and isinstance(succ.statements[-1], ailment.statement.Jump):
                successors = list(self._graph.successors(succ))
                if len(successors) == 1:
                    succ = successors[0]
                    self.state.alloc_block = block
                    self.state.init_block = succ

    def _try_simplify_alloc_block(self):
        if len(self.state.alloc_call.args) >= 1:
            alloc_size = extract_value(self.state.alloc_call.args[0])
            alloc_align = 1
            if len(self.state.alloc_call.args) >= 2:
                alloc_align = extract_value(self.state.alloc_call.args[1])
            self.state.alloc_size = alloc_size
            self.state.alloc_align = alloc_align
            self.state.new_alloc_statements = self.state.alloc_block.statements[:-1]

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

    def _try_simplify_vec_like(self):
        ret_expr = self.state.alloc_call.ret_expr
        alloc_var, alloc_base, alloc_offset = None, None, 0
        alloc_length, alloc_capacity = None, None
        new_init_statements = []
        for stmt in self.state.new_init_statements:
            discard = False
            if isinstance(stmt, ailment.statement.Store) and not (alloc_var and alloc_length and alloc_capacity):
                addr = stmt.addr
                data = stmt.data
                # Identify variable (with base and offset)
                # Variable can be a stack base offset or register
                if data.likes(ret_expr):
                    if isinstance(stmt.addr, ailment.expression.StackBaseOffset):
                        alloc_var = stmt.addr
                        alloc_base = stmt.addr.base
                        alloc_offset = stmt.addr.offset
                        discard = True
                    elif isinstance(stmt.addr, ailment.expression.Register):
                        alloc_var = stmt.addr
                        alloc_base = stmt.addr.reg_offset
                        alloc_offset = 0
                        discard = True
                # Search for other fields (length and capacity)
                elif isinstance(data, ailment.expression.Const) and data.value * self.state.alloc_align == len(
                    self.state.init_bytes
                ):
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
                    if not alloc_length:
                        alloc_length = data
                        discard = True
                    else:
                        alloc_capacity = data
                        discard = True
            if not discard:
                new_init_statements.append(stmt)
        if not alloc_length or not alloc_capacity:
            return
        if self.state.alloc_align == 1:
            try:
                decoded_str = self.state.init_bytes.decode("utf-8")
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
                    args=[data],
                    ret_expr=addr,
                    **self.state.alloc_call.tags,
                )
                self.state.new_init_statements = new_init_statements
                self._do_simplify(new_stmt)
                return
            except UnicodeDecodeError:
                pass
        # It's not a string, try vector
        endian = "big" if (self.project.arch.memory_endness == archinfo.Endness.BE) else "little"
        elements = [
            int.from_bytes(self.state.init_bytes[i : i + self.state.alloc_align], endian)
            for i in range(0, len(self.state.init_bytes), self.state.alloc_align)
        ]
        addr = alloc_var
        data = Vec(addr.idx, addr.variable, 0, self.project.arch.bits * 3, elements)
        new_stmt = ailment.Stmt.Store(
            addr.idx,
            addr,
            data,
            self.project.arch.bytes * 3,
            self.project.arch.memory_endness,
            ins_addr=self.state.alloc_call.ins_addr,
        )
        self.state.new_init_statements = new_init_statements
        self._do_simplify(new_stmt)

    def _try_simplify(self):
        funcs = [self._try_simplify_vec_like]
        for func in funcs:
            func()

    def _do_simplify(self, new_stmt):
        self.state.alloc_block.statements = self.state.new_alloc_statements
        self.state.init_block.statements = self.state.new_init_statements
        self.state.alloc_block.statements.append(new_stmt)

    def _analyze(self, cache=None):
        for block in sorted(self._graph.nodes, key=lambda b: b.addr):
            for stmt in block.statements:
                if isinstance(stmt, Call):
                    prototype = stmt.prototype
                    if isinstance(prototype, RustSimTypeFunction) and prototype.is_returnty_struct and len(stmt.args):
                        stmt.ret_expr = stmt.args[0]
                        stmt.args = stmt.args[1:]
                        prototype = prototype.copy()
                        prototype.returnty = prototype.args[0]
                        prototype.args = prototype.args[1:]
                        stmt.prototype = prototype

        for block in list(self._graph.nodes()):
            self.state = AllocSimplifierState()
            # Is this block trying to allocate new heap memory?
            if extract_rust_function_name(extract_callee(block, self.kb)) in AllocSimplifier.RUST_ALLOC_FUNCTIONS:
                self.state.alloc_call = block.statements[-1]
            else:
                continue
            # Can we identify the region that contains all the blocks of the initialization process?
            self._try_identify_region(block)
            if not self.state.alloc_block or not self.state.init_block:
                continue
            self._try_simplify_alloc_block()
            # Can we extract the number of bytes allocated from alloc_block?
            if self.state.alloc_size is None:
                continue
            # Can we extract the initial bytes from init_block?
            self._try_simplify_init_block()
            if self.state.init_bytes is None:
                continue
            # Sanity check passed! Let's try to match a specific type
            self._try_simplify()
