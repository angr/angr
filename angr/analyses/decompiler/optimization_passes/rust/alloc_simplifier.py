from typing import Optional

import ailment
import archinfo
from ailment.utils import stable_hash

from ..optimization_pass import OptimizationPass, OptimizationPassStage
from ..engine_base import SimplifierAILState


class VecInitialization(ailment.statement.Statement):
    def __init__(self, idx, dst, init_values, **kwargs):
        super().__init__(idx, **kwargs)
        self.dst = dst
        self.init_values = init_values

    def __repr__(self):
        return f"vec!{self.init_values}"

    def __str__(self):
        return f"vec!{self.init_values}"

    def _hash_core(self):
        return stable_hash((VecInitialization, self.idx))

    def replace(self, old_expr, new_expr):
        raise NotImplementedError()


class AllocSimplifier(OptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Simplify Rust memory allocation"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.state = SimplifierAILState(self.project.arch)
        # self.engine = DivSimplifierAILEngine()
        self.analyze()

    def _check(self):
        return True, None

    def _get_tail_call(self, block) -> Optional[ailment.statement.Call]:
        if len(block.statements) >= 1 and isinstance(block.statements[-1], ailment.statement.Call):
            return block.statements[-1]
        return None

    def _is_rust_alloc_call(self, call):
        if call is None:
            return False
        addr = call.target.value
        if addr in self.project.kb.functions:
            func = self.project.kb.functions[addr]
            return func.name == "__rust_alloc"
        return False

    def _is_handle_alloc_error_call(self, call):
        if call is None:
            return False
        addr = call.target.value
        if addr in self.project.kb.functions:
            func = self.project.kb.functions[addr]
            return "handle_alloc_error" in func.name
        return False

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

    def _try_vec_initialization(self, alloc_block, alloc_call, if_block, error_block, init_block):
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

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes()):
            block: ailment.Block
            alloc_call = self._get_tail_call(block)
            if self._is_rust_alloc_call(alloc_call):
                alloc_block = block
                successors = set(self._graph.successors(alloc_block))
                if len(successors) == 1:
                    if_block = next(iter(successors))
                    if len(if_block.statements) >= 1:
                        if isinstance(if_block.statements[-1], ailment.statement.ConditionalJump):
                            successors = set(self._graph.successors(if_block))
                            if len(successors) == 2:
                                block1, block2 = successors
                                error_block, init_block = None, None
                                if self._is_handle_alloc_error_call(self._get_tail_call(block1)):
                                    error_block, init_block = block1, block2
                                elif self._is_handle_alloc_error_call(self._get_tail_call(block2)):
                                    error_block, init_block = block2, block1
                                self._try_vec_initialization(alloc_block, alloc_call, if_block, error_block, init_block)
