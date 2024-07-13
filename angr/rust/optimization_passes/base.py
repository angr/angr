from typing import Optional

from ailment import Block, Const
from ailment.statement import Call, Statement, Jump, ConditionalJump

from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from ...utils.library import get_rust_function_name


class TransformationPass(OptimizationPass):
    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

    def match_call(self, block_or_stmt, func_list, match_prefix=False):
        stmt = None
        if isinstance(block_or_stmt, Statement):
            stmt = block_or_stmt
        elif isinstance(block_or_stmt, Block) and block_or_stmt.statements:
            stmt = block_or_stmt.statements[-1]
        if isinstance(stmt, Call) and isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
            func = self.kb.functions[stmt.target.value]
            name = get_rust_function_name(func.demangled_name)
            if match_prefix:
                return any(name.startswith(func_name) for func_name in func_list)
            return name in func_list
        return False

    def replace_jump_target(self, block, old_target: Optional[Block], new_target: Block):
        if not block.statements:
            return
        terminal = block.statements[-1]
        if isinstance(terminal, Jump):
            if isinstance(terminal.target, Const):
                terminal.target.value = new_target.addr
                terminal.target_idx = new_target.idx
            elif old_target is None:
                target = Const(0, None, new_target.addr, terminal.target.bits)
                block.statements[-1] = Jump(
                    terminal.idx,
                    target,
                    new_target.idx,
                    ins_addr=terminal.ins_addr,
                )
            else:
                return
        elif isinstance(terminal, ConditionalJump):
            if old_target is None or (
                isinstance(terminal.true_target, Const)
                and isinstance(terminal.false_target, Const)
                and (
                    (
                        terminal.true_target.value == old_target.addr
                        and terminal.true_target_idx == old_target.idx
                        and terminal.false_target.value == new_target.addr
                        and terminal.false_target_idx == new_target.idx
                    )
                    or (
                        terminal.false_target.value == old_target.addr
                        and terminal.false_target_idx == old_target.idx
                        and terminal.true_target.value == new_target.addr
                        and terminal.true_target_idx == new_target.idx
                    )
                )
            ):
                target = Const(0, None, new_target.addr, terminal.true_target.bits)
                block.statements[-1] = Jump(
                    terminal.idx,
                    target,
                    new_target.idx,
                    ins_addr=terminal.ins_addr,
                )
            elif (
                isinstance(terminal.true_target, Const)
                and terminal.true_target.value == old_target.addr
                and terminal.true_target_idx == old_target.idx
            ):
                terminal.true_target.value = new_target.addr
                terminal.true_target_idx = new_target.idx
            elif (
                isinstance(terminal.false_target, Const)
                and terminal.false_target.value == old_target.addr
                and terminal.false_target_idx == old_target.idx
            ):
                terminal.false_target.value = new_target.addr
                terminal.false_target_idx = new_target.idx
            else:
                return
        elif isinstance(terminal, Call):
            pass
        else:
            return
        self._graph.add_edge(block, new_target)
