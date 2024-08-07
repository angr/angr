from collections import defaultdict
from pprint import pformat
from typing import Optional

import archinfo
from ailment import Block, Const
from ailment.expression import StackBaseOffset, Register, BinaryOp, Convert
from ailment.statement import Call, Statement, Jump, ConditionalJump, Return, Store

from ...analyses.decompiler import Clinic
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from ...rust.utils.library import demangle, normalize


class SimpleSimulator:
    def __init__(self):
        self.stack = defaultdict(dict)
        self.regs = defaultdict(dict)

    def __str__(self):
        return pformat(self)

    def __repr__(self):
        return str(self)

    def simulate(self, block):
        for stmt in block.statemets:
            if isinstance(stmt, Store):
                if isinstance(stmt.addr, StackBaseOffset):
                    self.stack[stmt.addr.base][stmt.addr.offset] = stmt
                elif isinstance(stmt.addr, Register):
                    self.stack[stmt.addr.reg_offset][0] = stmt
                elif isinstance(stmt.addr, BinaryOp):
                    op0, op1 = stmt.addr.operands
                    if isinstance(op0, Register) and isinstance(op1, Const):
                        self.stack[op0.reg_offset][op1.value] = stmt

    def match_consecutive_memory(self, size, condition):
        for base, data in self.stack.items():
            offsets = sorted(data.keys())
            for offset in offsets:
                stmt = data[offset]


class TransformationPass(OptimizationPass):
    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

    #     self._old_graph = None
    #
    # def shadow_graph(self):
    #     self._old_graph = self._graph
    #     self._graph = Clinic._copy_graph(self._graph)
    #
    # def recover_graph(self):
    #     self._graph = self._old_graph
    #     self.out_graph = self._graph

    @property
    def endian(self):
        return "big" if (self.project.arch.memory_endness == archinfo.Endness.BE) else "little"

    def match_call(self, block_or_stmt, func_list):
        stmt = None
        if isinstance(block_or_stmt, Statement):
            stmt = block_or_stmt
        elif isinstance(block_or_stmt, Block) and block_or_stmt.statements:
            stmt = block_or_stmt.statements[-1]
        if isinstance(stmt, Return) and len(stmt.ret_exprs):
            stmt = stmt.ret_exprs[0]
            if isinstance(stmt, Convert):
                stmt = stmt.operand
        if isinstance(stmt, Call) and isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
            func = self.kb.functions[stmt.target.value]
            name = normalize(func.name, remove_polymorphism=True)
            return name in func_list
        return False

    def replace_call_with_jump(self, block):
        terminal = block.statements[-1]
        if isinstance(terminal, Call) and self.num_successors(block) == 1:
            succ = self.get_one_successor(block)
            block.statements[-1] = Jump(
                terminal.idx,
                Const(0, None, succ.addr, self.project.arch.bits),
                succ.idx,
                ins_addr=terminal.ins_addr,
            )

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

    def num_successors(self, block):
        return len(list(self._graph.successors(block)))

    def get_one_successor(self, block) -> Block:
        return next(self._graph.successors(block))

    def get_two_successors(self, block):
        return tuple(self._graph.successors(block))

    def has_terminal(self, block):
        if len(block.statements):
            last_stmt = block.statements
            if isinstance(last_stmt, Return) or isinstance(last_stmt, Jump) or isinstance(last_stmt, ConditionalJump):
                return True
        return False

    def merge_blocks(self, block0: Block, block1: Block):
        if not self.has_terminal(block0):
            block = Block(
                addr=block0.addr,
                original_size=block0.original_size + block1.original_size,
                statements=block0.statements + block1.statements,
                idx=block0.idx,
            )

            in_edges = list(self._graph.in_edges(block0, data=True))
            out_edges = list(self._graph.out_edges(block1, data=True))

            self._remove_block(block0)
            self._remove_block(block1)
            self._graph.add_node(block)
            self._blocks_by_addr[block.addr].add(block)
            self._blocks_by_addr_and_idx[(block.addr, block.idx)] = block

            for src, _, data in in_edges:
                if src is block0:
                    src = block
                self._graph.add_edge(src, block, **data)

            for _, dst, data in out_edges:
                if dst is block1:
                    dst = block
                self._graph.add_edge(block, dst, **data)

            return block
        return block0

    def simulate_stores(self, block):
        result = {"stack": {}, "regs": {}}
        for stmt in block.statemets:
            if isinstance(stmt, Store):
                if isinstance(stmt.addr, StackBaseOffset):
                    pass
                elif isinstance(stmt.addr, Register):
                    pass
                elif isinstance(stmt.addr, BinaryOp):
                    pass
        return result
