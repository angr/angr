import logging
from typing import Optional

import archinfo
from ailment import Block, Const
from ailment.expression import (
    Convert,
    VirtualVariable,
    VirtualVariableCategory,
)
from ailment.statement import Call, Statement, Jump, ConditionalJump, Return, Assignment
from networkx import NetworkXError

from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass
from ...rust.utils.library import normalize


l = logging.getLogger(name=__name__)


class SSAVariableHelper:
    def __init__(self, context: OptimizationPass):
        self.context = context

    def new_stack_vvar(self, dst_offset, bits, tags):
        vvar_id = self.context.vvar_id_start
        self.context.vvar_id_start += 1
        vvar_bits = bits
        vvar = VirtualVariable(
            None,
            vvar_id,
            vvar_bits,
            VirtualVariableCategory.STACK,
            oident=dst_offset,
            **tags,
        )
        return vvar


class TransformationPass(OptimizationPass):
    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

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
        elif isinstance(stmt, Assignment):
            stmt = stmt.src
        if isinstance(stmt, Call) and isinstance(stmt.target, str):
            name = normalize(stmt.target, monopolize=True, use_trait_name=True)
            return name in func_list
        if isinstance(stmt, Call) and isinstance(stmt.target, Const) and stmt.target.value in self.kb.functions:
            func = self.kb.functions[stmt.target.value]
            name = normalize(func.name, monopolize=True, use_trait_name=True)
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
            if old_target is None or (isinstance(terminal.target, Const) and terminal.target.value == old_target.addr):
                target = Const(0, None, new_target.addr, terminal.target.bits)
                block.statements[-1] = Jump(
                    terminal.idx,
                    target,
                    new_target.idx,
                    **terminal.tags,
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
            l.debug(f"Unexpected terminal: {terminal}")
            return
        # Remove old edges
        if old_target:
            try:
                self._graph.remove_edge(block, old_target)
            except NetworkXError:
                pass
        else:
            for succ in list(self._graph.successors(block)):
                try:
                    self._graph.remove_edge(block, succ)
                except NetworkXError:
                    pass
        # Add new edge
        self._graph.add_edge(block, new_target)

    def num_predecessors(self, block):
        return len(list(self._graph.predecessors(block)))

    def get_one_predecessor(self, block) -> Block:
        return next(self._graph.predecessors(block))

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
