from __future__ import annotations
from typing import Self

from ailment.statement import Statement, Assignment, Label
from ailment.expression import Phi, VirtualVariable, VirtualVariableCategory
from ailment.block import Block

from angr.code_location import CodeLocation


class RewritingState:
    def __init__(
        self,
        loc: CodeLocation,
        arch,
        func,
        original_block: Block,
        registers: dict | None = None,
    ):
        self.loc = loc
        self.arch = arch
        self.func = func

        self.registers: dict[int, VirtualVariable] = registers if registers is not None else {}
        self.original_block = original_block
        self.out_block = None

    def copy(self) -> RewritingState:
        state = RewritingState(
            self.loc,
            self.arch,
            self.func,
            self.original_block,
            registers=self.registers.copy(),
        )
        return state

    def append_statement(self, stmt: Statement):
        if self.out_block is None:
            self.out_block = Block(self.loc.block_addr, self.original_block.original_size, idx=self.loc.block_idx)
        self.out_block.statements.append(stmt)
