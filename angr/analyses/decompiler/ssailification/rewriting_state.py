from __future__ import annotations

from angr.ailment.statement import Statement
from angr.ailment.expression import VirtualVariable
from angr.ailment.block import Block

from angr.code_location import AILCodeLocation
from angr.utils.cowdict import ChainMapCOW


class RewritingState:
    """
    The abstract state for the expression rewriting engine.
    """

    def __init__(
        self,
        loc: AILCodeLocation,
        arch,
        func,
        original_block: Block,
        registers: dict[int, VirtualVariable] | None = None,
        stackvars: ChainMapCOW[int, VirtualVariable] | None = None,
    ):
        self.loc = loc
        self.arch = arch
        self.func = func

        self.registers = registers or {}
        self.stackvars = stackvars if stackvars is not None else ChainMapCOW(collapse_threshold=200)
        self.tmps: dict[int, VirtualVariable] = {}
        self.original_block = original_block
        self.out_block = None

    def copy(self) -> RewritingState:
        copy_regs = dict(self.registers)

        return RewritingState(
            self.loc,
            self.arch,
            self.func,
            self.original_block,
            registers=copy_regs,
            stackvars=self.stackvars.copy(),
        )

    def append_statement(self, stmt: Statement):
        if self.out_block is None:
            self.out_block = Block(self.loc.block_addr, self.original_block.original_size, idx=self.loc.block_idx)
        self.out_block.statements.append(stmt)
