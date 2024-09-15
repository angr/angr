from __future__ import annotations
from collections import defaultdict

from ailment.statement import Statement
from ailment.expression import VirtualVariable
from ailment.block import Block

from angr.code_location import CodeLocation


class RewritingState:
    """
    The abstract state for the expression rewriting engine.
    """

    def __init__(
        self,
        loc: CodeLocation,
        arch,
        func,
        original_block: Block,
        registers: dict[int, dict[int, VirtualVariable]] | None = None,
        stackvars: dict[int, dict[int, VirtualVariable]] | None = None,
    ):
        self.loc = loc
        self.arch = arch
        self.func = func

        self.registers: defaultdict[int, dict[int, VirtualVariable | None]] = (
            registers if registers is not None else defaultdict(dict)
        )
        self.stackvars: defaultdict[int, dict[int, VirtualVariable]] = (
            stackvars if stackvars is not None else defaultdict(dict)
        )
        self.original_block = original_block
        self.out_block = None

    def copy(self) -> RewritingState:

        copy_regs = defaultdict(dict)
        for k, vdict in self.registers.items():
            copy_regs[k] = vdict.copy()

        copy_stackvars = defaultdict(dict)
        for k, vdict in self.stackvars.items():
            copy_stackvars[k] = vdict.copy()

        return RewritingState(
            self.loc,
            self.arch,
            self.func,
            self.original_block,
            registers=copy_regs,
            stackvars=copy_stackvars,
        )

    def append_statement(self, stmt: Statement):
        if self.out_block is None:
            self.out_block = Block(self.loc.block_addr, self.original_block.original_size, idx=self.loc.block_idx)
        self.out_block.statements.append(stmt)
