from typing import List

import claripy

from ..analysis import Analysis, AnalysesHub
from .apis import CauseBase, InstrOperandCause, InstrOpcodeCause


OP_TYPE_IMM = 2  # from capstone


class RootCauseAnalysis(Analysis):
    def __init__(self, block_addr: int, stmt_idx: int, constraint=None, cross_insn_opt=False):
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.constraint = constraint
        self.cross_insn_opt = cross_insn_opt

        self.causes = self.analyze()

    def analyze(self):
        block = self.project.factory.block(self.block_addr, cross_insn_opt=self.cross_insn_opt)
        stmt = block.vex.statements[self.stmt_idx]

        causes: List[CauseBase] = [ ]

        # handle simple cases
        if self.constraint is not None and self.constraint.op in ('__eq__', '__ne__'):
            # comparison. we report both the comparison itself and the constant (if there is any)
            if not self.constraint.args[1].symbolic:
                # find its source
                for ins in reversed(block.capstone.insns):
                    # iterate in its operands
                    for idx, operand in enumerate(ins.operands):
                        if operand.type == OP_TYPE_IMM and operand.value.imm == self.constraint.args[1].args[0]:
                            # found it!
                            cause = InstrOperandCause(ins.address, idx, operand.value.imm)
                            causes.append(cause)
                    # x86
                    if ins.mnemonic in {'cmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe'}:
                        # report it
                        cause = InstrOpcodeCause(ins.address, ins.mnemonic)
                        causes.append(cause)

        return causes


AnalysesHub.register_default('RootCause', RootCauseAnalysis)