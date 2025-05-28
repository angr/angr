# pylint:disable=too-many-boolean-expressions
from __future__ import annotations

import archinfo

from angr.ailment import Block
from angr.ailment.statement import Statement, Call, Assignment
from angr.ailment.expression import Const, Register, VirtualVariable

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.optimization_passes import register_optimization_pass

WIN64_REG_ARGS = {
    archinfo.ArchAMD64().registers["rcx"][0],
    archinfo.ArchAMD64().registers["rdx"][0],
    archinfo.ArchAMD64().registers["r8"][0],
    archinfo.ArchAMD64().registers["r9"][0],
}


class StringObfType3Rewriter(OptimizationPass):
    """
    Type-3 optimization pass replaces deobfuscate_string calls with the deobfuscated strings, and then removes
    arguments on the stack.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["windows"]
    STAGE = OptimizationPassStage.AFTER_MAKING_CALLSITES

    NAME = "Simplify Type 3 string deobfuscation calls"
    DESCRIPTION = "Simplify Type 3 string deobfuscation calls"
    stmt_classes = ()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        if self.kb.obfuscations.type3_deobfuscated_strings:
            return True, None
        return False, None

    @staticmethod
    def is_call_or_call_assignment(stmt) -> bool:
        return isinstance(stmt, Call) or (isinstance(stmt, Assignment) and isinstance(stmt.src, Call))

    def _analyze(self, cache=None):

        # find all blocks with type-3 deobfuscation calls
        for block in list(self._graph):
            if not block.statements:
                continue
            last_stmt = block.statements[-1]
            if (
                self.is_call_or_call_assignment(last_stmt)
                and last_stmt.ins_addr in self.kb.obfuscations.type3_deobfuscated_strings
            ):
                new_block = self._process_block(
                    block, self.kb.obfuscations.type3_deobfuscated_strings[block.statements[-1].ins_addr]
                )
                if new_block is not None:
                    self._update_block(block, new_block)

    def _process_block(self, block: Block, deobf_content: bytes):
        # FIXME: This rewriter is very specific to the implementation of the deobfuscation scheme. we can make it more
        # generic when there are more cases available in the wild.

        # TODO: Support multiple blocks

        # replace the call
        old_stmt: Statement = block.statements[-1]
        str_id = self.kb.custom_strings.allocate(deobf_content)
        old_call: Call = old_stmt.src if isinstance(old_stmt, Assignment) else old_stmt
        new_call = Call(
            old_call.idx,
            "init_str",
            args=[
                old_call.args[0],
                Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                Const(None, None, len(deobf_content), self.project.arch.bits),
            ],
            ret_expr=old_call.ret_expr,
            bits=old_call.bits,
            **old_call.tags,
        )
        if isinstance(old_stmt, Assignment):
            new_stmt = Assignment(old_stmt.idx, old_stmt.dst, new_call, **old_stmt.tags)
        else:
            new_stmt = new_call

        statements = block.statements[:-1] + [new_stmt]

        # remove N-2 continuous stack assignment
        if len(deobf_content) > 2:
            stack_offset_to_stmtid: dict[int, int] = {}
            for idx, stmt in enumerate(statements):
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_stack
                    and isinstance(stmt.dst.stack_offset, int)
                    and isinstance(stmt.src, Const)
                    and stmt.src.value <= 0xFF
                ):
                    stack_offset_to_stmtid[stmt.dst.stack_offset] = idx
            sorted_offsets = sorted(stack_offset_to_stmtid)
            if sorted_offsets:
                spacing = 8  # FIXME: Make it adjustable
                distance = min(len(deobf_content) - 2, len(sorted_offsets) - 1)
                for start_idx in range(len(sorted_offsets) - distance):
                    if sorted_offsets[start_idx] + spacing * distance == sorted_offsets[start_idx + distance]:
                        # found them
                        # remove these statements
                        for i in range(start_idx, start_idx + distance + 1):
                            statements[stack_offset_to_stmtid[sorted_offsets[i]]] = None
                        break
                statements = [stmt for stmt in statements if stmt is not None]

        # remove writes to rdx, rcx, r8, and r9
        if self.project.arch.name == "AMD64":
            statements = [stmt for stmt in statements if not self._stmt_sets_win64_reg_arg(stmt)]

        # return the new block
        return block.copy(statements=statements)

    @staticmethod
    def _stmt_sets_win64_reg_arg(stmt) -> bool:
        return isinstance(stmt, Assignment) and isinstance(stmt.dst, Register) and stmt.dst.reg_offset in WIN64_REG_ARGS


register_optimization_pass(StringObfType3Rewriter, presets=["fast", "full"])
