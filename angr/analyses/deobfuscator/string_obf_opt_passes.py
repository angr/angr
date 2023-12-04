from typing import Dict

from ailment import Block
from ailment.statement import Call, Store
from ailment.expression import Const, StackBaseOffset

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.optimization_passes import register_optimization_pass


class StringObfType3Rewriter(OptimizationPass):
    """
    Type-3 optimization pass replaces deobfuscate_string calls with the deobfuscated strings, and then removes
    arguments on the stack.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["windows"]
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION

    NAME = "Simplify Type 3 string deobfuscation calls"
    stmt_classes = ()

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)

        self.analyze()

    def _check(self):
        if self.kb.obfuscations.type3_deobfuscated_strings:
            return True, None
        return False, None

    def _analyze(self, cache=None):

        # find all blocks with type-3 deobfuscation calls
        for block in list(self._graph):
            if not block.statements:
                continue
            last_stmt = block.statements[-1]
            if isinstance(last_stmt, Call) and last_stmt.ins_addr in self.kb.obfuscations.type3_deobfuscated_strings:
                new_block = self._process_block(
                    block, self.kb.obfuscations.type3_deobfuscated_strings[block.statements[-1].ins_addr]
                )
                if new_block is not None:
                    self._update_block(block, new_block)

    def _process_block(self, block: Block, deobf_content: bytes):
        # FIXME: This rewriter is very specific to the implementation of the deobfuscation scheme. we can make it more
        # generic when there are more cases available in the wild.

        # replace the call
        old_call: Call = block.statements[-1]
        str_id = self.kb.custom_strings.allocate(deobf_content)
        new_call = Call(
            old_call.idx,
            "init_str",
            args=[
                old_call.args[0],
                Const(None, None, str_id, self.project.arch.bits, custom_string=True),
                Const(None, None, len(deobf_content), self.project.arch.bits),
            ],
            ret_expr=old_call.ret_expr,
            **old_call.tags,
        )

        statements = block.statements[:-1] + [new_call]

        # remove N-2 continuous stack assignment
        if len(deobf_content) > 2:
            stack_offset_to_stmtid: Dict[int, int] = {}
            for idx, stmt in enumerate(statements):
                if (
                    isinstance(stmt, Store)
                    and isinstance(stmt.addr, StackBaseOffset)
                    and isinstance(stmt.data, Const)
                    and stmt.data.value <= 0xFF
                ):
                    stack_offset_to_stmtid[stmt.addr.offset] = idx
            sorted_offsets = sorted(stack_offset_to_stmtid)
            spacing = 8  # FIXME: Make it adjustable
            distance = min(len(deobf_content) - 2, len(sorted_offsets) - 1)
            for start_idx in range(len(sorted_offsets) - distance):
                if sorted_offsets[start_idx] + spacing * distance == sorted_offsets[start_idx + distance]:
                    # found them
                    # remove these statements
                    for i in range(start_idx, start_idx + distance):
                        statements[stack_offset_to_stmtid[sorted_offsets[i]]] = None
                    break
            statements = [stmt for stmt in statements if stmt is not None]

        # return the new block
        new_block = block.copy(statements=statements)
        return new_block


register_optimization_pass(StringObfType3Rewriter, True)
