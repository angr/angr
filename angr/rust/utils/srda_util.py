from ailment import Assignment
from ailment.expression import VirtualVariable

from angr.analyses.s_reaching_definitions import SRDAView, SReachingDefinitionsAnalysis
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


class SRDAUtil:
    def __init__(self, srda: SReachingDefinitionsAnalysis):
        self.srda = srda
        self.srda_view = SRDAView(srda.model)

    def get_stack_vvar_by_insn(
        self, stack_offset: int, addr: int, block_idx: int | None = None
    ) -> VirtualVariable | None:
        vvars = set()

        def _predicate(stmt) -> bool:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset == stack_offset
            ):
                vvars.add(stmt.dst)
                return True
            return False

        self.srda_view._get_vvar_by_insn(addr, OP_BEFORE, _predicate, block_idx=block_idx)

        # assert len(vvars) <= 1
        return next(iter(vvars), None)
