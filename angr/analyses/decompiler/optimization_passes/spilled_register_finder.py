import logging

from .register_save_area_simplifier import RegisterSaveAreaSimplifier


_l = logging.getLogger(name=__name__)


class SpilledRegisterFinder(RegisterSaveAreaSimplifier):
    """
    Finds spilled registers and tags them with pseudoregisters based on their stack offset.
    """

    @staticmethod
    def _modify_statement(old_block, stmt_idx_: int, updated_blocks_, stack_offset: int = None):
        old_stmt = old_block.statements[stmt_idx_]
        pseudoreg = 0x1000000 - stack_offset
        old_stmt.tags["pseudoreg"] = pseudoreg
