from collections import defaultdict

from ..errors import AngrError
from .plugin import KnowledgeBasePlugin

import logging
l = logging.getLogger(name=__name__)


class IndirectJumpsPlugin(KnowledgeBasePlugin):
    """
    Storage for information about indirect jumps in the program. Access with kb.indirect_jumps.

    Every exit that can not be obtained from direct analysis of IRSB should be considered as
    an indirect jump. Every exit that is produced by a SimProcedure should be considred as
    an indirect jump too.

    These two particular requirements are made in order for user to be able to reconstruct the
    CFG using only that knowledge that is present in the knowledge base.

    :ivar _jumps:               Mapping from instruction address to list of possible targets,
                                along with jumpkinds, instruction addresses and statement indexes.
    :ivar _complete_jumps:      A set of complete jumps, i.e. jumps with exhaustive targets list.
    """

    def __init__(self):
        super(IndirectJumpsPlugin, self).__init__()
        self._jumps = defaultdict(dict)
        self._complete_jumps = set()

    @property
    def jumps(self):
        return self._jumps

    @property
    def complete_jumps(self):
        return self._complete_jumps

    #
    #   ...
    #

    def register_jump(self, src_addr, dst_addr, **jump_specs):
        """Register an indirect jump from `src_addr` to `dst_addr` of jump kind `jumpkind`.

        :param src_addr:    The source address of the indirect jump.
        :param dst_addr:    The destination address of the indirect jump.

        :param jumpkind:    The jumpkind of the indirect jump.
        :param ins_addr:   The address of the instruction that produces the indirect jump.
        :param stmt_idx:    The index of the statement that produces the indirect jump.

        :return:
        """
        self._jumps[src_addr][dst_addr] = jump_specs

    def get_jump_targets(self, src_addr):
        """

        :param src_addr:
        :return:
        """
        if src_addr not in self._jumps:
            raise AngrError("No indirect jump from %#x" % src_addr)
        return self._jumps[src_addr]

    def mark_complete(self, src_addr):
        """Mark indirect jump from src_addr as complete, that is, having an exhaustive targets list.

        :param src_addr:
        :return:
        """
        if src_addr not in self._jumps:
            raise AngrError("No indirect jump from %#x" % src_addr)
        self._complete_jumps.add(src_addr)

    def is_complete(self, src_addr):
        """Return True if the indirect jump at src_addr is complete, that is, having an exhaustive targets list.

        :param src_addr:
        :return:
        """
        if src_addr not in self._jumps:
            raise AngrError("No indirect jump from %#x" % src_addr)
        return src_addr in self._complete_jumps
