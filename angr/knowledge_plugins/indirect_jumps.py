from collections import Mapping

from .artifact import KnowledgeArtifact
from ..errors import AngrError


class IndirectJumpsPlugin(KnowledgeArtifact, Mapping):
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
    _provides = 'indirect_jumps'

    def __init__(self, kb=None):
        super(IndirectJumpsPlugin, self).__init__(kb)
        self._jumps = dict()
        self._complete_jumps = set()

    def copy(self):
        o = IndirectJumpsPlugin(self._kb)
        o._jumps = self._jumps.copy()
        o._complete_jumps = self._complete_jumps.copy()
        return o

    #
    #   ...
    #

    def __getitem__(self, item):
        return self._jumps[item]

    def __iter__(self):
        return iter(self._jumps)

    def __len__(self):
        return len(self._jumps)

    #
    #   ...
    #

    def register_jump(self, from_addr, to_addr, jumpkind, insn_addr=None, stmt_idx=None, overwrite=True):
        """

        :param from_addr:
        :param to_addr:
        :param jumpkind:
        :param insn_addr:
        :param stmt_idx:
        :param overwrite:
        :return:
        """
        specs = jumpkind, insn_addr, stmt_idx
        targets = self._jumps.setdefault(from_addr, {})

        if not overwrite and to_addr in targets and targets[to_addr] != specs:
            raise AngrError("Already have %#x -> %#x jump with specs: %s"
                            % (from_addr, to_addr, specs))

        targets[to_addr] = specs

        self._notify_observers('register_jump', from_addr=from_addr, to_addr=to_addr, specs=specs)

    def make_complete(self, from_addr):
        if from_addr not in self._jumps:
            raise AngrError("No indirect jump from %#x" % from_addr)
        self._complete_jumps.add(from_addr)

    def is_complete(self, from_addr):
        if from_addr not in self._jumps:
            raise AngrError("No indirect jump from %#x" % from_addr)
        return from_addr in self._complete_jumps
