from .plugin import KnowledgeBasePlugin
from ..code_location import CodeLocation


class Propagations(KnowledgeBasePlugin):

    def __init__(self, kb):
        self._kb = kb
        self._propagations = {}

    def find_nearest_prop(self, target_addr, block_addr):
        '''
        This function attempts to find a propagation closest to the
        target_addr. If a propagation cannot be found, None is returned.

        :param target_addr: An address to a target inst
        :param block_addr:  An address to a target basic block
        :return:            A dictionary of propagation state OR None
        '''

        # sanity check
        if len(self._propagations) == 0:
            return None

        # check if the block exists
        block_found = False
        for b in self._propagations:
            if b.block_addr == block_addr:
                block_found = True

        # TODO: for now we can only support the same block
        # but we should be able to take any ancestor and start
        # at that point
        if not block_found:
            return None

        block_loc = CodeLocation(block_addr, None)
        block_prop = self._propagations[block_loc]

        return block_prop

    def copy(self):
        o = Propagations(self._kb)
        o._propagations = {k: v for k, v in self._labels.items()}