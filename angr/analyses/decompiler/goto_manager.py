from typing import Set
from collections import defaultdict

import ailment


class Goto:
    """
    Describe the existence of a goto (jump) statement. May have multiple gotos with the same address (targets
    will differ).
    """

    def __init__(self, block_addr=None, ins_addr=None, target_addr=None):
        """
        :param block_addr:  The block address this goto is contained in
        :param ins_addr:    The instruction address this goto is at
        :param target_addr: The target this goto will jump to
        """
        self.block_addr = block_addr
        self.ins_addr = ins_addr
        self.target_addr = target_addr

    def __hash__(self):
        return hash(f"{self.block_addr}{self.ins_addr}{self.target_addr}")

    def __str__(self):
        if not self.addr or not self.target_addr:
            return f"<Goto {self.__hash__()}>"

        return f"<Goto: [{hex(self.addr)}] -> {hex(self.target_addr)}>"

    def __repr__(self):
        return self.__str__()

    @property
    def addr(self):
        return self.block_addr or self.ins_addr


class GotoManager:
    """
    Container class for all Gotos found in a function after decompilation structuring.
    This should be populated using GotoSimplifier.
    """

    def __init__(self, func, gotos=None):
        self.func = func
        self.gotos: Set[Goto] = gotos or set()

        self._gotos_by_addr = None

    def __str__(self):
        return f"<GotoManager: func[{hex(self.func.addr)}] {len(self.gotos)} gotos>"

    def __repr__(self):
        return self.__str__()

    def gotos_by_addr(self, force_refresh=False):
        """
        Returns a dictionary of gotos by addresses. This set can CONTAIN DUPLICATES, so don't trust
        this for a valid number of gotos. If you need the real number of gotos, just get the size of
        self.gotos. This set should mostly be used when checking if a block contains a goto, since recording
        can be recorded on null-addr blocks.

        :param force_refresh: Don't use the cached self._gotos_by_addr
        :return:
        """

        if not force_refresh and self._gotos_by_addr:
            return self._gotos_by_addr

        self._gotos_by_addr = defaultdict(set)
        for goto in self.gotos:
            if goto.block_addr is not None:
                self._gotos_by_addr[goto.block_addr].add(goto)

            if goto.ins_addr is not None:
                self._gotos_by_addr[goto.ins_addr].add(goto)

        return self._gotos_by_addr

    def gotos_in_block(self, block: ailment.Block) -> Set[Goto]:
        gotos_by_addr = self.gotos_by_addr()
        gotos = set()
        if block.addr in gotos_by_addr:
            gotos.update(gotos_by_addr[block.addr])

        for stmt in block.statements:
            if stmt.ins_addr in gotos_by_addr:
                gotos.update(gotos_by_addr[stmt.ins_addr])

        return gotos
