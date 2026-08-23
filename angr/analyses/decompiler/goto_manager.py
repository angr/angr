from __future__ import annotations

import networkx

from angr import ailment
from angr.ailment.block import Block

from .utils import find_block_by_addr_and_idx


class Goto:
    """
    Describe the existence of a goto (jump) statement. May have multiple gotos with the same address (targets
    will differ).
    """

    def __init__(self, src_addr, dst_addr, src_idx=None, dst_idx=None, src_ins_addr=None):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_idx = src_idx
        self.dst_idx = dst_idx
        self.src_ins_addr = src_ins_addr

    def __hash__(self):
        return hash(f"{self.src_addr}{self.dst_addr}{self.src_idx}{self.dst_idx}")

    def __str__(self):
        if self.src_addr is None or self.dst_addr is None:
            return f"<Goto {self.__hash__()}>"

        src_idx_str = "" if self.src_idx is None else f".{self.src_idx}"
        dst_idx_str = "" if self.dst_idx is None else f".{self.dst_idx}"
        src_ins_addr_str = "" if self.src_ins_addr is None else f"{hex(self.src_ins_addr)}"
        return f"<Goto: [{hex(self.src_addr)}@{src_ins_addr_str}{src_idx_str}] -> {hex(self.dst_addr)}{dst_idx_str}>"

    def __repr__(self):
        return self.__str__()


class GotoManager:
    """
    Container class for all Gotos found in a function after decompilation structuring.
    This should be populated using GotoSimplifier.
    """

    def __init__(self, func, gotos=None):
        self.func = func
        self.gotos: set[Goto] = gotos or set()

        self._gotos_by_addr = None

    def __str__(self):
        return f"<GotoManager: func[{hex(self.func.addr)}] {len(self.gotos)} gotos>"

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def _instruction_addrs(block: ailment.Block) -> set[int]:
        return {stmt.tags["ins_addr"] for stmt in block.statements if "ins_addr" in stmt.tags}

    @classmethod
    def find_source_block(cls, graph: networkx.DiGraph, goto: Goto) -> ailment.Block | None:
        try:
            return find_block_by_addr_and_idx(graph, goto.src_addr, goto.src_idx)
        except ValueError:
            pass

        if goto.src_ins_addr is None:
            return None
        fallback_blocks = [
            block
            for block in graph
            if block.addr != goto.src_addr and goto.src_ins_addr in cls._instruction_addrs(block)
        ]
        return fallback_blocks[0] if len(fallback_blocks) == 1 else None

    @classmethod
    def find_destination_block(cls, graph: networkx.DiGraph, goto: Goto) -> ailment.Block | None:
        try:
            return find_block_by_addr_and_idx(graph, goto.dst_addr, goto.dst_idx)
        except ValueError:
            pass

        fallback_blocks = [
            block for block in graph if block.addr != goto.dst_addr and goto.dst_addr in cls._instruction_addrs(block)
        ]
        return fallback_blocks[0] if len(fallback_blocks) == 1 else None

    def gotos_in_block(self, block: ailment.Block, graph: networkx.DiGraph | None = None) -> set[Goto]:
        gotos_found = set()
        for goto in self.gotos:
            if graph is not None:
                if self.find_source_block(graph, goto) is block:
                    gotos_found.add(goto)
            elif (goto.src_addr, goto.src_idx) == (block.addr, block.idx):
                gotos_found.add(goto)

        return gotos_found

    def is_goto_edge(self, src: ailment.Block, dst: ailment.Block, graph: networkx.DiGraph | None = None):
        src_gotos = self.gotos_in_block(src, graph=graph)
        for goto in src_gotos:
            if graph is not None:
                if self.find_destination_block(graph, goto) is dst:
                    return True
            elif (goto.dst_addr, goto.dst_idx) == (dst.addr, dst.idx):
                return True

        return False

    def find_goto_edges(self, graph: networkx.DiGraph) -> list[tuple[Block, Block]]:
        """
        This function finds all edges that are _potential_ gotos in the graph.
        The gotos are not guaranteed to be correct, but they are an approximation based on how the Phoenix
        structuring algorithm will select edges from the graph to be gotos in structuring.
        """
        # Resolve each recorded goto to exact or uniquely shifted blocks.
        goto_edges = []
        for goto in self.gotos:
            dst_block = self.find_destination_block(graph, goto)
            src_block = self.find_source_block(graph, goto)

            if src_block is not None and dst_block is not None:
                # if you found the source, we dont need to try later things on this dst
                goto_edges.append((src_block, dst_block))

        return goto_edges
