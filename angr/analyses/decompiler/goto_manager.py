from __future__ import annotations
import ailment
from ailment.block import Block
import networkx

from .utils import find_block_by_addr


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

    def gotos_in_block(self, block: ailment.Block) -> set[Goto]:
        gotos_found = set()
        for goto in self.gotos:
            if goto.src_addr == block.addr:
                gotos_found.add(goto)
            else:
                block_addrs = {stmt.ins_addr for stmt in block.statements if "ins_addr" in stmt.tags}
                if goto.src_ins_addr in block_addrs:
                    gotos_found.add(goto)

        return gotos_found

    def is_goto_edge(self, src: ailment.Block, dst: ailment.Block):
        src_gotos = self.gotos_in_block(src)
        for goto in src_gotos:
            if goto.dst_addr == dst.addr:
                return True
            block_addrs = {stmt.ins_addr for stmt in dst.statements if "ins_addr" in stmt.tags}
            if goto.dst_addr in block_addrs:
                return True

        return False

    def find_goto_edges(self, graph: networkx.DiGraph) -> list[tuple[Block, Block]]:
        """
        This function finds all edges that are _potential_ gotos in the graph.
        The gotos are not guaranteed to be correct, but they are an approximation based on how the Phoenix
        structuring algorithm will select edges from the graph to be gotos in structuring.
        """
        # first collect all simple destinations known by the goto managers
        dst_blocks = set()
        goto_edges = []
        for goto in self.gotos:
            try:
                dst_block = find_block_by_addr(graph, goto.dst_addr)
            except ValueError:
                continue

            try:
                src_block = find_block_by_addr(graph, goto.src_addr)
            except ValueError:
                src_block = None

            if src_block is None:
                # try the instruction addrs in the block to find the goto
                try:
                    src_block = find_block_by_addr(graph, goto.src_ins_addr, insn_addr=True)
                except ValueError:
                    src_block = None

            if src_block is not None and dst_block is not None:
                # if you found the source, we dont need to try later things on this dst
                goto_edges.append((src_block, dst_block))
            elif dst_block is not None:
                dst_blocks.add(dst_block)

        return goto_edges
