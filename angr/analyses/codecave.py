from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.cfg import CFGBase
from angr.knowledge_plugins.cfg import MemoryDataSort

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function


log = logging.getLogger(__name__)


class CodeCaveClassification(Enum):
    """
    Type of code caves.
    """

    ALIGNMENT = auto()
    UNREACHABLE = auto()


@dataclass
class CodeCave:
    """
    Describes a code cave in a binary.
    """

    func: Function | None
    addr: int
    size: int
    classification: CodeCaveClassification


class CodeCaveAnalysis(Analysis):
    """
    Best-effort static location of potential vacant code caves for possible code injection:
    - Padding functions
    - Unreachable code
    """

    codecaves: list[CodeCave]

    def __init__(self):
        self.codecaves = []

        if len(self.project.kb.functions) == 0 and self.project.kb.cfgs.get_most_accurate() is None:
            log.warning("Please run CFGFast analysis first, to identify functions")
            return

        # Alignment functions
        for func in self.project.kb.functions.values():
            if func.is_alignment:
                for block in func.blocks:
                    self.codecaves.append(CodeCave(func, block.addr, block.size, CodeCaveClassification.ALIGNMENT))

        # Alignment also labels metadata such as XFG hashes. Only export complete no-op ranges outside recovered code.
        cfg = self.project.kb.cfgs.get_most_accurate()
        if cfg is not None:
            for data in cfg.memory_data.values():
                if data.sort != MemoryDataSort.Alignment or not data.size:
                    continue
                if cfg.get_all_nodes_intersecting_region(data.addr, data.size):
                    continue
                addr = data.addr
                end = data.addr + data.size
                while addr < end:
                    block = self.project.factory.block(addr, size=end - addr)
                    if not block.size or not CFGBase._is_noop_block(self.project.arch, block):
                        break
                    addr += block.size
                if addr == end:
                    self.codecaves.append(CodeCave(None, data.addr, data.size, CodeCaveClassification.ALIGNMENT))

        # Unreachable code
        for func in self.project.kb.functions.values():
            if func.is_alignment or func.is_plt or func.is_simprocedure or func.addr in self.project.kb.labels:
                continue

            in_degree = self.project.kb.callgraph.in_degree(func.addr)
            if in_degree == 0 or (
                in_degree == 1
                and self.project.kb.functions[next(self.project.kb.callgraph.predecessors(func.addr))].is_alignment
            ):
                for block in func.blocks:
                    self.codecaves.append(CodeCave(func, block.addr, block.size, CodeCaveClassification.UNREACHABLE))

            # FIXME: find dead blocks with argument propagation
            # FIXME: find dead blocks with external coverage info


AnalysesHub.register_default("CodeCaves", CodeCaveAnalysis)
