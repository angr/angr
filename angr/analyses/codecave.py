from __future__ import annotations
import logging
from enum import Enum, auto
from typing import TYPE_CHECKING
from dataclasses import dataclass

from angr.analyses import Analysis, AnalysesHub


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
