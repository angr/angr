# pylint:disable=missing-class-docstring
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
from collections import defaultdict
from dataclasses import dataclass

from sortedcontainers import SortedDict

from angr.analyses import Analysis, AnalysesHub
from angr.utils.bits import ffs

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function


log = logging.getLogger(__name__)


class OverlappingFunctionsAnalysis(Analysis):
    """
    Identify functions with interleaved blocks.
    """

    overlapping_functions: dict[int, list[int]]

    def __init__(self):
        self.overlapping_functions = defaultdict(list)
        addr_to_func_max_addr = SortedDict()

        for func in self.project.kb.functions.values():
            if func.is_alignment:
                continue
            func_max_addr = max((block.addr + block.size) for block in func.blocks)
            addr_to_func_max_addr[func.addr] = (func, func_max_addr)

        for idx, (addr, (_func, max_addr)) in enumerate(addr_to_func_max_addr.items()):
            for other_addr in addr_to_func_max_addr.islice(idx + 1):
                if other_addr >= max_addr:
                    break

                self.overlapping_functions[addr].append(other_addr)


class FunctionAlignmentAnalysis(Analysis):
    """
    Determine typical function alignment
    """

    alignment: int | None

    def __init__(self):
        self.alignment = None

        if len(self.project.kb.functions) == 0:
            if self.project.kb.cfgs.get_most_accurate() is None:
                log.warning("Please run CFGFast analysis first, to identify functions")
            return

        alignment_bins = defaultdict(int)
        count = 0
        for func in self.project.kb.functions.values():
            if not (func.is_alignment or func.is_plt or func.is_simprocedure):
                alignment_bins[ffs(func.addr)] += 1
                count += 1

        # FIXME: Higher alignment values will be naturally aligned

        typical_alignment = max(alignment_bins, key=lambda k: alignment_bins[k])
        if count > 10 and alignment_bins[typical_alignment] >= count / 4:  # XXX: cutoff
            self.alignment = 1 << max(typical_alignment, 0)
            log.debug("Function alignment appears to be %d bytes", self.alignment)


@dataclass
class AtypicallyAlignedFunction:
    function: Function
    expected_alignment: int


@dataclass
class PatchedOutFunctionality:
    patched_function: Function
    patched_out_function: Function


class PatchFinderAnalysis(Analysis):
    """
    Looks for binary patches using some basic heuristics:
    - Looking for interleaved functions
    - Looking for unaligned functions
    """

    # FIXME: Possible additional heuristics:
    # - Jumps out to end of function, then back
    # - Looking for patch jumps, e.g. push <addr>; ret
    # - Looking for instruction partials broken by a patch (nodecode)
    # - Unusual stack manipulation

    atypical_alignments: list[AtypicallyAlignedFunction]
    possibly_patched_out: list[PatchedOutFunctionality]

    def __init__(self):
        self.atypical_alignments = []
        self.possibly_patched_out = []

        if len(self.project.kb.functions) == 0:
            if self.project.kb.cfgs.get_most_accurate() is None:
                log.warning("Please run CFGFast analysis first, to identify functions")
            return

        # In CFGFast with scanning enabled, a function may be created from unreachable blocks within another function.
        # Search for interleaved/overlapping functions to identify possible patches.
        overlapping_functions = self.project.analyses.OverlappingFunctions().overlapping_functions
        for addr, overlapping_func_addrs in overlapping_functions.items():
            func = self.project.kb.functions[addr]

            # Are the overlapping functions reachable?
            for overlapping_addr in overlapping_func_addrs:
                overlapping_func = self.project.kb.functions[overlapping_addr]
                if self.project.kb.callgraph.in_degree(overlapping_addr) == 0:
                    self.possibly_patched_out.append(PatchedOutFunctionality(func, overlapping_func))
                    # FIXME: What does the patch do?

        # Look for unaligned functions
        expected_alignment = self.project.analyses.FunctionAlignment().alignment
        if expected_alignment is not None and expected_alignment > self.project.arch.instruction_alignment:
            for func in self.project.kb.functions.values():
                if not (func.is_alignment or func.is_plt or func.is_simprocedure) and func.addr & (
                    expected_alignment - 1
                ):
                    self.atypical_alignments.append(AtypicallyAlignedFunction(func, expected_alignment))


AnalysesHub.register_default("OverlappingFunctions", OverlappingFunctionsAnalysis)
AnalysesHub.register_default("FunctionAlignment", FunctionAlignmentAnalysis)
AnalysesHub.register_default("PatchFinder", PatchFinderAnalysis)
