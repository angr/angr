from __future__ import annotations
from typing import TYPE_CHECKING

from collections.abc import Generator
from collections import defaultdict
import contextlib
import logging

from archinfo.arch_arm import is_arm_arch

from angr.analyses import AnalysesHub
from angr.analyses.analysis import Analysis
from angr.errors import AngrRuntimeError
from .flirt_sig import FlirtSignature, FlirtSignatureParsed
from .flirt_function import FlirtFunction
from .flirt_matcher import FlirtMatcher

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


_l = logging.getLogger(name=__name__)


MAX_UNIQUE_STRING_LEN = 70


class FlirtAnalysis(Analysis):
    """
    FlirtAnalysis accomplishes two purposes:

    - If a FLIRT signature file is specified, it will match the given signature file against the current binary and
      rename recognized functions accordingly.
    - If no FLIRT signature file is specified, it will use strings to determine possible libraries embedded in the
      current binary, and then match all possible signatures for the architecture.
    """

    def __init__(self, sig: FlirtSignature | str | None = None, max_mismatched_bytes: int = 0):

        from angr.flirt import FLIRT_SIGNATURES_BY_ARCH  # pylint:disable=import-outside-toplevel

        self._is_arm = is_arm_arch(self.project.arch)
        self._all_suggestions: dict[str, dict[str, dict[int, str]]] = {}
        self._suggestions: dict[int, str] = {}
        self.matched_suggestions: dict[str, tuple[FlirtSignature, dict[int, str]]] = {}
        self._temporary_sig = False
        self._max_mismatched_bytes = max_mismatched_bytes

        if sig:
            if isinstance(sig, str):
                # this is a file path
                simos_name = self.project.arch.name if self.project.simos.name is not None else "UnknownOS"
                sig = FlirtSignature(simos_name.lower(), simos_name.lower(), "Temporary", sig, None)

                self.signatures = [sig]
                self._temporary_sig = True

        else:
            if not FLIRT_SIGNATURES_BY_ARCH:
                raise AngrRuntimeError(
                    "No FLIRT signatures exist. Please load FLIRT signatures by calling "
                    "load_signatures() before running FlirtAnalysis."
                )

            # determine all signatures to match against strings in mapped memory regions
            mem_regions = [
                self.project.loader.memory.load(seg.vaddr, seg.memsize)
                for seg in self.project.loader.main_object.segments
                if seg.filesize > 0 and seg.memsize > 0
            ]

            self.signatures = list(self._find_hits_by_strings(mem_regions))
            _l.debug("Identified %d signatures to apply.", len(self.signatures))

        path_to_sig: dict[str, FlirtSignature] = {}
        for sig_ in self.signatures:
            self._match_all_against_one_signature(sig_)
            if sig_.sig_name not in self._all_suggestions:
                self._all_suggestions[sig_.sig_name] = {}
            path_to_sig[sig_.sig_path] = sig_
            self._all_suggestions[sig_.sig_name][sig_.sig_path] = self._suggestions
            self._suggestions = {}

        for lib, sig_to_suggestions in self._all_suggestions.items():
            max_suggestions = None
            max_suggestion_sig_path = None
            for sig_, suggestion in sig_to_suggestions.items():
                _l.debug("Signature %s has %d function name suggestions.", sig_, len(suggestion))
                if max_suggestions is None or len(suggestion) > max_suggestions:
                    max_suggestion_sig_path = sig_
                    max_suggestions = len(suggestion)

            if max_suggestion_sig_path is not None:
                sig_ = path_to_sig.get(max_suggestion_sig_path)
                assert sig_ is not None
                _l.info("Applying FLIRT signature %s for library %s.", sig_, lib)
                self._apply_changes(
                    sig_.sig_name if not self._temporary_sig else None, sig_to_suggestions[max_suggestion_sig_path]
                )
                self.matched_suggestions[lib] = (sig_, sig_to_suggestions[max_suggestion_sig_path])

    def _find_hits_by_strings(self, regions: list[bytes]) -> Generator[FlirtSignature]:

        from angr.flirt import STRING_TO_LIBRARIES, LIBRARY_TO_SIGNATURES  # pylint:disable=import-outside-toplevel

        library_hits: dict[str, int] = defaultdict(int)
        for s, libs in STRING_TO_LIBRARIES.items():
            for region in regions:
                if s.encode("ascii") in region:
                    for lib in libs:
                        library_hits[lib] += 1

        # sort libraries based on the number of hits
        sorted_libraries = sorted(library_hits.keys(), key=lambda lib: library_hits[lib], reverse=True)
        arch_lowercase = self.project.arch.name.lower()

        for lib in sorted_libraries:
            for sig in LIBRARY_TO_SIGNATURES[lib]:
                if sig.arch == arch_lowercase:
                    yield sig
                elif sig.arch == "armel" and self._is_arm:
                    # ARMHF may use ARMEL libraries
                    yield sig

    def _match_all_against_one_signature(self, sig: FlirtSignature):
        # match each function
        self._suggestions = {}
        with open(sig.sig_path, "rb") as sigfile:
            flirt = FlirtSignatureParsed.parse(sigfile)
            tolerances = range(self._max_mismatched_bytes + 1)
            for tolerance in tolerances:
                # we iteratively match until we find no new matches
                updated_funcs = set()
                while True:
                    matched = False

                    funcs = (
                        self.project.kb.functions.values()
                        if not updated_funcs
                        else {self.project.kb.functions.get_by_addr(a) for a in self._get_caller_funcs(updated_funcs)}
                    )
                    updated_funcs = set()

                    for func in funcs:
                        func: Function
                        if func.is_simprocedure or func.is_plt:
                            continue
                        if func.addr in self._suggestions:
                            # we already have a suggestion for this function
                            continue
                        if not func.is_default_name:
                            # it already has a name. skip
                            continue

                        # print(tolerance, repr(func))
                        start = func.addr
                        if self._is_arm:
                            start = start & 0xFFFF_FFFE

                        max_block_addr = max(func.block_addrs_set)
                        end_block = func.get_block(max_block_addr)
                        end = max_block_addr + end_block.size

                        if self._is_arm:
                            end = end & 0xFFFF_FFFE

                        # load all bytes
                        func_bytes = self.project.loader.memory.load(start, end - start + 0x100)
                        matcher = FlirtMatcher(
                            flirt,
                            func,
                            self._get_callee_name,
                            self._on_func_matched,
                            mismatch_bytes_tolerance=tolerance,
                        )
                        func_matched = matcher.match_function(func_bytes, start)
                        if func_matched:
                            updated_funcs.add(func.addr)
                        matched |= func_matched

                    if not matched:
                        break

    def _get_caller_funcs(self, update_func_addrs: set[int]) -> set[int]:
        caller_funcs = set()
        for func_addr in update_func_addrs:
            for pred in self.kb.functions.callgraph.predecessors(func_addr):
                if pred != func_addr:
                    caller_funcs.add(pred)
        return caller_funcs

    def _get_callee_name(
        self, func, func_addr: int, call_addr: int, expected_name: str  # pylint:disable=unused-argument
    ) -> str | None:
        for block_addr, (call_target, _) in func._call_sites.items():
            block = func.get_block(block_addr)
            call_ins_addr = (
                block.instruction_addrs[-2] if self.project.arch.branch_delay_slot else block.instruction_addrs[-1]
            )
            if block_addr <= call_addr < block_addr + block.size and call_ins_addr <= call_addr:
                if call_target is None or not self.kb.functions.contains_addr(call_target):
                    return None
                callee = self.kb.functions.get_by_addr(call_target)
                return callee.name
        return None

    def _on_func_matched(self, func: Function, base_addr: int, flirt_func: FlirtFunction):
        func_addr = base_addr + flirt_func.offset
        _l.debug(
            "_on_func_matched() is called with func_addr %#x with a suggested name %s.", func_addr, flirt_func.name
        )
        if func_addr != base_addr and (self._is_arm and func_addr != base_addr + 1):
            # get the correct function
            try:
                func = self.kb.functions.get_by_addr(func_addr)
            except KeyError:
                # the function is not found. Try the THUMB version
                if self._is_arm:
                    with contextlib.suppress(KeyError):
                        func = self.kb.functions.get_by_addr(func_addr + 1)

            if func is None:
                _l.debug(
                    "FlirtAnalysis identified a function at %#x but it does not exist in function manager.", func_addr
                )
                return

        if func.is_default_name:
            # set the function name
            # TODO: Make sure function names do not conflict with existing ones
            _l.debug("Identified %s @ %#x (%#x-%#x)", flirt_func.name, func_addr, base_addr, flirt_func.offset)
            func_name = flirt_func.name if flirt_func.name != "?" else f"unknown_function_{func.addr:x}"
            self._suggestions[func.addr] = func_name

    def _apply_changes(self, library_name: str | None, suggestion: dict[int, str]) -> None:
        for func_addr, suggested_name in suggestion.items():
            func = self.kb.functions.get_by_addr(func_addr)
            func.name = suggested_name
            func.is_default_name = False
            func.from_signature = "flirt"
            func.find_declaration(ignore_binary_name=True, binary_name_hint=library_name)


AnalysesHub.register_default("Flirt", FlirtAnalysis)
