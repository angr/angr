from typing import TYPE_CHECKING
from functools import partial
from collections import defaultdict
import logging

import nampa
from archinfo.arch_arm import is_arm_arch

from ..analyses import AnalysesHub
from ..errors import AngrRuntimeError
from ..flirt import FlirtSignature, STRING_TO_LIBRARIES, LIBRARY_TO_SIGNATURES, FLIRT_SIGNATURES_BY_ARCH
from .analysis import Analysis

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

    def __init__(self, sig: FlirtSignature | str | None = None):
        self._is_arm = is_arm_arch(self.project.arch)
        self._all_suggestions: dict[str, dict[str, dict[int, str]]] = {}
        self._suggestions: dict[int, str] = {}
        self.matched_suggestions: dict[str, tuple[FlirtSignature, dict[int, str]]] = {}
        self._temporary_sig = False

        if sig:
            if isinstance(sig, str):
                # this is a file path
                sig = FlirtSignature(
                    self.project.arch.name.lower(), self.project.simos.name.lower(), "Temporary", sig, None
                )

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
                sig_ = path_to_sig.get(max_suggestion_sig_path, None)
                _l.info("Applying FLIRT signature %s for library %s.", sig_, lib)
                self._apply_changes(
                    sig_.sig_name if not self._temporary_sig else None, sig_to_suggestions[max_suggestion_sig_path]
                )
                self.matched_suggestions[lib] = (sig_, sig_to_suggestions[max_suggestion_sig_path])

    def _find_hits_by_strings(self, regions: list[bytes]) -> list[FlirtSignature]:
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
            flirt = nampa.parse_flirt_file(sigfile)
            for func in self.project.kb.functions.values():
                func: "Function"
                if func.is_simprocedure or func.is_plt:
                    continue
                if not func.is_default_name:
                    # it already has a name. skip
                    continue

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
                _callback = partial(self._on_func_matched, func)
                nampa.match_function(flirt, func_bytes, start, _callback)

    def _on_func_matched(self, func: "Function", base_addr: int, flirt_func: "nampa.FlirtFunction"):
        func_addr = base_addr + flirt_func.offset
        _l.debug(
            "_on_func_matched() is called with func_addr %#x with a suggested name %s.", func_addr, flirt_func.name
        )
        if func_addr != base_addr:
            # get the correct function
            func = None
            try:
                func = self.kb.functions.get_by_addr(func_addr)
            except KeyError:
                # the function is not found. Try the THUMB version
                if self._is_arm:
                    try:
                        func = self.kb.functions.get_by_addr(func_addr + 1)
                    except KeyError:
                        pass

            if func is None:
                _l.debug(
                    "FlirtAnalysis identified a function at %#x but it does not exist in function manager.", func_addr
                )
                return

        if func.is_default_name:
            # set the function name
            # TODO: Make sure function names do not conflict with existing ones
            _l.debug("Identified %s @ %#x (%#x-%#x)", flirt_func.name, func_addr, base_addr, flirt_func.offset)
            if flirt_func.name != "?":
                func_name = flirt_func.name
            else:
                func_name = f"unknown_function_{func.addr:x}"
            self._suggestions[func.addr] = func_name

    def _apply_changes(self, library_name: str | None, suggestion: dict[int, str]) -> None:
        for func_addr, suggested_name in suggestion.items():
            func = self.kb.functions.get_by_addr(func_addr)
            func.name = suggested_name
            func.is_default_name = False
            func.from_signature = "flirt"
            func.find_declaration(ignore_binary_name=True, binary_name_hint=library_name)


AnalysesHub.register_default("Flirt", FlirtAnalysis)
