from collections.abc import Callable
from typing import Any

from angr.rustylib import SegmentList

type RegionTuple = tuple[int, int, int | None, str | None, bool, bool, bool, bool]
type SymbolTuple = tuple[int, int, bool, str | None]
type MemoryDataRequest = tuple[int, int, str]

class LoaderSnapshot:
    """
    An immutable snapshot of what CFG recovery needs from cle: objects, sections, segments, symbols, arch constants
    and zero-copy references to the loader's memory backers. Build it with
    ``angr.analyses.cfg.loader_snapshot.build_loader_snapshot``.
    """

    def __init__(
        self,
        objects: list[Any],
        loader_object_count: int,
        backers: list[tuple[int, Any]],
        arch: Any,
        loader_min_addr: int = 0,
        loader_max_addr: int = 0,
    ) -> None: ...
    @property
    def object_count(self) -> int: ...
    @property
    def loader_object_count(self) -> int: ...
    @property
    def arch_name(self) -> str: ...
    @property
    def arch_bytes(self) -> int: ...
    @property
    def big_endian(self) -> bool: ...
    @property
    def instruction_alignment(self) -> int | None: ...
    def object(self, idx: int) -> tuple[int, int, int, int, bool, bool, bool]:
        """``(min_addr, max_addr, mapped_base, kind, is_main, has_memory, is_outer)``."""

    def sections(self, idx: int) -> list[RegionTuple]:
        """``(vaddr, memsize, filesize, name, is_executable, is_readable, is_writable, only_uninit)`` per section."""

    def segments(self, idx: int) -> list[RegionTuple]: ...
    def backers(self) -> list[tuple[int, int]]:
        """``(start, size)`` of every leaf backer of the loader memory."""

    def object_backers(self, idx: int) -> list[tuple[int, int]]:
        """``(rva, size)`` of every leaf backer of one object's memory."""

    def load_byte(self, addr: int) -> int | None:
        """``loader.memory[addr]``, or None when unmapped."""

    def load_word(self, addr: int, size: int | None = None) -> int | None:
        """``loader.memory.unpack_word(addr, size=size)``, or None when unmapped or straddling backers."""

    def load_bytes(self, addr: int, n: int) -> bytes | None:
        """``loader.memory.load(addr, n)``, or None when nothing is mapped at ``addr``."""

    def next_mapped_addr(self, addr: int) -> int | None: ...
    def find_object_containing(self, addr: int, membership_check: bool = True) -> int | None:
        """Index of the object ``loader.find_object_containing`` returns."""

    def find_section_containing(self, addr: int) -> tuple[int, int] | None:
        """``(object index, section index)``; pseudo objects are skipped."""

    def find_section_next_to(self, addr: int) -> tuple[int, int] | None:
        """`loader.find_section_next_to(addr)`: `(object index, section index)`."""

    def find_segment_containing(self, addr: int) -> tuple[int, int] | None: ...
    def addrs_belong_to_same_section(self, a: int, b: int) -> bool: ...
    def addrs_belong_to_same_segment(self, a: int, b: int) -> bool: ...
    def floor_symbol(self, addr: int) -> SymbolTuple | None:
        """``(rebased_addr, size, is_function, name)`` of ``loader.find_symbol(addr, fuzzy=True)``."""

    def symbol_at(self, addr: int) -> SymbolTuple | None:
        """``loader.find_symbol(addr)``."""

    def ceiling_symbol(self, addr: int) -> SymbolTuple | None:
        """The first non-import symbol at or after ``addr`` in the object containing it."""

    def function_symbol_addrs(self, idx: int) -> list[int]: ...
    def executable_memory_regions(
        self, objects: list[int] | None = None, force_segment: bool = False
    ) -> list[tuple[int, int]]:
        """``CFGBase._executable_memory_regions``."""

class LinearSweep:
    """
    The linear-sweep state of one CFGFast run: ``_next_unscanned_addr``, ``_next_code_addr*`` and the byte
    classifiers. ``byte_loader`` overrides snapshot byte reads (CFGFast with a base state).
    """

    def __init__(
        self,
        snapshot: LoaderSnapshot,
        regions: list[tuple[int, int]],
        exec_regions: list[tuple[int, int]],
        nodecode_window_size: int,
        nodecode_threshold: float,
        nodecode_step: int,
        check_xfg: bool,
    ) -> None: ...
    next_addr: int | None
    def inside_regions(self, addr: int) -> bool: ...
    def region_end(self, addr: int) -> int | None: ...
    def addr_in_exec_memory_regions(self, addr: int) -> bool: ...
    def next_unscanned_addr(self, seg_list: SegmentList, alignment: int | None = None) -> int | None: ...
    def update_unscanned_addr(self, new_addr: int) -> None: ...
    def next_code_addr(
        self, seg_list: SegmentList, byte_loader: Callable[[int], int | None] | None = None
    ) -> tuple[int | None, list[MemoryDataRequest]]:
        """The next address to scan, plus the ``MemoryData(addr, size, sort)`` records to store, in order."""

    def next_code_addr_smart(
        self, seg_list: SegmentList, byte_loader: Callable[[int], int | None] | None = None
    ) -> tuple[int | None, list[MemoryDataRequest]]: ...
    @staticmethod
    def nodecode_bytes_ratio(seg_list: SegmentList, cutoff_addr: int, window_size: int) -> float: ...
    def scan_for_printable_strings(
        self,
        start_addr: int,
        min_length_nullterminated: int = 3,
        min_length_non_nullterminated: int = 13,
        byte_loader: Callable[[int], int | None] | None = None,
    ) -> int: ...
    def scan_for_printable_widestrings(
        self,
        start_addr: int,
        min_length_nullterminated: int = 3,
        min_length_non_nullterminated: int = 9,
        byte_loader: Callable[[int], int | None] | None = None,
    ) -> int: ...
    def scan_for_repeating_bytes(
        self,
        start_addr: int,
        repeating_byte: int | None,
        threshold: int = 2,
        byte_loader: Callable[[int], int | None] | None = None,
    ) -> int: ...
    def repeating_byte_run_length(self, start_addr: int, min_length: int, ignore: int | None = None) -> int: ...
    def scan_for_fp_constants(self, start_addr: int, threshold: int = 4) -> int: ...
    def scan_for_monotonic_byte_ramp(
        self, start_addr: int, threshold: int = 16, byte_loader: Callable[[int], int | None] | None = None
    ) -> int: ...
    def scan_for_consecutive_pointers(self, start_addr: int, threshold: int = 2) -> int: ...
    def scan_for_mixed_pointers(self, start_addr: int, threshold: int = 3, window: int = 6) -> int: ...
    def scan_for_win_xfg_hash(self, start_addr: int) -> bool: ...

def go_preamble_supported(arch_name: str) -> bool: ...
def find_go_stack_check_preambles(blob: bytes, arch_name: str, base: int = 0) -> list[tuple[int, int, int]]: ...
def func_addrs_from_prologues(
    snapshot: LoaderSnapshot,
    binary_idx: int,
    exec_regions: list[tuple[int, int]],
    has_arm_code: bool = True,
    fallback: Callable[[bytes, Any, int, int], list[int]] | None = None,
) -> list[int]:
    """
    ``CFGFast._func_addrs_from_prologues``. ``fallback(pattern, backer, lo, endpos)`` matches patterns the Rust
    regex engine rejects (look-around) with Python's ``re`` and returns the match starts.
    """

def backer_exec_slices_py(
    exec_regions: list[tuple[int, int]], backer_mva: int, backer_size: int
) -> list[tuple[int, int]]: ...
def regex_find_all(pattern: bytes, blob: bytes) -> list[int] | None:
    """Match starts of a Python byte regex over ``blob``; None when the pattern needs Python's ``re``."""
