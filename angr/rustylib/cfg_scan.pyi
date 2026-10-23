from typing import Any

type RegionTuple = tuple[int, int, int | None, str | None, bool, bool, bool, bool]
type SymbolTuple = tuple[int, int, bool, str | None]

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

def go_preamble_supported(arch_name: str) -> bool: ...
def find_go_stack_check_preambles(blob: bytes, arch_name: str, base: int = 0) -> list[tuple[int, int, int]]: ...
