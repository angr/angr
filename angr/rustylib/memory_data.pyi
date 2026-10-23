from collections.abc import Callable

from . import SegmentList
from .cfg_scan import LoaderSnapshot

type Fields = tuple[int | None, int | None, str | None, int | None, int | None, bytes | None]

class MemoryDataStore:
    """
    The MemoryData records of a CFGModel, keyed and sorted by address. Fields are (size, reference_size, sort,
    max_size, pointer_addr, content); sorts are interned strings or None.
    """

    def __init__(self) -> None: ...
    def __len__(self) -> int: ...
    def __contains__(self, addr: int) -> bool: ...
    def copy(self) -> MemoryDataStore: ...
    def clear(self) -> None: ...
    def addrs(self) -> list[int]:
        """All addresses in ascending order."""

    def irange(
        self,
        minimum: int | None = None,
        maximum: int | None = None,
        inclusive: tuple[bool, bool] = (True, True),
        reverse: bool = False,
    ) -> list[int]:
        """`SortedDict.irange` over the addresses."""

    def next_addr(self, addr: int) -> int | None:
        """The lowest address at or after `addr` that has a record."""

    def fields(self, addr: int) -> Fields: ...
    def set(
        self,
        addr: int,
        size: int | None,
        reference_size: int | None,
        sort: str | None,
        max_size: int | None,
        pointer_addr: int | None,
        content: bytes | None,
    ) -> None:
        """Insert or overwrite the record at `addr`."""

    def remove(self, addr: int) -> bool: ...
    def add_memory_data(self, addr: int, sort: str | None, size: int | None = None) -> bool:
        """`CFGModel.add_memory_data`: True if a new record was added."""

    def size(self, addr: int) -> int | None: ...
    def set_size(self, addr: int, value: int | None) -> None: ...
    def reference_size(self, addr: int) -> int | None: ...
    def set_reference_size(self, addr: int, value: int | None) -> None: ...
    def sort(self, addr: int) -> str | None: ...
    def set_sort(self, addr: int, value: str | None) -> None: ...
    def max_size(self, addr: int) -> int | None: ...
    def set_max_size(self, addr: int, value: int | None) -> None: ...
    def pointer_addr(self, addr: int) -> int | None: ...
    def set_pointer_addr(self, addr: int, value: int | None) -> None: ...
    def content(self, addr: int) -> bytes | None: ...
    def set_content(self, addr: int, value: bytes | None) -> None: ...
    def records(self) -> list[tuple[int, int | None, int | None, str | None, int | None, int | None]]:
        """(addr, size, reference_size, sort, max_size, pointer_addr) of every record, by address."""

    def merge_string_references(self, max_string_size: int = 256, update_ratio: float = 0.5) -> int:
        """`CFGFast._post_process_string_references`; returns the number of updated records."""

def tidy_data_references(
    store: MemoryDataStore,
    snapshot: LoaderSnapshot,
    memory_data_addrs: list[int] | None = None,
    exec_mem_regions: list[tuple[int, int]] | None = None,
    seg_list: SegmentList | None = None,
    has_xrefs: bool = False,
    plt_xref: Callable[[int], bool] | None = None,
    copy_xrefs: Callable[[int, int], None] | None = None,
    guess_fallback: Callable[[int, int], tuple[str, int | None] | None] | None = None,
    fill_gaps: bool = True,
) -> tuple[bool, list[int]]:
    """`CFGModel.tidy_data_references`; returns (new data found, addresses of the records made for pointers)."""

def guess_data_type(
    store: MemoryDataStore,
    snapshot: LoaderSnapshot,
    data_addr: int,
    max_size: int | None,
    seg_list: SegmentList | None = None,
    has_xrefs: bool = False,
    plt_xref: Callable[[int], bool] | None = None,
    guess_fallback: Callable[[int, int], tuple[str, int | None] | None] | None = None,
) -> tuple[str | None, int | None, bytes | None]:
    """`CFGModel._guess_data_type`: (sort, size, content)."""
